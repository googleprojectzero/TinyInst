/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define _CRT_SECURE_NO_WARNINGS

#include "litecov.h"

#include "common.h"

ModuleCovData::ModuleCovData() { ClearInstrumentationData(); }

// does not clear collected coverage and ignore coverage
void ModuleCovData::ClearInstrumentationData() {
  coverage_buffer_remote = NULL;
  coverage_buffer_size = 0;
  coverage_buffer_next = 0;
  has_remote_coverage = false;
  buf_to_coverage.clear();
  coverage_to_inst.clear();
  ClearCmpCoverageData();
}

void LiteCov::Init(int argc, char **argv) {
  TinyInst::Init(argc, argv);

  coverage_type = COVTYPE_BB;
  char *option = GetOption("-covtype", argc, argv);
  if (option) {
    if (strcmp(option, "bb") == 0)
      coverage_type = COVTYPE_BB;
    else if (strcmp(option, "edge") == 0)
      coverage_type = COVTYPE_EDGE;
    else
      FATAL("Unknown coverage type");
  }

  compare_coverage = GetBinaryOption("-cmp_coverage", argc, argv, false);

  for (ModuleInfo *module : instrumented_modules) {
    module->client_data = new ModuleCovData();
  }
}

void LiteCov::OnModuleInstrumented(ModuleInfo *module) {
  TinyInst::OnModuleInstrumented(module);

  ModuleCovData *data = (ModuleCovData *)module->client_data;

  data->ClearInstrumentationData();

  data->coverage_buffer_size = COVERAGE_SIZE;

  if (!data->coverage_buffer_size) {
    data->coverage_buffer_size = module->code_size;
  }

  // map as readonly initially
  // this causes an exception the first time coverage is written to the buffer
  // this enables us to quickly determine if we had new coverage or not
  data->coverage_buffer_remote = (unsigned char *)RemoteAllocateNear(
      (uint64_t)module->instrumented_code_remote,
      (uint64_t)module->instrumented_code_remote +
          module->instrumented_code_size,
      data->coverage_buffer_size, READONLY, true);

  if (!data->coverage_buffer_remote) {
    FATAL("Could not allocate coverage buffer");
  }
}

void LiteCov::OnModuleUninstrumented(ModuleInfo *module) {
  TinyInst::OnModuleUninstrumented(module);

  ModuleCovData *data = (ModuleCovData *)module->client_data;

  CollectCoverage(data);

  if (data->coverage_buffer_remote && IsTargetAlive()) {
    RemoteFree(data->coverage_buffer_remote, data->coverage_buffer_size);
    data->coverage_buffer_remote = NULL;
  }

  data->ClearInstrumentationData();
}

// just replaces the inserted instructions with NOPs
void LiteCov::ClearCoverageInstrumentation(ModuleInfo *module,
                                           uint64_t coverage_code) {
  ModuleCovData *data = (ModuleCovData *)module->client_data;

  auto iter = data->coverage_to_inst.find(coverage_code);
  if (iter == data->coverage_to_inst.end()) {
    if (compare_coverage) {
      ClearCmpCoverageInstrumentation(module, coverage_code);
    }
    return;
  }

  size_t code_offset = iter->second;

  NopCovInstructions(module, code_offset);

  data->coverage_to_inst.erase(iter);
}

uint64_t LiteCov::GetCmpCode(size_t bb_offset, size_t cmp_offset,
                             int bits_match) {
  // cmp code consists of bb offset in the highest 32 bits
  // cmp instruction offset (from bb start) in the next 24 bits
  // and bits to match in the lowest 8 bits
  uint64_t code = (((uint64_t)bb_offset << 32) +
                   ((cmp_offset << 8) & 0xFFFFFFFFUL) + bits_match);
  // it also has the highest bit set
  code |= 0x8000000000000000ULL;
  return code;
}

bool LiteCov::IsCmpCoverageCode(uint64_t code) {
  return (code & 0x8000000000000000ULL);
}

void LiteCov::EmitCoverageInstrumentation(ModuleInfo *module,
                                          uint64_t coverage_code) {
  ModuleCovData *data = (ModuleCovData *)module->client_data;

  // don't instrument if we are ignoring this bit of coverage
  if (data->ignore_coverage.find(coverage_code) != data->ignore_coverage.end())
    return;

  if (data->coverage_buffer_next == data->coverage_buffer_size) {
    WARN("Coverage buffer full\n");
    return;
  }

  if (data->coverage_to_inst.find(coverage_code) !=
      data->coverage_to_inst.end()) {
    WARN("Edge %llx already exists", coverage_code);
    return;
  }

  data->buf_to_coverage[data->coverage_buffer_next] = coverage_code;
  data->coverage_to_inst[coverage_code] = module->instrumented_code_allocated;

  size_t bit_address =
      (size_t)data->coverage_buffer_remote + data->coverage_buffer_next;
  size_t mov_address = GetCurrentInstrumentedAddress(module);
  data->coverage_buffer_next++;

  EmitCoverageInstrumentation(module, bit_address, mov_address);
}

void LiteCov::InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) {
  if (coverage_type != COVTYPE_BB) return;

  uint64_t coverage_code = GetBBCode(module, bb_address);

  EmitCoverageInstrumentation(module, coverage_code);
}

void LiteCov::InstrumentEdge(ModuleInfo *previous_module,
                             ModuleInfo *next_module, size_t previous_address,
                             size_t next_address) {
  if (coverage_type != COVTYPE_EDGE) return;

  // don't do anything on cross-module edges
  if (previous_module != next_module) return;
  uint64_t coverage_code =
      GetEdgeCode(previous_module, previous_address, next_address);

  EmitCoverageInstrumentation(previous_module, coverage_code);
}

// basic block code is just offset from the start of the module
uint64_t LiteCov::GetBBCode(ModuleInfo *module, size_t bb_address) {
  return ((uint64_t)bb_address - (uint64_t)module->min_address);
}

// edge code has previous offset in higher 32 bits
// and next offset in the lower 32 bits
// note that source address can be 0 if we don't know it
// (module entries, indirect jumps using global jumptable)
uint64_t LiteCov::GetEdgeCode(ModuleInfo *module, size_t edge_address1,
                              size_t edge_address2) {
  uint64_t offset1 = 0;
  if (edge_address1)
    offset1 = ((uint64_t)edge_address1 - (uint64_t)module->min_address);
  uint64_t offset2 = 0;
  if (edge_address2)
    offset2 = ((uint64_t)edge_address2 - (uint64_t)module->min_address);

  return ((offset1 << 32) + (offset2 & 0xFFFFFFFF));
}

void LiteCov::OnModuleEntered(ModuleInfo *module, size_t entry_address) {
  if (coverage_type == COVTYPE_BB) return;

  // if we are in edge coverage mode, record module entries as edges
  // we don't know the source address (it's in another module)
  // so treat it as zero
  ModuleCovData *data = (ModuleCovData *)module->client_data;
  uint64_t coverage_code = GetEdgeCode(module, 0, entry_address);
  if (data->ignore_coverage.count(coverage_code) != 0) return;
  data->collected_coverage.insert(coverage_code);
}

// checks if address is in any of our remote coverage buffers
ModuleCovData *LiteCov::GetDataByRemoteAddress(size_t address) {
  for (ModuleInfo *module : instrumented_modules) {
    ModuleCovData *data = (ModuleCovData *)module->client_data;
    if (!data->coverage_buffer_remote) continue;
    if ((address >= (size_t)data->coverage_buffer_remote) &&
        (address <
         ((size_t)data->coverage_buffer_remote + data->coverage_buffer_size))) {
      return data;
    }
  }
  return NULL;
}

// catches writing to the coverage buffer for the first time
void LiteCov::HandleBufferWriteException(ModuleCovData *data) {
  RemoteProtect(data->coverage_buffer_remote, data->coverage_buffer_size,
                READWRITE);

  data->has_remote_coverage = true;
}

bool LiteCov::OnException(Exception *exception_record) {
  if ((exception_record->type == ACCESS_VIOLATION) &&
      (exception_record->maybe_write_violation)) {
    ModuleCovData *data =
        GetDataByRemoteAddress((size_t)exception_record->access_address);
    if (data) {
      HandleBufferWriteException(data);
      return true;
    }
  }

  return TinyInst::OnException(exception_record);
}

void LiteCov::ClearRemoteBuffer(ModuleCovData *data) {
  if (!IsTargetAlive()) return;
  if (!data->coverage_buffer_remote) return;
  if (!data->has_remote_coverage) return;

  unsigned char *buf = (unsigned char *)malloc(data->coverage_buffer_next);
  memset(buf, 0, data->coverage_buffer_next);

  RemoteWrite(data->coverage_buffer_remote, buf, data->coverage_buffer_next);

  RemoteProtect(data->coverage_buffer_remote, data->coverage_buffer_size,
                READONLY);

  data->has_remote_coverage = false;

  free(buf);
}

void LiteCov::ClearCoverage(ModuleCovData *data) {
  data->collected_coverage.clear();
  ClearRemoteBuffer(data);
}

void LiteCov::ClearCoverage() {
  for (ModuleInfo *module : instrumented_modules) {
    ModuleCovData *data = (ModuleCovData *)module->client_data;
    ClearCoverage(data);
  }
}

// fetches and decodes coverage from the remote buffer
void LiteCov::CollectCoverage(ModuleCovData *data) {
  if (!data->has_remote_coverage) return;

  unsigned char *buf = (unsigned char *)malloc(data->coverage_buffer_next);

  RemoteRead(data->coverage_buffer_remote, buf, data->coverage_buffer_next);

  for (size_t i = 0; i < data->coverage_buffer_next; i++) {
    if (buf[i]) {
      auto iter = data->buf_to_coverage.find(i);
      if (iter == data->buf_to_coverage.end()) {
        if (compare_coverage) {
          CollectCmpCoverage(data, i, buf[i]);
        }
      } else {
        uint64_t coverage_code = iter->second;
        data->collected_coverage.insert(coverage_code);
      }
    }
  }

  free(buf);

  ClearRemoteBuffer(data);
  data->has_remote_coverage = false;
}

void LiteCov::CollectCoverage() {
  for (ModuleInfo *module : instrumented_modules) {
    ModuleCovData *data = (ModuleCovData *)module->client_data;
    CollectCoverage(data);
  }
}

void LiteCov::GetCoverage(Coverage &coverage, bool clear_coverage) {
  CollectCoverage();
  for (ModuleInfo *module : instrumented_modules) {
    ModuleCovData *data = (ModuleCovData *)module->client_data;

    if (data->collected_coverage.empty()) continue;

    // check if that module is already in the coverage list
    // (if the client calls with non-empty initial coverage)
    ModuleCoverage *module_coverage =
        GetModuleCoverage(coverage, module->module_name);
    if (module_coverage) {
      module_coverage->offsets.insert(data->collected_coverage.begin(),
                                      data->collected_coverage.end());
    } else {
      coverage.push_back({module->module_name, data->collected_coverage});
    }
  }
  if (clear_coverage) ClearCoverage();
}

// sets (new) coverage to ignore
void LiteCov::IgnoreCoverage(Coverage &coverage) {
  for (const ModuleCoverage &mod_cov : coverage) {
    ModuleInfo *module = GetModuleByName(mod_cov.module_name.c_str());
    if (!module) continue;
    ModuleCovData *data = (ModuleCovData *)module->client_data;

    // remember the offsets so they don't get instrumented later
    data->ignore_coverage.insert(mod_cov.offsets.begin(),
                                 mod_cov.offsets.end());
    if (!module->instrumented) continue;

    // if we already have instrumentation in place for some of the offsets
    // remove it here
    for (const uint64_t code_off : mod_cov.offsets) {
      ClearCoverageInstrumentation(module, code_off);
    }
  }
}

// quickly checks if we have new coverage
bool LiteCov::HasNewCoverage() {
  for (ModuleInfo *module : instrumented_modules) {
    ModuleCovData *data = (ModuleCovData *)module->client_data;
    if (!data->collected_coverage.empty()) return true;
    if (data->has_remote_coverage) return true;
  }
  return false;
}

void LiteCov::OnProcessExit() {
  CollectCoverage();
  TinyInst::OnProcessExit();
}

void ModuleCovData::ClearCmpCoverageData() {
  for (auto &[buffer_offset, cmp_record] : buf_to_cmp) {
    delete cmp_record;
  }
  buf_to_cmp.clear();
  coverage_to_cmp.clear();
}

void LiteCov::ClearCmpCoverageInstrumentation(ModuleInfo *module,
                                              uint64_t coverage_code) {
  if (!IsCmpCoverageCode(coverage_code)) return;

  ModuleCovData *data = (ModuleCovData *)module->client_data;

  int matched_width = coverage_code & 0xFF;
  coverage_code -= matched_width;

  auto iter = data->coverage_to_cmp.find(coverage_code);
  if (iter == data->coverage_to_cmp.end()) return;

  CmpCoverageRecord *cmp_record = iter->second;

  if (cmp_record->ignored) return;

  NopCmpCovInstructions(module, *cmp_record, matched_width);
}

void LiteCov::CollectCmpCoverage(ModuleCovData *data, size_t buffer_offset,
                                 char buffer_value) {
  auto iter = data->buf_to_cmp.find(buffer_offset);
  if (iter == data->buf_to_cmp.end()) return;

  CmpCoverageRecord *cmp_record = iter->second;

  if (cmp_record->ignored) return;

  if (buffer_value < cmp_record->match_width) return;

  for (int match = cmp_record->match_width; match <= buffer_value; match += 8) {
    // full match, no need to record it
    if (match == cmp_record->width) break;
    uint64_t coverage_code =
        GetCmpCode(cmp_record->bb_offset, cmp_record->cmp_offset, match);
    data->collected_coverage.insert(coverage_code);
  }
}
