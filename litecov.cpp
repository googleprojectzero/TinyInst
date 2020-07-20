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

#define  _CRT_SECURE_NO_WARNINGS

#include "windows.h"
#include "common.h"
#include "litecov.h"

// mov byte ptr [rip+offset], 1
// note: does not clobber flags
static unsigned char MOV_ADDR_1[] = { 0xC6, 0x05, 0xAA, 0xAA, 0xAA, 0x0A, 0x01 };

// same size as instrumentation
// used for clearing the instrumentation
// if the user wants to ignore specific pieces of coverage
// 7-byte nop taken from 
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/nops.h
// thanks @tehjh
static unsigned char NOP7[] = { 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 };

ModuleCovData::ModuleCovData() {
  ClearInstrumentationData();
}

// does not clear collected coverage and ignore coverage
void ModuleCovData::ClearInstrumentationData() {
  coverage_buffer_remote = NULL;
  coverage_buffer_size = 0;
  coverage_buffer_next = 0;
  has_remote_coverage = false;
  buf_to_coverage.clear();
  coverage_to_inst.clear();
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

  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++) {
    ModuleInfo *module = *iter;
    module->client_data = new ModuleCovData();
  }
}

void LiteCov::OnModuleInstrumented(ModuleInfo *module) {
  ModuleCovData *data = (ModuleCovData *)module->client_data;

  data->ClearInstrumentationData();

  data->coverage_buffer_size = COVERAGE_SIZE;

  if (!data->coverage_buffer_size) {
    data->coverage_buffer_size = module->code_size;
  }

  // allocate a coverage buffer near instrumented code
  // this ensures that we can write to it using mov [rip+offset], ...
  uint64_t min_address = 
    (uint64_t)module->instrumented_code_remote + module->instrumented_code_size;
  if (min_address < 0x80000000) min_address = 0;
  else min_address -= 0x80000000;
  uint64_t max_address = (uint64_t)module->instrumented_code_remote;
  if (max_address < data->coverage_buffer_size) max_address = 0;
  else max_address -= data->coverage_buffer_size;

  // map as readonly initially
  // this causes an exception the first time coverage is written to the buffer
  // this enables us to quickly determine if we had new coverage or not
  data->coverage_buffer_remote = 
    (unsigned char *)RemoteAllocateBefore(min_address,
                                          max_address,
                                          module->instrumented_code_size,
                                          PAGE_READONLY);

  if (!data->coverage_buffer_remote) {
    FATAL("Could not allocate coverage buffer");
  }
}

void LiteCov::OnModuleUninstrumented(ModuleInfo *module) {
  ModuleCovData *data = (ModuleCovData *)module->client_data;

  CollectCoverage(data);

  if (data->coverage_buffer_remote) {
    VirtualFreeEx(child_handle, data->coverage_buffer_remote, 0, MEM_RELEASE);
  }

  data->ClearInstrumentationData();
}

// just replaces the inserted instructions with NOPs
void LiteCov::ClearCoverageInstrumentation(
    ModuleInfo *module, uint64_t coverage_code)
{
  ModuleCovData *data = (ModuleCovData *)module->client_data;

  auto iter = data->coverage_to_inst.find(coverage_code);
  if (iter == data->coverage_to_inst.end()) return;

  size_t code_offset = iter->second;

  WriteCodeAtOffset(module, code_offset, NOP7, sizeof(NOP7));

  // need to commit since this isn't a part of normal instrumentation process
  CommitCode(module, code_offset, sizeof(NOP7));

  data->coverage_to_inst.erase(iter);
}

void LiteCov::EmitCoverageInstrumentation(
    ModuleInfo *module, uint64_t coverage_code)
{
  ModuleCovData *data = (ModuleCovData *)module->client_data;

  // don't instrument if we are ignoring this bit of coverage
  if (data->ignore_coverage.find(coverage_code) != data->ignore_coverage.end()) return;

  if (data->coverage_buffer_next == data->coverage_buffer_size) {
    WARN("Coverage buffer full\n");
    return;
  }

  if (data->coverage_to_inst.find(coverage_code) != data->coverage_to_inst.end()) {
    WARN("Edge %llx already exists", coverage_code);
  }

  data->buf_to_coverage[data->coverage_buffer_next] = coverage_code;
  data->coverage_to_inst[coverage_code] = module->instrumented_code_allocated;

  //////////////////////////////////////////////////
  // mov [coverage_buffer + coverage_buffer_next], 1
  //////////////////////////////////////////////////
  WriteCode(module, MOV_ADDR_1, sizeof(MOV_ADDR_1));

  size_t bit_address = (size_t)data->coverage_buffer_remote + data->coverage_buffer_next;
  size_t mov_address = GetCurrentInstrumentedAddress(module);
  data->coverage_buffer_next++;

  // fix the mov address/displacement
  if (child_ptr_size == 8) {
    *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 5) =
      (int32_t)(bit_address - mov_address);
  } else {
    *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 5) =
      (uint32_t)bit_address;
  }
}

void LiteCov::InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) {
  if (coverage_type != COVTYPE_BB) return;

  uint64_t coverage_code = GetBBCode(module, bb_address);

  EmitCoverageInstrumentation(module, coverage_code);
}

void LiteCov::InstrumentEdge(
    ModuleInfo *previous_module,
    ModuleInfo *next_module,
    size_t previous_address,
    size_t next_address)
{
  if (coverage_type != COVTYPE_EDGE) return;

  // don't do anything on cross-module edges
  if (previous_module != next_module) return;
  uint64_t coverage_code = GetEdgeCode(previous_module, previous_address, next_address);

  EmitCoverageInstrumentation(previous_module, coverage_code);
}

// basic block code is just offset from the start of the module
uint64_t LiteCov::GetBBCode(ModuleInfo *module, size_t bb_address) {
  return ((uint64_t)bb_address - (uint64_t)module->base);
}

// edge code has previous offset in higher 32 bits
// and next offset in the lower 32 bits
// note that source address can be 0 if we don't know it
// (module entries, indirect jumps using global jumptable)
uint64_t LiteCov::GetEdgeCode(
    ModuleInfo *module, size_t edge_address1, size_t edge_address2)
{
  uint64_t offset1 = 0;
  if (edge_address1) offset1 = ((uint64_t)edge_address1 - (uint64_t)module->base);
  uint64_t offset2 = 0;
  if (edge_address2) offset2 = ((uint64_t)edge_address2 - (uint64_t)module->base);

  return((offset1 << 32) + (offset2 & 0xFFFFFFFF));
}

void LiteCov::OnModuleEntered(ModuleInfo *module, size_t entry_address) {
  if (coverage_type == COVTYPE_BB) return;

  // if we are in edge coverage mode, record module entries as edges
  // we don't know the source address (it's in another module)
  // so treat it as zero
  ModuleCovData *data = (ModuleCovData *)module->client_data;
  uint64_t coverage_code = GetEdgeCode(module, 0, entry_address);
  if (data->ignore_coverage.find(coverage_code) != data->ignore_coverage.end()) return;
  data->collected_coverage.insert(coverage_code);
}

// checks if address is in any of our remote coverage buffers
ModuleCovData *LiteCov::GetDataByRemoteAddress(size_t address) {
  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++)
  {
    ModuleInfo *module = *iter;
    ModuleCovData *data = (ModuleCovData *)module->client_data;
    if (!data->coverage_buffer_remote) continue;
    if ((address >= (size_t)data->coverage_buffer_remote) &&
      (address < ((size_t)data->coverage_buffer_remote + data->coverage_buffer_size))) {
      return data;
    }
  }
  return NULL;
}

// catches writing to the coverage buffer for the first time
void LiteCov::HandleBufferWriteException(ModuleCovData *data) {
  DWORD old_protect;
  if (!VirtualProtectEx(child_handle,
                        data->coverage_buffer_remote,
                        data->coverage_buffer_size,
                        PAGE_READWRITE, &old_protect))
  {
    FATAL("Could not make coverage buffer writeable");
  }
  data->has_remote_coverage = true;
}

bool LiteCov::OnException(
    EXCEPTION_RECORD *exception_record, DWORD thread_id)
{
  if ((exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) &&
    (exception_record->ExceptionInformation[0] == 1)) {
    ModuleCovData *data =
      GetDataByRemoteAddress(exception_record->ExceptionInformation[1]);
    if (data) {
      HandleBufferWriteException(data);
      return true;
    }
  }

  return TinyInst::OnException(exception_record, thread_id);
}

void LiteCov::ClearRemoteBuffer(ModuleCovData *data) {
  if (!data->coverage_buffer_remote) return;
  if (!data->has_remote_coverage) return;

  unsigned char *buf = (unsigned char *)malloc(data->coverage_buffer_next);
  memset(buf, 0, data->coverage_buffer_next);

  SIZE_T num_written;
  if (!WriteProcessMemory(child_handle,
                          data->coverage_buffer_remote,
                          buf,
                          data->coverage_buffer_next,
                          &num_written)) {
    FATAL("Error clearing coverage buffer");
  }

  DWORD old_protect;
  if (!VirtualProtectEx(child_handle,
                        data->coverage_buffer_remote,
                        data->coverage_buffer_size,
                        PAGE_READONLY,
                        &old_protect))
  {
    FATAL("Could not make coverage buffer readonly");
  }

  data->has_remote_coverage = false;

  free(buf);
}

void LiteCov::ClearCoverage(ModuleCovData *data) {
  data->collected_coverage.clear();
  ClearRemoteBuffer(data);
}

void LiteCov::ClearCoverage() {
  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++)
  {
    ModuleInfo *module = *iter;
    ModuleCovData *data = (ModuleCovData *)module->client_data;
    ClearCoverage(data);
  }
}

// fetches and decodes coverage from the remote buffer
void LiteCov::CollectCoverage(ModuleCovData *data) {
  if (!data->has_remote_coverage) return;

  unsigned char *buf = (unsigned char *)malloc(data->coverage_buffer_next);

  SIZE_T num_read;
  if (!ReadProcessMemory(child_handle,
                         data->coverage_buffer_remote,
                         buf,
                         data->coverage_buffer_next,
                         &num_read))
  {
    FATAL("Error reading coverage buffer");
  }

  for (size_t i = 0; i < data->coverage_buffer_next; i++) {
    if (buf[i]) {
      uint64_t coverage_code = data->buf_to_coverage[i];
      data->collected_coverage.insert(coverage_code);
    }
  }

  free(buf);

  ClearRemoteBuffer(data);
}

void LiteCov::CollectCoverage() {
  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++)
  {
    ModuleInfo *module = *iter;
    ModuleCovData *data = (ModuleCovData *)module->client_data;
    CollectCoverage(data);
  }
}

void LiteCov::GetCoverage(Coverage &coverage, bool clear_coverage) {
  CollectCoverage();
  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++)
  {
    ModuleInfo *module = *iter;
    ModuleCovData *data = (ModuleCovData *)module->client_data;

    if (data->collected_coverage.empty()) continue;

    // check if that module is already in the coverage list
    // (if the client calls with non-empty initial coverage)
    ModuleCoverage *module_coverage = GetModuleCoverage(coverage, module->module_name);
    if (module_coverage) {
      module_coverage->offsets.insert(
        data->collected_coverage.begin(),
        data->collected_coverage.end());
    } else {
      coverage.push_back({ module->module_name, data->collected_coverage });
    }
  }
  if (clear_coverage) ClearCoverage();
}

// sets (new) coverage to ignore
void LiteCov::IgnoreCoverage(Coverage &coverage) {
  for (auto iter = coverage.begin(); iter != coverage.end(); iter++) {
    ModuleInfo *module = GetModuleByName(iter->module_name);
    if (!module) continue;
    ModuleCovData *data = (ModuleCovData *)module->client_data;

    // remember the offsets so they don't get instrumented later 
    data->ignore_coverage.insert(iter->offsets.begin(), iter->offsets.end());

    if (!module->instrumented) continue;

    // if we already have instrumentation in place for some of the offsets
    // remove it here
    for (auto code_iter = iter->offsets.begin();
         code_iter != iter->offsets.end(); code_iter++)
    {
      ClearCoverageInstrumentation(module, *code_iter);
    }
  }
}

// quickly checks if we have new coverage
bool LiteCov::HasNewCoverage() {
  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++)
  {
    ModuleInfo *module = *iter;
    ModuleCovData *data = (ModuleCovData *)module->client_data;
    if (!data->collected_coverage.empty()) return true;
    if (data->has_remote_coverage) return true;
  }
  return false;
}

void LiteCov::OnProcessExit() {
  TinyInst::OnProcessExit();
  CollectCoverage();
}
