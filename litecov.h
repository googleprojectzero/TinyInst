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

#ifndef LITECOV_H
#define LITECOV_H

#include <unordered_map>
#include <set>

#include "coverage.h"
#include "tinyinst.h"

#define COVERAGE_SIZE 0

enum CovType {
  COVTYPE_BB,
  COVTYPE_EDGE
};

struct CmpCoverageRecord {
  bool ignored;
  int width;
  int match_width;
  size_t bb_address; // for debugging
  size_t bb_offset;
  size_t cmp_offset;
  size_t instrumentation_offset;
  size_t instrumentation_size;
  size_t match_width_offset;
};

class ModuleCovData {
public:
  ModuleCovData();
  void ClearInstrumentationData();

  unsigned char *coverage_buffer_remote;
  size_t coverage_buffer_size;
  size_t coverage_buffer_next;

  std::set<uint64_t> collected_coverage;
  std::set<uint64_t> ignore_coverage;

  // maps offset in the coverage buffer to
  // offset of the basic block / edge code
  std::unordered_map<size_t, uint64_t> buf_to_coverage;

  // maps coverage code (e.g. a bb offset)
  // to offset in the instrumented buffer
  // of the corresponding instrumentation
  std::unordered_map<uint64_t, size_t> coverage_to_inst;

  bool has_remote_coverage;

  void ClearCmpCoverageData();
  std::unordered_map<size_t, CmpCoverageRecord*> buf_to_cmp;
  std::unordered_map<uint64_t, CmpCoverageRecord*> coverage_to_cmp;
};

class LiteCov : public TinyInst {
public:
  virtual void Init(int argc, char **argv);

  void GetCoverage(Coverage &coverage, bool clear_coverage);
  void ClearCoverage();

  // note: this does not affect already collected coverage
  void IgnoreCoverage(Coverage &coverage);

  bool HasNewCoverage();

protected:
  virtual void OnModuleInstrumented(ModuleInfo *module) override;
  virtual void OnModuleUninstrumented(ModuleInfo *module) override;

  virtual void OnProcessExit() override;

  virtual void OnModuleEntered(ModuleInfo *module, size_t entry_address) override;
  virtual bool OnException(Exception *exception_record) override;

  virtual void InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) override;
  virtual void InstrumentEdge(ModuleInfo *previous_module,
                              ModuleInfo *next_module,
                              size_t previous_address,
                              size_t next_address) override;
  virtual InstructionResult InstrumentInstruction(ModuleInfo *module,
                                                  xed_decoded_inst_t *xedd,
                                                  size_t bb_address,
                                                  size_t instruction_address) override;


  void EmitCoverageInstrumentation(ModuleInfo *module, uint64_t coverage_code);
  void ClearCoverageInstrumentation(ModuleInfo *module, uint64_t coverage_code);

  // compute a unique code for a basic block
  // this is just an offset into the module
  uint64_t GetBBCode(ModuleInfo *module, size_t bb_address);
 
  // compute a unique code for a basic block
  // this has address1 offset in lower 32 bits and
  // address2 offset in higher 32 bits
  uint64_t GetEdgeCode(ModuleInfo *module, size_t edge_address1, size_t edge_address2);

  ModuleCovData *GetDataByRemoteAddress(size_t address);
  void HandleBufferWriteException(ModuleCovData *data);

  void ClearCoverage(ModuleCovData *data);
  void ClearRemoteBuffer(ModuleCovData *data);

  void CollectCoverage(ModuleCovData *data);
  void CollectCoverage();

  uint64_t GetCmpCode(size_t bb_offset, size_t cmp_offset, int bits_match);
  bool IsCmpCoverageCode(uint64_t code);
  void ClearCmpCoverageInstrumentation(ModuleInfo *module, uint64_t coverage_code);
  void CollectCmpCoverage(ModuleCovData *data, size_t buffer_offset, char buffer_value);
  bool ShouldInstrumentSub(ModuleInfo *module,
                           xed_decoded_inst_t *cmp_xedd,
                           size_t instruction_address);
private:

  CovType coverage_type;
  bool compare_coverage;
};

#endif // LITECOV_H
