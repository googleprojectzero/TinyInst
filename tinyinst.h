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

#ifndef LITEINST_H
#define LITEINST_H

#include <list>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "Windows/debugger.h"
#include "common.h"

// must be a power of two
#define JUMPTABLE_SIZE 0x2000

// we will allocate 
// original_code_size * CODE_SIZE_MULTIPLIER + 
// JUMPTABLE_SIZE * child_ptr_size
// for instrumented code
#define CODE_SIZE_MULTIPLIER 4

typedef struct xed_decoded_inst_s xed_decoded_inst_t;

class TinyInst : public Debugger {
public:
  virtual void Init(int argc, char **argv);

protected:

  enum IndirectInstrumentation {
    II_NONE,
    II_GLOBAL,
    II_LOCAL,
    II_AUTO
  };

  enum InstructionResult {
    INST_HANDLED,
    INST_NOTHANDLED,
    INST_STOPBB
  };

  struct IndirectBreakpoinInfo {
    size_t list_head;
    size_t source_bb;
  };

  class ModuleInfo {
  public:
    ModuleInfo();
    void ClearInstrumentation();

    char module_name[MAX_PATH];
    void *module_header;
    size_t min_address;
    size_t max_address;
    size_t code_size;
    bool loaded;
    bool instrumented;
    std::list<AddressRange> executable_ranges;

    size_t instrumented_code_size;
    size_t instrumented_code_allocated;
    char *instrumented_code_local;
    char *instrumented_code_remote;
    char *instrumented_code_remote_previous;

    std::unordered_map<uint32_t, uint32_t> basic_blocks;

    size_t br_indirect_newtarget_global;

    // per callsite jumplist breakpoint
    // from breakpoint address to list head offset
    std::unordered_map<size_t, IndirectBreakpoinInfo> br_indirect_newtarget_list;

    size_t jumptable_offset;
    size_t jumptable_address_offset;

    std::unordered_set<size_t> invalid_instructions;
    std::unordered_map<size_t, size_t> tracepoints;

    // clients can use this to store additional data
    // about the module
    void *client_data;
  };
  std::list<ModuleInfo *> instrumented_modules;

  struct CrossModuleLink {
    ModuleInfo *module1;
    ModuleInfo *module2;
    size_t offset1;
    size_t offset2;
  };

  virtual void OnEntrypoint() override;
  virtual void OnProcessCreated() override;
  virtual void OnProcessExit() override;
  virtual void OnModuleLoaded(void *module, char *module_name) override;
  virtual void OnModuleUnloaded(void *module) override;
  virtual bool OnException(Exception *exception_record) override;
  virtual void OnTargetMethodReached() override;
  virtual void OnCrashed(Exception *exception_record) override;

  virtual size_t GetTranslatedAddress(size_t address) override;

  void OffsetStack(ModuleInfo *module, int32_t offset);
  void ReadStack(ModuleInfo *module, int32_t offset);
  void WriteStack(ModuleInfo *module, int32_t offset);
  void WriteCode(ModuleInfo *module, void *data, size_t size);
  void WriteCodeAtOffset(ModuleInfo *module, size_t offset, void *data, size_t size);
  void WritePointer(ModuleInfo *module, size_t value);
  void WritePointerAtOffset(ModuleInfo *module, size_t value, size_t offset);
  size_t ReadPointer(ModuleInfo *module, size_t offset);

  // fixes the memory displacement of the current instruction
  // (assumes it is in the 4 last bytes)
  inline void FixDisp4(ModuleInfo *module, int32_t disp) {
    *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4)
      = disp;
  }

  // gets the current code address in the instrumented code
  // *in the child process*
  inline size_t GetCurrentInstrumentedAddress(ModuleInfo *module) {
    return (size_t)module->instrumented_code_remote + module->instrumented_code_allocated;
  }

  void CommitCode(ModuleInfo *module, size_t start_offset, size_t size);

  ModuleInfo *GetModuleByName(char *name);
  ModuleInfo *GetModule(size_t address);
  ModuleInfo *GetModuleFromInstrumented(size_t address);
  AddressRange *GetRegion(ModuleInfo *module, size_t address);

  void FixInstructionAndOutput(ModuleInfo *module,
    xed_decoded_inst_t *xedd,
    unsigned char *input,
    unsigned char *input_address_remote,
    bool convert_call_to_jmp = false);

  int xed_mmode;
  int32_t sp_offset;

private:
  bool HandleBreakpoint(void *address);
  void OnInstrumentModuleLoaded(void *module, ModuleInfo *target_module);
  ModuleInfo *IsInstrumentModule(char *module_name);
  void InstrumentAllLoadedModules();
  void InstrumentModule(ModuleInfo *module);
  void ClearInstrumentation(ModuleInfo *module);
  bool TryExecuteInstrumented(char * address);
  size_t GetTranslatedAddress(ModuleInfo *module, size_t address);
  void TranslateBasicBlock(char *address,
                           ModuleInfo *module,
                           std::set<char *> *queue,
                           std::list<std::pair<uint32_t, uint32_t>> *offset_fixes);
  void TranslateBasicBlockRecursive(char *address, ModuleInfo *module);
  void FixOffsetOrEnqueue(ModuleInfo *module,
                          uint32_t bb,
                          uint32_t jmp_offset,
                          std::set<char *> *queue,
                          std::list<std::pair<uint32_t, uint32_t>> *offset_fixes);
  void InvalidInstruction(ModuleInfo *module);

  // needed to support cross-module linking
  // on module unloads / reloads
  void InvalidateCrossModuleLink(CrossModuleLink *link);
  void FixCrossModuleLink(CrossModuleLink *link);
  void FixCrossModuleLinks(ModuleInfo *module);
  void InvalidateCrossModuleLinks(ModuleInfo *module);
  void InvalidateCrossModuleLinks();
  void ClearCrossModuleLinks(ModuleInfo *module);
  void ClearCrossModuleLinks();

  // functions related to indirect jump/call instrumentation
  void InitGlobalJumptable(ModuleInfo *module);
  void MovIndirectTarget(ModuleInfo *module,
                         xed_decoded_inst_t *xedd,
                         size_t original_address,
                         int32_t stack_offset);
  void InstrumentIndirect(ModuleInfo *module,
                          xed_decoded_inst_t *xedd,
                          size_t instruction_address,
                          IndirectInstrumentation mode,
                          size_t bb_address);
  void InstrumentRet(ModuleInfo *module,
                     xed_decoded_inst_t *xedd,
                     size_t instruction_address,
                     IndirectInstrumentation mode,
                     size_t bb_address);
  void InstrumentGlobalIndirect(ModuleInfo *module,
                                xed_decoded_inst_t *xedd,
                                size_t instruction_address);
  void InstrumentLocalIndirect(ModuleInfo *module,
                               xed_decoded_inst_t *xedd,
                               size_t instruction_address,
                               size_t bb_address);

  // returns the indirect instrumentation mode that should be used for a particular call
  // can be overriden
  virtual IndirectInstrumentation ShouldInstrumentIndirect(ModuleInfo *module,
                                                           xed_decoded_inst_t *xedd,
                                                           size_t instruction_address);

  void PushReturnAddress(ModuleInfo *module, uint64_t return_address);

  bool IsRipRelative(ModuleInfo *module,
                     xed_decoded_inst_t *xedd,
                     size_t instruction_address,
                     size_t *mem_address);
  size_t AddTranslatedJump(ModuleInfo *module,
                           ModuleInfo *target_module,
                           size_t original_target,
                           size_t actual_target,
                           size_t list_head_offset,
                           size_t edge_start_address,
                           bool global_indirect);
  bool HandleIndirectJMPBreakpoint(void *address);

  // instrumentation API
  virtual void OnModuleEntered(ModuleInfo *module, size_t entry_address) {}
  virtual void InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) {}
  virtual void InstrumentEdge(ModuleInfo *previous_module,
                              ModuleInfo *next_module,
                              size_t previous_address,
                              size_t next_address) {}

  virtual InstructionResult InstrumentInstruction(ModuleInfo *module,
                                                  xed_decoded_inst_t *xedd,
                                                  size_t bb_address,
                                                  size_t instruction_address)
  { 
    return INST_NOTHANDLED;
  }

  virtual void OnModuleInstrumented(ModuleInfo *module) {}
  virtual void OnModuleUninstrumented(ModuleInfo *module) {}

  IndirectInstrumentation indirect_instrumentation_mode;

  bool instrument_cross_module_calls;
  bool patch_return_addresses;
  bool persist_instrumentation_data;

  bool trace_basic_blocks;
  bool trace_module_entries;

  // these could be indexed by module1 and module2 for performance
  // but the assumption for now is that there won't be too many of
  // them so a flat structure shoudl be ok for now
  std::list<CrossModuleLink> cross_module_links;
};

#endif // LITEINST_H