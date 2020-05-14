#ifndef LITEINST_H
#define LITEINST_H

#include <list>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "debugger.h"

// must be a power of two
#define JUMPTABLE_SIZE 0x2000

// we will allocate 
// original_code_size * CODE_SIZE_MULTIPLIER + 
// JUMPTABLE_SIZE * child_ptr_size
// for instrumented code
#define CODE_SIZE_MULTIPLIER 4

typedef struct xed_decoded_inst_s xed_decoded_inst_t;

class LiteInst : public Debugger {
public:
  virtual void Init(int argc, char **argv);

protected:

  enum IndirectInstrumentation {
    II_NONE,
    II_GLOBAL,
    II_LOCAL,
    II_AUTO
  };

  struct AddressRange {
    size_t from;
    size_t to;
    char *data;
  };

  class ModuleInfo {
  public:
    ModuleInfo() {
      module_name[0] = 0;
      base = NULL;
      size = 0;
      code_size = 0;
      loaded = false;
      instrumented = false;
      instrumented_code_local = NULL;
      instrumented_code_remote = NULL;
      instrumented_code_remote_previous = NULL;
      instrumented_code_size = 0;
      mapping = NULL;
    }

    void ClearInstrumentation(HANDLE child_handle) {
      instrumented = false;

      for (auto iter = executable_ranges.begin(); iter != executable_ranges.end(); iter++) {
        if (iter->data) free(iter->data);
      }
      executable_ranges.clear();
      code_size = 0;

      if(instrumented_code_local)
        VirtualFree(instrumented_code_local, 0, MEM_RELEASE);
      if(child_handle && instrumented_code_remote)
        VirtualFreeEx(child_handle, instrumented_code_remote, 0, MEM_RELEASE);

      instrumented_code_local = NULL;
      instrumented_code_remote = NULL;
      instrumented_code_remote_previous = NULL;

      instrumented_code_size = 0;
      instrumented_code_allocated = 0;

      basic_blocks.clear();

      br_indirect_newtarget_global = 0;
      br_indirect_newtarget_list.clear();

      jumptable_offset = 0;
      jumptable_address_offset = 0;

      invalid_instructions.clear();
      tracepoints.clear();
    }

    char module_name[MAX_PATH];
    void *base;
    size_t size;
    size_t code_size;
    bool loaded;
    bool instrumented;
    std::list<AddressRange> executable_ranges;

    size_t instrumented_code_size;
    size_t instrumented_code_allocated;
    char *instrumented_code_local;
    char *instrumented_code_remote;
    char *instrumented_code_remote_previous;
    HANDLE mapping;

    std::unordered_map<uint32_t, uint32_t> basic_blocks;

    size_t br_indirect_newtarget_global;

    // per callsite jumplist breakpoint
    // from breakpoint address to list head offset
    std::unordered_map<size_t, size_t> br_indirect_newtarget_list;

    size_t jumptable_offset;
    size_t jumptable_address_offset;

    std::unordered_set<size_t> invalid_instructions;
    std::unordered_map<size_t, size_t> tracepoints;
  };
  std::list<ModuleInfo *> instrumented_modules;

  struct CrossModuleLink {
    ModuleInfo *module1;
    ModuleInfo *module2;
    size_t offset1;
    size_t offset2;
  };

  virtual void OnEntrypoint() override;
  virtual void OnProcessCreated(CREATE_PROCESS_DEBUG_INFO *info) override;
  virtual void OnModuleLoaded(HMODULE module, char *module_name) override;
  virtual void OnModuleUnloaded(HMODULE module) override;
  virtual bool OnException(EXCEPTION_RECORD *exception_record, DWORD thread_id) override;
  virtual void OnPersistMethodReached(DWORD thread_id) override;

private:
  bool HandleBreakpoint(void *address, DWORD thread_id);
  void OnInstrumentModuleLoaded(HMODULE module, ModuleInfo *target_module);
  ModuleInfo *IsInstrumentModule(char *module_name);
  void InstrumentAllLoadedModules();
  void ExtractCodeRanges(ModuleInfo *module);
  void ProtectCodeRanges(ModuleInfo *module);
  void InstrumentModule(ModuleInfo *module);
  void ClearInstrumentation(ModuleInfo *module, bool clear_remote_data);
  bool TryExecuteInstrumented(char * address, DWORD thread_id);
  size_t GetTranslatedAddress(ModuleInfo *module, size_t address);
  void TranslateBasicBlock(char *address, ModuleInfo *module, std::set<char *> *queue, std::list<std::pair<uint32_t, uint32_t>> *offset_fixes);
  void TranslateBasicBlockRecursive(char *address, ModuleInfo *module);
  ModuleInfo *GetModule(char *address);
  ModuleInfo *GetModuleFromInstrumented(char *address);
  AddressRange *GetRegion(ModuleInfo *module, size_t address);
  void FixOffsetOrEnqueue(ModuleInfo *module, uint32_t bb, uint32_t jmp_offset, std::set<char *> *queue, std::list<std::pair<uint32_t, uint32_t>> *offset_fixes);
  void CommitCode(ModuleInfo *module, size_t start_offset, size_t size);
  void FixInstructionAndOutput(ModuleInfo *module, xed_decoded_inst_t *xedd, unsigned char *input, unsigned char *input_address_remote, bool convert_to_jmp = false);
  void Debug(EXCEPTION_RECORD *exception_record);
  void InvalidInstruction(ModuleInfo *module);

  void *LiteInst::RemoteAllocateBefore(uint64_t min_address, uint64_t max_address, size_t size, DWORD protection_flags);

  void InvalidateCrossModuleLink(CrossModuleLink *link);
  void FixCrossModuleLink(CrossModuleLink *link);
  void FixCrossModuleLinks(ModuleInfo *module);
  void InvalidateCrossModuleLinks(ModuleInfo *module);
  void InvalidateCrossModuleLinks();
  void ClearCrossModuleLinks(ModuleInfo *module);

  inline void FixDisp4(ModuleInfo *module, int32_t disp) {
    *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = disp;
  }

  inline size_t GetCurrentInstrumentedAddress(ModuleInfo *module) {
    return (size_t)module->instrumented_code_remote + module->instrumented_code_allocated;
  }

  // functions related to indirect jump/call instrumentation
  void InitGlobalJumptable(ModuleInfo *module);
  void MovIndirectTarget(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t original_address, int32_t stack_offset);
  void InstrumentIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address, IndirectInstrumentation mode);
  void InstrumentRet(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address, IndirectInstrumentation mode);
  void InstrumentGlobalIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address);
  void InstrumentLocalIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address);

  // returns the indirect instrumentation mode that should be used for a particular call
  // can be overriden
  virtual IndirectInstrumentation ShouldInstrumentIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address);

  void LiteInst::PushReturnAddress(ModuleInfo *module, uint64_t return_address);

  void OffsetStack(ModuleInfo *module, int32_t offset);
  void ReadStack(ModuleInfo *module, int32_t offset);
  void WriteStack(ModuleInfo *module, int32_t offset);
  void WriteCode(ModuleInfo *module, void *data, size_t size);
  void WriteCodeAtOffset(ModuleInfo *module, size_t offset, void *data, size_t size);
  void WritePointer(ModuleInfo *module, size_t value);
  void WritePointerAtOffset(ModuleInfo *module, size_t value, size_t offset);
  size_t ReadPointer(ModuleInfo *module, size_t offset);
  bool IsRipRelative(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address, size_t *mem_address);
  size_t AddTranslatedJump(ModuleInfo *module, ModuleInfo *target_module, size_t original_target, size_t actual_target, size_t list_head_offset, bool global_indirect);
  bool HandleIndirectJMPBreakpoint(void *address, DWORD thread_id);

  // instrumentation API
  virtual void InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) {}
  virtual void InstrumentEdge(ModuleInfo *module, size_t previous_address, size_t next_address) {}

  int xed_mmode;

  IndirectInstrumentation indirect_instrumentation_mode;

  bool instrument_cross_module_calls;
  bool patch_return_addresses;
  bool persist_instrumentation_data;

  int32_t sp_offset;

  bool trace_basic_blocks;
  bool trace_module_entries;

  // these could be indexed by module1 and module2 for performance
  // but the assumption for now is that there won't be too many of
  // them so a flat structure shoudl be ok for now
  std::list<CrossModuleLink> cross_module_links;
};

#endif // LITEINST_H