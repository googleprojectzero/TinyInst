#ifndef LITEINST_H
#define LITEINST_H

#include <list>
#include <set>
#include <unordered_map>

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
      instrumented_code_size = 0;
      mapping = NULL;
    }

    void Clear() {
      // TODO
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
    HANDLE mapping;

    std::unordered_map<uint32_t, uint32_t> basic_blocks;

    size_t br_indirect_newtarget_global;

    // per callsite jumplist breakpoint
    // from breakpoint address to list head offset
    std::unordered_map<size_t, size_t> br_indirect_newtarget_list;

    size_t jumptable_offset;
    size_t jumptable_address_offset;
  };
  std::list<ModuleInfo *> instrumented_modules;

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
  void InstrumentModule(ModuleInfo *module);
  bool TryExecuteInstrumented(char * address, DWORD thread_id);
  size_t GetTranslatedAddress(ModuleInfo *module, size_t address);
  bool TranslateBasicBlock(char *address, ModuleInfo *module, std::set<char *> *queue, std::list<std::pair<uint32_t, uint32_t>> *offset_fixes);
  bool TranslateBasicBlockRecursive(char *address, ModuleInfo *module);
  ModuleInfo *GetModule(char *address);
  ModuleInfo *GetModuleFromInstrumented(char *address);
  void FixOffsetOrEnqueue(ModuleInfo *module, uint32_t bb, uint32_t jmp_offset, std::set<char *> *queue, std::list<std::pair<uint32_t, uint32_t>> *offset_fixes);
  void CommitCode(ModuleInfo *module, size_t start_offset, size_t size);
  void FixInstructionAndOutput(ModuleInfo *module, xed_decoded_inst_t *xedd, unsigned char *input, unsigned char *input_address_remote, bool convert_to_jmp = false);
  void Debug(EXCEPTION_RECORD *exception_record);

  // functions related to indirect jump/call instrumentation
  void InitGlobalJumptable(ModuleInfo *module);
  void MovIndirectTarget(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t original_address);
  void InstrumentIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address, IndirectInstrumentation mode);
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
  bool IsRipRelative(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address, size_t *mem_address);
  size_t AddTranslatedJump(ModuleInfo *module, size_t original_target, size_t actual_target, size_t list_head_offset, bool global_indirect);
  bool HandleIndirectJMPBreakpoint(void *address, DWORD thread_id);

  // instrumentation API
  virtual void InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) {}
  virtual void InstrumentEdge(ModuleInfo *module, size_t previous_address, size_t next_address) {}

  int xed_mmode;

  IndirectInstrumentation indirect_instrumentation_mode;

  bool instrument_cross_module_calls;
  bool patch_return_addresses;

  int32_t sp_offset;

  bool trace_basic_blocks;
  bool trace_module_entries;
  std::unordered_map<size_t, size_t> tracepoints;
};

#endif // LITEINST_H