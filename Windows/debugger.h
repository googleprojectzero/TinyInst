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

#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <string>
#include <list>
#include <unordered_set>
#include <unordered_map>

#include "common.h"
#include "windows.h"
#include "arch/x86/reg.h"

enum CallingConvention {
  CALLCONV_MICROSOFT_X64,
  CALLCONV_THISCALL,
  CALLCONV_FASTCALL,
  CALLCONV_CDECL,
  CALLCONV_DEFAULT,
};

enum MemoryProtection {
  READONLY,
  READWRITE,
  READEXECUTE,
  READWRITEEXECUTE
};

enum DebuggerStatus {
  DEBUGGER_NONE,
  DEBUGGER_CONTINUE,
  DEBUGGER_PROCESS_EXIT,
  DEBUGGER_TARGET_START,
  DEBUGGER_TARGET_END,
  DEBUGGER_CRASHED,
  DEBUGGER_HANGED,
  DEBUGGER_ATTACHED
};

struct SavedRegisters {
  CONTEXT saved_context;
};

class Debugger {
public:

  virtual void Init(int argc, char **argv);
  DebuggerStatus Run(char *cmd, uint32_t timeout);
  DebuggerStatus Run(int argc, char **argv, uint32_t timeout);
  DebuggerStatus Kill();
  DebuggerStatus Continue(uint32_t timeout);
  DebuggerStatus Attach(unsigned int pid, uint32_t timeout);

  bool IsTargetAlive() { return (child_handle != NULL); };
  bool IsTargetFunctionDefined() { return target_function_defined; }

  uint64_t GetTargetReturnValue() { return target_return_value; }
  
  enum ExceptionType {
    BREAKPOINT,
    ACCESS_VIOLATION,
    ILLEGAL_INSTRUCTION,
    STACK_OVERFLOW,
    OTHER
  };

  struct Exception {
    ExceptionType type;
    void *ip;
    bool maybe_write_violation;
    bool maybe_execute_violation;
    void *access_address;
  };

  Exception GetLastException() {
    return last_exception;
  }
  
protected:

  virtual void OnModuleLoaded(void *module, char *module_name);
  virtual void OnModuleUnloaded(void *module);
  virtual void OnTargetMethodReached() {}
  virtual void OnProcessCreated();
  virtual void OnProcessExit() {};
  virtual void OnEntrypoint();

  // should return true if the exception has been handled
  virtual bool OnException(Exception *exception_record) {
    return false;
  }

  virtual void OnCrashed(Exception *exception_record) { }

  void *GetModuleEntrypoint(void *base_address);
  void ReadStack(void *stack_addr, uint64_t *buffer, size_t numitems);
  void WriteStack(void *stack_addr, uint64_t *buffer, size_t numitems);
  void GetImageSize(void *base_address, size_t *min_address, size_t *max_address);

  // helper functions
  void* RemoteAllocate(size_t size, MemoryProtection protection);
  void *RemoteAllocateNear(uint64_t region_min,
    uint64_t region_max,
    size_t size,
    MemoryProtection protection,
    bool use_shared_memory = false);

  void ExtractCodeRanges(void *module_base,
                         size_t min_address,
                         size_t max_address,
                         std::list<AddressRange> *executable_ranges,
                         size_t *code_size,
                         bool do_protect = true);

  void ProtectCodeRanges(std::list<AddressRange> *executable_ranges);

  // returns address in (potentially) instrumented code
  virtual size_t GetTranslatedAddress(size_t address) { return address; }

  void RemoteFree(void *address, size_t size);
  void RemoteWrite(void *address, const void *buffer, size_t size);
  void RemoteRead(void *address, void *buffer, size_t size);
  void RemoteProtect(void *address, size_t size, MemoryProtection protect);

  size_t GetRegister(Register r);
  void SetRegister(Register r, size_t value);

  void *GetTargetMethodAddress() { return target_address;  }

  DWORD GetProcOffset(HMODULE module, const char* name);
  void* GetSymbolAddress(void* base_address, const char* symbol_name);

  void SaveRegisters(SavedRegisters* registers);
  void RestoreRegisters(SavedRegisters* registers);

  void SetReturnAddress(size_t value);
  size_t GetReturnAddress();

  void GetFunctionArguments(uint64_t* arguments, size_t num_args, uint64_t sp, CallingConvention callconv);
  void SetFunctionArguments(uint64_t* arguments, size_t num_args, uint64_t sp, CallingConvention callconv);

  void GetExceptionHandlers(size_t module_haeder, std::unordered_set <size_t>& handlers);

  void PatchPointersRemote(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace);
  template<typename T>
  void PatchPointersRemoteT(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace);

  HANDLE GetChildProcessHandle() { return child_handle; }

private:
  struct Breakpoint {
    void *address;
    int type;
    unsigned char original_opcode;
  };
  std::list<Breakpoint *> breakpoints;

  void StartProcess(char *cmd);
  void GetProcessPlatform();
  DebuggerStatus DebugLoop(uint32_t timeout, bool killing=false);
  int HandleDebuggerBreakpoint(void *address);
  void HandleDllLoadInternal(LOAD_DLL_DEBUG_INFO *LoadDll);
  DebuggerStatus HandleExceptionInternal(EXCEPTION_RECORD *exception_record);
  void HandleTargetReachedInternal();
  void HandleTargetEnded();
  char *GetTargetAddress(HMODULE module);
  void AddBreakpoint(void *address, int type);
  DWORD GetLoadedModules(HMODULE **modules);
  void DeleteBreakpoints();
  DWORD WindowsProtectionFlags(MemoryProtection protection);
  DWORD GetImageSize(void *base_address);
  void *RemoteAllocateBefore(uint64_t min_address,
                             uint64_t max_address,
                             size_t size,
                             MemoryProtection protection);
  void *RemoteAllocateAfter(uint64_t min_address,
                            uint64_t max_address,
                            size_t size,
                            MemoryProtection protection);

protected:

  bool child_entrypoint_reached;
  bool target_reached;

  int32_t child_ptr_size = sizeof(void *);

private:
  HANDLE child_handle, child_thread_handle;

  HANDLE devnul_handle = INVALID_HANDLE_VALUE;

  DEBUG_EVENT dbg_debug_event;
  DWORD dbg_continue_status;
  bool dbg_continue_needed;
  DebuggerStatus dbg_last_status;

  int wow64_target = 0;

protected:
  bool target_function_defined;
  bool loop_mode;
  bool attach_mode;
  bool trace_debug_events;

  bool sinkhole_stds;
  uint64_t mem_limit;
  uint64_t cpu_aff;

private:
  // persistence related
  int target_num_args;
  uint64_t target_offset;
  std::string target_module;
  std::string target_method;
  CallingConvention calling_convention;
  void *target_address;
  void *saved_sp;
  void *saved_return_address;
  uint64_t *saved_args;

  uint64_t target_return_value;

  void RetrieveThreadContext();
  void CreateException(EXCEPTION_RECORD *win_exception_record,
                       Exception *exception);

  Exception last_exception;
  // thread id of the last event
  DWORD thread_id;
  CONTEXT lcContext;
  bool have_thread_context;
  size_t allocation_granularity;

  bool force_dep;
};

#endif // DEBUGGER_H
