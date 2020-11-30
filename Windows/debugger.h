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
#include "windows.h"

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

class Debugger {
public:

  virtual void Init(int argc, char **argv);
  DebuggerStatus Run(char *cmd, uint32_t timeout);
  DebuggerStatus Run(int argc, char **argv, uint32_t timeout);
  DebuggerStatus Kill();
  DebuggerStatus Continue(uint32_t timeout);
  DebuggerStatus Attach(unsigned int pid, uint32_t timeout);

  bool IsTargetAlive() { return (child_handle != NULL); };
  bool IsTargetFunctionDefined() { return target_function_defined; };
  
  enum ExceptionType {
    BREAKPOINT,
    ACCESS_VIOLATION,
    ILLEGAL_INSTRUCTION,
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

  enum MemoryProtection {
    READONLY,
    READWRITE,
    READEXECUTE,
    READWRITEEXECUTE
  };

  enum Register {
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    RIP
  };

  struct AddressRange {
    size_t from;
    size_t to;
    char *data;
  };

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
  void ReadStack(void *stack_addr, void **buffer, size_t numitems);
  void WriteStack(void *stack_addr, void **buffer, size_t numitems);
  void GetImageSize(void *base_address, size_t *min_address, size_t *max_address);

  // helper functions
  void *RemoteAllocateNear(uint64_t region_min,
    uint64_t region_max,
    size_t size,
    MemoryProtection protection,
    bool use_shared_memory = false);

  void ExtractCodeRanges(void *module_base,
                         size_t min_address,
                         size_t max_address,
                         std::list<AddressRange> *executable_ranges,
                         size_t *code_size);

  void ProtectCodeRanges(std::list<AddressRange> *executable_ranges);

  // returns address in (potentially) instrumented code
  virtual size_t GetTranslatedAddress(size_t address) { return address; }

  void RemoteFree(void *address, size_t size);
  void RemoteWrite(void *address, void *buffer, size_t size);
  void RemoteRead(void *address, void *buffer, size_t size);
  void RemoteProtect(void *address, size_t size, MemoryProtection protect);

  size_t GetRegister(Register r);
  void SetRegister(Register r, size_t value);

  void *GetTargetMethodAddress() { return target_address;  }

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
  DWORD GetProcOffset(char *data, const char *name);
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
  int calling_convention;
  void *target_address;
  void *saved_sp;
  void *saved_return_address;
  void **saved_args;

  void RetrieveThreadContext();
  void CreateException(EXCEPTION_RECORD *win_exception_record,
                       Exception *exception);

  Exception last_exception;
  // thread id of the last event
  DWORD thread_id;
  CONTEXT lcContext;
  bool have_thread_context;
  size_t allocation_granularity;
};

#endif // DEBUGGER_H
