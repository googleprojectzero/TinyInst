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

#include <sys/user.h>
#include <sys/ptrace.h>

#include <inttypes.h>
#include <list>
#include <string>
#include <set>
#include <vector>
#include <unordered_map>
#include <mutex>

#include "common.h"
#include "procmaps.h"

#ifdef ARM64
#include "arch/arm64/reg.h"
#else
#include "arch/x86/reg.h"
#endif

#ifdef __ANDROID__
  typedef int __ptrace_request;
#endif

#ifdef ARM64
#define SYSCALL_RETURN_REGISTER X0
#define SYSCALL_NUMER_REGISTER X8
#else
#define SYSCALL_RETURN_REGISTER RAX
#define SYSCALL_NUMER_REGISTER SYSCALL_RAX
#endif

class SyscallHook;

enum DebuggerStatus {
  DEBUGGER_NONE,
  DEBUGGER_CONTINUE,
  DEBUGGER_PROCESS_EXIT,
  DEBUGGER_TARGET_START,
  DEBUGGER_TARGET_END,
  DEBUGGER_CRASHED,
  DEBUGGER_HANGED,
  DEBUGGER_ATTACHED,
};

enum MemoryProtection {
  READONLY,
  READWRITE,
  READEXECUTE,
  READWRITEEXECUTE
};

enum CallingConvention {
  CALLCONV_DEFAULT,
};

struct LoadedModule {
  std::string path;
  uint64_t address;
};

bool operator< (LoadedModule const& lhs, LoadedModule const& rhs);

#ifdef ARM64
typedef user_pt_regs arch_reg_struct;
#else
typedef user_regs_struct arch_reg_struct;
#endif

struct SavedRegisters {
  arch_reg_struct saved_context;
};

class Debugger {

public:
  virtual void Init(int argc, char **argv);

  DebuggerStatus Run(int argc, char **argv, uint32_t timeout);
  DebuggerStatus Run(char *cmd, uint32_t timeout);
  DebuggerStatus Continue(uint32_t timeout);
  DebuggerStatus Kill();
  DebuggerStatus Attach(unsigned int pid, uint32_t timeout);

  bool IsTargetAlive() { return is_target_alive; }
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
  class SharedMemory {
  public:
    std::string name;
    uint64_t local_address;
    uint64_t remote_address;
    int local_fd;
    int remote_fd;
    uint64_t size;
  };

  enum TargetEndDetection {
    RETADDR_STACK_OVERWRITE,
    RETADDR_BREAKPOINT
  };

  virtual void OnProcessCreated();
  virtual void OnEntrypoint();
  virtual void OnModuleLoaded(void *module, char *module_name);
  virtual void OnModuleUnloaded(void *module);
  virtual void OnProcessExit() {};
  virtual void OnTargetMethodReached() {}
  virtual void OnSyscall(int thread_id, uint64_t syscall_number) {}
  virtual void OnSyscallEnd(int thread_id) {}

  virtual bool OnException(Exception *exception_record) { return false; }
  virtual void OnCrashed(Exception *exception_record) { }

  void *GetModuleEntrypoint(void *base_address);

  void GetImageSize(void *base_address, size_t *min_address, size_t *max_address);

  void ExtractCodeRanges(void *module_base,
                         size_t min_address,
                         size_t max_address,
                         std::list<AddressRange> *executable_ranges,
                         size_t *code_size,
                         bool do_protect = true);

  void ProtectCodeRanges(std::list<AddressRange> *executable_ranges);

  void PatchPointersRemote(void *base_address, std::unordered_map<size_t, size_t>& search_replace);
  void PatchPointersRemote(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace);
  template<typename T>
  void PatchPointersRemoteT(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace);


  virtual size_t GetTranslatedAddress(size_t address) { return address; }

  void RemoteRead(void *address, void *buffer, size_t size);
  void RemoteWrite(void *address, const void *buffer, size_t size);

  size_t GetRegister(Register r);
  void SetRegister(Register r, size_t value);

  void *GetTargetMethodAddress() { return target_address; }

  void SaveRegisters(SavedRegisters* registers);
  void RestoreRegisters(SavedRegisters* registers);

  void* RemoteAllocate(size_t size, MemoryProtection protection, bool use_shared_memory = false);
  void RemoteFree(void *address, size_t size);
  void RemoteProtect(void *address, size_t size, MemoryProtection protection);

  void *RemoteAllocateNear(uint64_t region_min,
                           uint64_t region_max,
                           size_t size,
                           MemoryProtection protection,
                           bool use_shared_memory = false);

  void *GetSymbolAddress(void *base_address, const char *symbol_name);

  size_t GetReturnAddress();
  void SetReturnAddress(size_t value);

  void GetFunctionArguments(uint64_t *arguments, size_t num_arguments, uint64_t sp, CallingConvention callconv);
  void SetFunctionArguments(uint64_t *arguments, size_t num_arguments, uint64_t sp, CallingConvention callconv);

  void SetSyscallArguments(uint64_t *args, size_t num_args);
  void GetSyscallArguments(uint64_t *args, size_t num_args);

  int GetCurrentThreadID() { return current_pid; }

  void RegisterSyscallHook(SyscallHook *hook);

  int32_t child_ptr_size = sizeof(void *);
 
  bool child_entrypoint_reached;
  bool target_reached;
  bool target_function_defined;

  Exception last_exception;

private:
  std::set<LoadedModule> loaded_modules;
  std::set<int> threads;

  struct Breakpoint {
    void *address;
    int type;
  #ifdef ARM64
    uint32_t original_opcode;
  #else
    unsigned char original_opcode;
  #endif
  };
  std::list<Breakpoint *> breakpoints;

  DebuggerStatus DebugLoop(uint32_t timeout);
  DebuggerStatus HandleStopped(int status);

  void AddBreakpoint(void *address, int type);
  void DeleteBreakpoints();
  int HandleDebuggerBreakpoint();
  template<typename T_r_debug, typename T_link_map>
  int GetLoadedModulesT(std::set<LoadedModule> &modules, bool set_breakpoint);
  int GetLoadedModules(std::set<LoadedModule> &modules, bool set_breakpoint);
  void OnLoadedModulesChanged(bool set_breakpoint);
  void SetThreadOptions(pid_t pid);

  uint64_t* GetRegisterHelper(Register r, arch_reg_struct *regs);

  uint64_t GetSegment(uint64_t header, uint32_t type, uint64_t *segment_size);
  int ReadCString(uint64_t address, char *str, size_t size);
  void GetElfIdentAndOffset(uint64_t header, uint8_t *e_ident, uint64_t *pie_offset);
  void SetupModules();
  void SetupSyscalls();
  void OnNotifier();

  void GetModuleFilename(void *base_address, std::string *name);

  void *RemoteMmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
  int RemoteMunmap(void *addr, size_t len);
  int RemoteOpen(const char *pathname, int flags, mode_t mode);
  int RemoteMprotect(void *addr, size_t len, int prot);
  void RemoteSyscall();

  int GetProt(MemoryProtection protection);

  void *GetTargetAddress(void *base_address);
  void HandleTargetReachedInternal();
  void HandleTargetEnded();

  char **GetEnvp();

  Register ArgumentToRegister(int arg);

  void *RemoteAllocateBefore(uint64_t min_address,
                             uint64_t max_address,
                             size_t size,
                             MemoryProtection protection,
                             std::vector<MapsEntry> &map_entries,
                             SharedMemory *shm);

  void *RemoteAllocateAfter(uint64_t min_address,
                            uint64_t max_address,
                            size_t size,
                            MemoryProtection protection,
                            std::vector<MapsEntry> &map_entries,
                            SharedMemory *shm);

  void *RemoteAllocateAt(uint64_t address, uint64_t size, MemoryProtection protection, SharedMemory *shm);

  void ReadStack(void *stack_addr, uint64_t *buffer, size_t numitems);
  void WriteStack(void *stack_addr, uint64_t *buffer, size_t numitems);

  void GetArchRegs(arch_reg_struct *regs);
  void SetArchRegs(arch_reg_struct *regs);

  void GetThreads(int pid);

  void CleanupTarget();

  void ResolveSymlinks(std::string *path);

  void Watchdog();
  friend void *debugger_watchdog_thread(void *arg);

  SharedMemory *CreateSharedMemory(size_t size);
  void ClearSharedMemory();
  std::list<SharedMemory> shared_memory;
  unsigned int curr_shm_index;

  volatile bool watchdog_enabled;
  volatile uint64_t watchdog_timeout_time;
  volatile bool killed_by_watchdog;
  std::mutex watchdog_mutex;

  std::unordered_map<std::string, std::string> symlink_cache;

  // todo initialize
  int proc_mem_fd;
  std::list<std::string> additional_env;
  pid_t main_pid, current_pid;
  uint64_t main_binary_header;
  uint64_t entrypoint_address;
  std::string main_binary_path;
  std::string main_binary_name;
  uint64_t rendezvous_address;
  uint64_t syscall_address;
  uint64_t debugger_allocated_memory;

  bool trace_debug_events;

  bool loop_mode;

  char target_module[PATH_MAX];
  char target_method[PATH_MAX];

  int target_num_args;
  uint64_t target_offset;

  void *target_address;
  void *saved_sp;
  void *saved_return_address;
  void **saved_args;
  TargetEndDetection target_end_detection;

  uint64_t target_return_value;

  DebuggerStatus handle_exception_status;
  DebuggerStatus dbg_last_status;

  bool killing_target;
  bool is_target_alive;
  bool attach_mode;

  bool linux32_warning;

  bool trace_syscalls;
  std::set<pid_t> pending_syscalls;
  __ptrace_request ptrace_continue_request;

  friend class SyscallHook;
  std::list<SyscallHook *> syscall_hooks;
};

#endif /* DEBUGGER_H */
