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

#include <mach-o/loader.h>

#include <limits.h>
#include <unordered_map>
#include <list>
#include <vector>
#include <mutex>

#include "common.h"


#ifdef ARM64
#include "arch/arm64/reg.h"
#else
#include "arch/x86/reg.h"
#endif

#include "macOS/machtarget.h"
extern "C" {
  #include "macOS/mig_server.h"
}

#ifdef ARM64
  #define MAX_NUM_REG_ARGS 8
  #define ARCH_THREAD_STATE ARM_THREAD_STATE64
  #define ARCH_THREAD_STATE_COUNT ARM_THREAD_STATE64_COUNT
  #define ARCH_THREAD_STATE_T arm_thread_state64_t

  #define ARCH_FPU_STATE ARM_NEON_STATE64
  #define ARCH_FPU_STATE_COUNT ARM_NEON_STATE64_COUNT
  #define ARCH_FPU_STATE_T arm_neon_state64_t

#else

  #define MAX_NUM_REG_ARGS 6
  #define ARCH_THREAD_STATE x86_THREAD_STATE64
  #define ARCH_THREAD_STATE_COUNT x86_THREAD_STATE64_COUNT
  #define ARCH_THREAD_STATE_T x86_thread_state64_t

  #define ARCH_FPU_STATE x86_FLOAT_STATE64
  #define ARCH_FPU_STATE_COUNT x86_FLOAT_STATE64_COUNT
  #define ARCH_FPU_STATE_T x86_float_state64_t
#endif

struct SavedRegisters {
  ARCH_THREAD_STATE_T gpr_registers;
  mach_msg_type_number_t gpr_count;
  ARCH_FPU_STATE_T fpu_registers;
  mach_msg_type_number_t fpu_count;
};

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

enum CallingConvention {
  CALLCONV_DEFAULT,
};

enum MemoryProtection {
  READONLY,
  READWRITE,
  READEXECUTE,
  READWRITEEXECUTE
};

class SharedMemory {
public:
  SharedMemory(mach_vm_address_t la,
		mach_vm_address_t ra,
		mach_vm_size_t s,
		mach_port_t p) : local_address(la), remote_address(ra), size(s), port(p) {}
  SharedMemory(const SharedMemory& other) : local_address(other.local_address),
					    remote_address(other.remote_address),
					    size(other.size),
					    port(other.port) {}
  SharedMemory &operator=(const SharedMemory& other) {
    local_address = other.local_address;
    remote_address = other.remote_address;
    size = other.size;
    port = other.port;
    return *this;
  }

  bool operator==(SharedMemory const& rhs) {
    return local_address == rhs.local_address &&
	  remote_address == rhs.remote_address &&
	  size == rhs.size &&
	  port == rhs.port;
  }

  mach_vm_address_t local_address;
  mach_vm_address_t remote_address;
  mach_vm_size_t size;
  mach_port_t port;
};

// From dyld SPI header dyld_process_info.h
typedef void *dyld_process_info;
struct dyld_process_cache_info {
  // UUID of cache used by process.
  uuid_t cacheUUID;
  // Load address of dyld shared cache.
  uint64_t cacheBaseAddress;
  // Process is running without a dyld cache.
  bool noCache;
  // Process is using a private copy of its dyld cache.
  bool privateCache;
};


class Debugger {
friend kern_return_t catch_mach_exception_raise_state_identity(
  mach_port_t exception_port,
  mach_port_t thread_port,
  mach_port_t task_port,
  exception_type_t exception_type,
  mach_exception_data_t code,
  mach_msg_type_number_t code_cnt,
  int *flavor,
  thread_state_t old_state,
  mach_msg_type_number_t old_state_cnt,
  thread_state_t new_state,
  mach_msg_type_number_t *new_state_cnt);

public:
  virtual void Init(int argc, char **argv);
  DebuggerStatus Run(char *cmd, uint32_t timeout);
  DebuggerStatus Run(int argc, char **argv, uint32_t timeout);
  DebuggerStatus Kill();
  DebuggerStatus Continue(uint32_t timeout);
  DebuggerStatus Attach(unsigned int pid, uint32_t timeout);

  bool IsTargetAlive();
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
  enum TargetEndDetection {
    RETADDR_STACK_OVERWRITE,
    RETADDR_BREAKPOINT
  };

  virtual void OnModuleLoaded(void *module, char *module_name);
  virtual void OnModuleUnloaded(void *module) {}

  virtual void OnProcessCreated();
  virtual void OnProcessExit();

  virtual void OnEntrypoint();
  virtual void OnTargetMethodReached() {}

  virtual void OnCrashed(Exception *exception_record) {}

  // should return true if the exception has been handled
  virtual bool OnException(Exception *exception_record) {
    return false;
  }

  size_t GetRegister(Register r);
  void SetRegister(Register r, size_t value);
  void SetReturnAddress(size_t value);
  size_t GetReturnAddress();

  void *GetModuleEntrypoint(void *base_address);
  bool IsDyld(void *base_address);

  void GetImageSize(void *base_address, size_t *min_address, size_t *max_address);

  MachTarget *mach_target;

  void ClearSharedMemory();
  void RemoteFree(void *address, size_t size);
  void RemoteWrite(void *address, const void *buffer, size_t size);
  void RemoteRead(void *address, void *buffer, size_t size);
  void RemoteProtect(void *address, size_t size, MemoryProtection protect);

  bool target_function_defined;
  bool trace_debug_events;
  bool attach_mode;
  bool loop_mode;
  bool disable_aslr;
  bool private_dlyd_cache;

  std::list<std::string> additional_env;
  
  bool child_entrypoint_reached;
  bool target_reached;

  int32_t child_ptr_size = sizeof(void*);

  // helper functions

  void *MakeSharedMemory(mach_vm_address_t address, size_t size, MemoryProtection protection);

  void *RemoteAllocate(size_t size,
                       MemoryProtection protection,
                       bool use_shared_memory = false);
  void *RemoteAllocateNear(uint64_t region_min,
                           uint64_t region_max,
                           size_t size,
                           MemoryProtection protection,
                           bool use_shared_memory = false);
  void *RemoteAllocate(size_t size);

  void ExtractCodeRanges(void *base_address,
                         size_t min_address,
                         size_t max_address,
                         std::list<AddressRange> *executable_ranges,
                         size_t *code_size);

  void ProtectCodeRanges(std::list<AddressRange> *executable_ranges);

  void PatchPointersRemote(void *base_address, std::unordered_map<size_t, size_t>& search_replace);
  void PatchPointersRemote(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace);
  
  // returns address in (potentially) instrumented code
  virtual size_t GetTranslatedAddress(size_t address) { return address; }
  
  void *GetTargetMethodAddress() { return target_address; }

  bool GetSectionAndSlide(void *mach_header_address,
                          const char *segname,
                          const char *sectname,
                          section_64 *ret_section,
                          size_t *file_vm_slide);
  
  void SaveRegisters(SavedRegisters *registers);
  void RestoreRegisters(SavedRegisters *registers);

  void *GetSymbolAddress(void *base_address, const char *symbol_name);

  void GetFunctionArguments(uint64_t *arguments, size_t num_arguments, uint64_t sp, CallingConvention callconv = CALLCONV_DEFAULT);
  void SetFunctionArguments(uint64_t *arguments, size_t num_arguments, uint64_t sp, CallingConvention callconv = CALLCONV_DEFAULT);

private:
  static std::unordered_map<task_t, Debugger*> task_to_debugger_map;
  static std::mutex map_mutex;
  std::list<SharedMemory> shared_memory;

  struct MachException {
    mach_port_t exception_port;
    mach_port_t thread_port;
    mach_port_t task_port;
    exception_type_t exception_type;
    mach_exception_data_t code;
    mach_msg_type_number_t code_cnt;
    int *flavor;
    thread_state_t new_state;
    mach_msg_type_number_t *new_state_cnt;

    MachException();

    MachException(mach_port_t exception_port,
                  mach_port_t thread_port,
                  mach_port_t task_port,
                  exception_type_t exception_type,
                  mach_exception_data_t code,
                  mach_msg_type_number_t code_cnt,
                  int *flavor,
                  thread_state_t new_state,
                  mach_msg_type_number_t *new_state_cnt)
    : exception_port(exception_port),
      thread_port(thread_port),
      task_port(task_port),
      exception_type(exception_type),
      code(code),
      code_cnt(code_cnt),
      flavor(flavor),
      new_state(new_state),
      new_state_cnt(new_state_cnt)
    {}
  };

  char **GetEnvp();

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

  MachException *mach_exception;
  Exception last_exception;

  std::list<SharedMemory>::iterator FreeSharedMemory(std::list<SharedMemory>::iterator it);
  void StartProcess(int argc, char **argv);
  DebuggerStatus DebugLoop(uint32_t timeout);
  void AttachToProcess();
  void HandleExceptionInternal(MachException *mach_exception);
  int HandleDebuggerBreakpoint();

  void PrintContext();

  DebuggerStatus handle_exception_status;
  DebuggerStatus dbg_last_status;
  kern_return_t dbg_continue_status;

  bool dbg_continue_needed;
  bool dbg_reply_needed;
  mach_msg_header_t *request_buffer;
  mach_msg_header_t *reply_buffer;

  bool killing_target;

  void GetMachHeader(void *mach_header_axddress, mach_header_64 *mach_header);
  void GetLoadCommandsBuffer(void *mach_header_address, const mach_header_64 *mach_header, void **load_commands);

  template <class TCMD>
  bool GetLoadCommand(mach_header_64 mach_header,
                      void *load_commands_buffer,
                      uint32_t load_cmd_type,
                      const char *segname,
                      TCMD **ret_command);

  void OnDyldImageNotifier(size_t mode, unsigned long infoCount, uint64_t machHeaders[]);

  void AddBreakpoint(void *address, int type);
  void DeleteBreakpoints();

  uint64_t* GetPointerToRegister(Register r);
  Register ArgumentToRegister(int arg);

  void CreateException(MachException *mach_exception, Exception *exception);
  vm_prot_t MacOSProtectionFlags(MemoryProtection memory_protection);

  void *GetTargetAddress(void *base_address);

  void RemoteProtect(void *address, size_t size, vm_prot_t protect);

  void HandleTargetReachedInternal();
  void HandleTargetEnded();

  void *RemoteAllocateBefore(uint64_t min_address,
                             uint64_t max_address,
                             size_t size,
                             MemoryProtection protection);

  void *RemoteAllocateAfter(uint64_t min_address,
                            uint64_t max_address,
                            size_t size,
                            MemoryProtection protection);

  kern_return_t RemoteAllocateAt(void *ret_address, int size);

  void ExtractSegmentCodeRanges(mach_vm_address_t segment_start_addr,
                                mach_vm_address_t segment_end_addr,
                                std::list<AddressRange> *executable_ranges,
                                size_t *code_size);

  void HandleDyld(void *module);

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

  // memory limit in bytes
  uint64_t target_memory_limit;

  //DYLD SPI
  void *(*m_dyld_process_info_create)(task_t task,
                                      uint64_t timestamp,
                                      kern_return_t *kernelError);

  void (*m_dyld_process_info_for_each_image)(void *info,
                                             void (^callback)(uint64_t machHeaderAddress,
                                                              const uuid_t uuid,
                                                              const char *path));

  void (*m_dyld_process_info_release)(void *info);

  void *m_dyld_debugger_notification;

  void *dyld_address;
};


#endif /* DEBUGGER_H */
