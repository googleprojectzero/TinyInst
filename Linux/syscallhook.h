/*
Copyright 2023 Google LLC

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

#ifndef SYSCALLHOOK_H
#define SYSCALLHOOK_H

#include "debugger.h"

enum SyscallStatus {
  SYSCALL_CONTINUE,
  SYSCALL_SKIP,
};

class SyscallHookContext {
public:
  SyscallHookContext(size_t num_arguments);
  ~SyscallHookContext();

  uint64_t GetArg(size_t index);
  void SetArg(size_t index, uint64_t value);
  uint64_t GetReturnValue();
  void SetReturnValue(uint64_t value);

  size_t num_arguments;
  uint64_t *arguments;
  uint64_t return_value;
  int current_thread;
  bool args_changed;
  bool return_value_changed;
  
  // clients can store their per-call data here
  void *user_data;
};

class SyscallHook {
public:
  SyscallHook(uint64_t syscall_number, size_t num_args, int thread_filter = 0)
    : thread_filter(thread_filter), syscall_number(syscall_number), num_args(num_args), current_context(NULL) { }
  
  virtual void OnProcessExit();
  
  virtual SyscallStatus OnSyscall() { return SYSCALL_CONTINUE; }
  virtual void OnSyscallEnd() { }

  void OnSyscallInternal(int thread_id, uint64_t syscall_number);
  void OnSyscallEndInternal(int thread_id);

  void SetDebugger(Debugger *debugger) {
    this->debugger = debugger;
  }

protected:
  uint64_t GetArg(size_t index);
  void SetArg(size_t index, uint64_t value);
  uint64_t GetRegister(Register r);
  void SetRegister(Register r, uint64_t value);
  void SetReturnValue(uint64_t value);
  uint64_t GetReturnValue();
  
  void RemoteWrite(void *address, const void *buffer, size_t size);
  void RemoteRead(void *address, void *buffer, size_t size);
  void *RemoteAllocate(size_t size, MemoryProtection protection);

  SyscallHookContext *CreateContext();
  void CommitContext();

protected:
  SyscallHookContext *current_context;
  Debugger *debugger;
  size_t num_args;
  int thread_filter;
  uint64_t syscall_number;

  std::unordered_map<int, SyscallHookContext *> thread_contexts;
};


#endif /* SYSCALLHOOK_H */
