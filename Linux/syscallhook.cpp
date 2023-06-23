#include "common.h"
#include "syscallhook.h"

SyscallHookContext::SyscallHookContext(size_t num_arguments) {
  this->num_arguments = num_arguments;
  arguments = NULL;
  if(num_arguments) {
    arguments = (uint64_t *)malloc(num_arguments * sizeof(uint64_t));
  }
  args_changed = false;
  return_value_changed = false;
  user_data = NULL;
  current_thread = 0;
  return_value = 0;
}

SyscallHookContext::~SyscallHookContext() {
  if(arguments) free(arguments);
}

uint64_t SyscallHookContext::GetArg(size_t index) {
  if(index >= num_arguments) {
    FATAL("Requested argument exceeds function number of arguments");
  }
  return arguments[index];
}

void SyscallHookContext::SetArg(size_t index, uint64_t value) {
  if(index >= num_arguments) {
    FATAL("Requested argument exceeds function number of arguments");
  }
  arguments[index] = value;
  args_changed = true;
}

uint64_t SyscallHookContext::GetReturnValue() {
  return return_value;
}

void SyscallHookContext::SetReturnValue(uint64_t value) {
  return_value = value;
  return_value_changed = true;
}

uint64_t SyscallHook::GetArg(size_t index) {
  if(!current_context) {
    FATAL("Can't access arguments, did the function run yet?");
  }
  
  return current_context->GetArg(index);
}

void SyscallHook::SetArg(size_t index, uint64_t value) {
  if(!current_context) {
    FATAL("Can't access arguments, did the function run yet?");
  }
  
  current_context->SetArg(index, value);
}

uint64_t SyscallHook::GetRegister(Register r) {
  return debugger->GetRegister(r);
}

void SyscallHook::SetRegister(Register r, uint64_t value) {
  debugger->SetRegister(r, value);
}

void SyscallHook::SetReturnValue(uint64_t value) {
  return current_context->SetReturnValue(value);
}

uint64_t SyscallHook::GetReturnValue() {
  return current_context->GetReturnValue();
}

void SyscallHook::RemoteWrite(void *address, const void *buffer, size_t size) {
  debugger->RemoteWrite(address, buffer, size);
}

void SyscallHook::RemoteRead(void *address, void *buffer, size_t size) {
  debugger->RemoteRead(address, buffer, size);
}

void *SyscallHook::RemoteAllocate(size_t size, MemoryProtection protection) {
  return debugger->RemoteAllocate(size, protection);
}

SyscallHookContext *SyscallHook::CreateContext() {
  SyscallHookContext *context = new SyscallHookContext(num_args);
  debugger->GetSyscallArguments(context->arguments, num_args);
  return context;
}

void SyscallHook::CommitContext() {
  if(!current_context->args_changed) return;
  debugger->SetSyscallArguments(current_context->arguments,
                                 current_context->num_arguments);
}

void SyscallHook::OnSyscallInternal(int thread_id, uint64_t syscall_number) {
  if(syscall_number != this->syscall_number) return;
  if(thread_filter && (thread_id != thread_filter)) return;

  current_context = CreateContext();

  SyscallStatus ret = OnSyscall();

  if(ret == SYSCALL_SKIP) SetRegister(SYSCALL_NUMER_REGISTER, (uint64_t)-1);

  CommitContext();

  thread_contexts[thread_id] = current_context;
  current_context = NULL;
}

void SyscallHook::OnSyscallEndInternal(int thread_id) {
  if(thread_filter && (thread_id != thread_filter)) return;

  auto iter = thread_contexts.find(thread_id);
  if(iter == thread_contexts.end()) return;
  current_context = iter->second;
  thread_contexts.erase(iter);

  if(!current_context->return_value_changed) {
    current_context->return_value = GetRegister(SYSCALL_RETURN_REGISTER);
  }  

  OnSyscallEnd();

  if(current_context->return_value_changed) {
    SetRegister(SYSCALL_RETURN_REGISTER, current_context->return_value);
  }

  delete current_context;
  current_context = NULL;
}

void SyscallHook::OnProcessExit() {
  if(current_context) {
    delete current_context;
    current_context = NULL;
  }
  for(auto iter = thread_contexts.begin(); iter != thread_contexts.end(); iter++) {
    delete iter->second;
  }
  thread_contexts.clear();
}
