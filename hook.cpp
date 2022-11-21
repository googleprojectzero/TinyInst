/*
Copyright 2022 Google LLC

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

#include "common.h"
#include "hook.h"

HookContext::HookContext(size_t num_arguments) {
  this->num_arguments = num_arguments;
  arguments = NULL;
  if(num_arguments) {
    arguments = (uint64_t *)malloc(num_arguments * sizeof(uint64_t));
  }
  sp = 0;
  return_address = 0;
  args_changed = false;
  user_data = NULL;
}

HookContext::~HookContext() {
  if(arguments) free(arguments);
}

uint64_t HookContext::GetArg(size_t index) {
  if(index >= num_arguments) {
    FATAL("Requested argument exceeds function number of arguments");
  }
  return arguments[index];
}

void HookContext::SetArg(size_t index, uint64_t value) {
  if(index >= num_arguments) {
    FATAL("Requested argument exceeds function number of arguments");
  }
  arguments[index] = value;
  args_changed = true;
}

uint64_t Hook::GetArg(size_t index) {
  if(!current_context) {
    FATAL("Can't access arguments, did the function run yet?");
  }
  
  return current_context->GetArg(index);
}

void Hook::SetArg(size_t index, uint64_t value) {
  if(!current_context) {
    FATAL("Can't access arguments, did the function run yet?");
  }
  
  current_context->SetArg(index, value);
}

uint64_t Hook::GetRegister(Register r) {
  return tinyinst->GetRegister(r);
}

void Hook::SetRegister(Register r, uint64_t value) {
  tinyinst->SetRegister(r, value);
}

void Hook::SetReturnValue(uint64_t value) {
  tinyinst->SetRegister(ARCH_RETURN_VALUE_REGISTER, value);
}

uint64_t Hook::GetReturnValue() {
  return tinyinst->GetRegister(ARCH_RETURN_VALUE_REGISTER);
}

uint64_t Hook::GetReturnAddress() {
  return tinyinst->GetReturnAddress();
}

void Hook::SetReturnAddress(uint64_t address) {
  tinyinst->SetReturnAddress(address);
}

void Hook::RemoteWrite(void *address, const void *buffer, size_t size) {
  tinyinst->RemoteWrite(address, buffer, size);
}

void Hook::RemoteRead(void *address, void *buffer, size_t size) {
  tinyinst->RemoteRead(address, buffer, size);
}

void *Hook::RemoteAllocate(size_t size, MemoryProtection protection) {
  return tinyinst->RemoteAllocate(size, protection);
}

void Hook::WriteCode(ModuleInfo *module, void *data, size_t size) {
  tinyinst->WriteCode(module, data, size);
}

void Hook::CommitCode(ModuleInfo *module, size_t start_offset, size_t size) {
  tinyinst->CommitCode(module, start_offset, size);
}

size_t Hook::GetCurrentInstrumentedAddress(ModuleInfo *module) {
  return tinyinst->GetCurrentInstrumentedAddress(module);
}

HookContext *Hook::CreateContext() {
  HookContext *context = new HookContext(num_args);
  uint64_t sp = tinyinst->GetRegister(ARCH_SP);
  context->sp = sp;
  context->return_address = GetReturnAddress();
  tinyinst->GetFunctionArguments(context->arguments, num_args, sp, callconv);
  return context;
}

void Hook::CommitContext() {
  if(!current_context->args_changed) return;
  tinyinst->SetFunctionArguments(current_context->arguments,
                                 current_context->num_arguments,
                                 current_context->sp, callconv);

}

InstructionResult HookReplace::InstrumentFunction(ModuleInfo* module, size_t function_address) {
  breakpoint_address = assembler->Breakpoint(module);
  WriteCodeBefore(module);
  assembler->Ret(module);
  return INST_STOPBB;
}

bool HookReplace::HandleBreakpoint(ModuleInfo *module, void *address) {
  if((size_t)address == breakpoint_address) {
    current_context = CreateContext();

    OnFunctionEntered();

    CommitContext();
    delete current_context;
    current_context = NULL;

    return true;
  }
  
  return false;
}

void HookReplace::OnProcessExit() {
  breakpoint_address = 0;
  if(current_context) delete current_context;
}

InstructionResult HookBegin::InstrumentFunction(ModuleInfo* module, size_t function_address) {
  breakpoint_address = assembler->Breakpoint(module);
  WriteCodeBefore(module);
  return INST_NOTHANDLED;
}

bool HookBegin::HandleBreakpoint(ModuleInfo *module, void *address) {
  if((size_t)address == breakpoint_address) {
    current_context = CreateContext();

    OnFunctionEntered();

    CommitContext();
    delete current_context;
    current_context = NULL;

    return true;
  }
  
  return false;
}

void HookBegin::OnProcessExit() {
  breakpoint_address = 0;
  if(current_context) delete current_context;
}


InstructionResult HookBeginEnd::InstrumentFunction(ModuleInfo* module, size_t function_address) {
  breakpoint_before = assembler->Breakpoint(module);
  WriteCodeBefore(module);
  return INST_NOTHANDLED;
}

bool HookBeginEnd::HandleBreakpoint(ModuleInfo *module, void *address) {
  if((size_t)address == breakpoint_before) {
    current_context = CreateContext();

    OnFunctionEntered();

    CommitContext();
    
    HookTrailer *trailer;
    if(!unused_trailers.empty()) {
      trailer = *unused_trailers.begin();
      unused_trailers.pop_front();
    } else {
      trailer = CreateTrailer(module);
    }
    
    // we can't rely on current_context being the same when we reach
    // breakpoint_after, because the hooked function could have been
    // entered from another thread or called recursively
    // that's why we allocate unique breakpoint per call and associate
    // context with it
    trailer->context = current_context;
    breakpoints_after[trailer->breakpoint] = trailer;
    
    SetReturnAddress(trailer->trailer_start);
    
    return true;
  }
  
  auto iter = breakpoints_after.find((uint64_t)address);
  if(iter != breakpoints_after.end()) {
    HookTrailer *trailer = iter->second;
    current_context = trailer->context;
    
    OnFunctionReturned();
    
    SetRegister(ARCH_PC, current_context->return_address);

    unused_trailers.push_back(trailer);
    breakpoints_after.erase(iter);
    
    trailer->context = NULL;
    delete current_context;
    current_context = NULL;

    return true;
  }
  
  return false;
}

HookTrailer *HookBeginEnd::CreateTrailer(ModuleInfo *module) {
  HookTrailer *trailer = new HookTrailer();
  trailer->trailer_start = GetCurrentInstrumentedAddress(module);
  
  size_t code_size_before = module->instrumented_code_allocated;
  
  WriteCodeAfter(module);
  // Breakpoint needs to be *after* user-inserted code
  // because when resolving the breakpoint, we jump
  // to the real return address
  trailer->breakpoint = assembler->Breakpoint(module);

  size_t code_size_after = module->instrumented_code_allocated;
  CommitCode(module, code_size_before, (code_size_after - code_size_before));
  
  return trailer;
}

void HookBeginEnd::OnProcessExit() {
  breakpoint_before = 0;
  for(auto iter = breakpoints_after.begin(); iter != breakpoints_after.end(); iter++) {
    if(iter->second->context) delete iter->second->context;
    delete iter->second;
  }
  breakpoints_after.clear();
  for(auto iter = unused_trailers.begin(); iter != unused_trailers.end(); iter++) {
    delete *iter;
  }
  unused_trailers.clear();
}
