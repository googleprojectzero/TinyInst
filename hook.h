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

#ifndef HOOK_H
#define HOOK_H

#include <vector>
#include <string>
#include <tinyinst.h>
#include <list>
#include <unordered_map>

#include "tinyinst.h"

class TinyInst;
class Assembler;

class HookContext {
public:
  HookContext(size_t num_arguments);
  ~HookContext();

  uint64_t GetArg(size_t index);
  void SetArg(size_t index, uint64_t value);

  size_t num_arguments;
  uint64_t *arguments;
  uint64_t sp;
  uint64_t return_address;
  bool args_changed;
  
  // clients can store their per-call data here
  void *user_data;
};

class HookTrailer {
public:
  uint64_t trailer_start;
  uint64_t breakpoint;
  HookContext *context;
};

class Hook {
public:
  Hook(const char *module_name, const char *function_name, size_t num_args, CallingConvention call_convention = CALLCONV_DEFAULT)
    : module_name(module_name), function_name(function_name), callconv(call_convention), num_args(num_args), current_context(NULL), function_offset(0) { }
  
  Hook(const char *module_name, size_t offset, size_t num_args, CallingConvention call_convention = CALLCONV_DEFAULT)
    : module_name(module_name), function_offset(offset), callconv(call_convention), num_args(num_args), current_context(NULL) { }

  virtual void OnProcessExit() { }

  std::string &GetModuleName() {
    return module_name;
  }

  std::string &GetFunctionName() {
    return function_name;
  }

  uint64_t GetFunctionOffset() {
    return function_offset;
  }
  
  void SetTinyInst(TinyInst *tinyinst) {
    this->tinyinst = tinyinst;
  }

  void SetAssembler(Assembler *assembler) {
    this->assembler = assembler;
  }

  virtual InstructionResult InstrumentFunction(ModuleInfo* module, size_t function_address) = 0;
  
  virtual bool HandleBreakpoint(ModuleInfo *module, void *address) { return false; }

protected:
  uint64_t GetArg(size_t index);
  void SetArg(size_t index, uint64_t value);
  uint64_t GetRegister(Register r);
  void SetRegister(Register r, uint64_t value);
  void SetReturnValue(uint64_t value);
  uint64_t GetReturnValue();
  uint64_t GetReturnAddress();
  void SetReturnAddress(uint64_t address);
  
  void RemoteWrite(void *address, const void *buffer, size_t size);
  void RemoteRead(void *address, void *buffer, size_t size);
  void *RemoteAllocate(size_t size, MemoryProtection protection);


  void SaveArgs();
  void RestoreArgs();
  
  void WriteCode(ModuleInfo *module, void *data, size_t size);
  void CommitCode(ModuleInfo *module, size_t start_offset, size_t size);

  size_t GetCurrentInstrumentedAddress(ModuleInfo *module);
      
  HookContext *CreateContext();
  void CommitContext();

protected:
  HookContext *current_context;
  Assembler *assembler;
  TinyInst *tinyinst;
  std::string module_name;
  std::string function_name;
  uint64_t function_offset;
  CallingConvention callconv;
  size_t num_args;
};

class HookReplace : public Hook {
public:
  HookReplace(const char *module_name, const char *function_name, size_t num_args, CallingConvention call_convention = CALLCONV_DEFAULT) : Hook(module_name, function_name, num_args, call_convention) {
    breakpoint_address = 0;
  }
  
  HookReplace(const char *module_name, size_t offset, size_t num_args, CallingConvention call_convention = CALLCONV_DEFAULT) : Hook(module_name, offset, num_args, call_convention) {
    breakpoint_address = 0;
  }

protected:
  virtual InstructionResult InstrumentFunction(ModuleInfo* module, size_t function_address);

  virtual bool HandleBreakpoint(ModuleInfo *module, void *address);

  virtual void WriteCodeBefore(ModuleInfo* module) { }
  
  virtual void OnFunctionEntered() { }
  
  virtual void OnProcessExit();
  
private:
  uint64_t breakpoint_address;
};

class HookBegin : public Hook {
public:
  HookBegin(const char *module_name, const char *function_name, size_t num_args, CallingConvention call_convention = CALLCONV_DEFAULT) : Hook(module_name, function_name, num_args, call_convention) {
    breakpoint_address = 0;
  }

  HookBegin(const char *module_name, size_t offset, size_t num_args, CallingConvention call_convention = CALLCONV_DEFAULT) : Hook(module_name, offset, num_args, call_convention) {
    breakpoint_address = 0;
  }

protected:
  virtual InstructionResult InstrumentFunction(ModuleInfo* module, size_t function_address);

  virtual bool HandleBreakpoint(ModuleInfo *module, void *address);

  virtual void WriteCodeBefore(ModuleInfo* module) { }
  
  virtual void OnFunctionEntered() { }

  virtual void OnProcessExit();

private:
  uint64_t breakpoint_address;
};

class HookBeginEnd : public Hook {
public:
  HookBeginEnd(const char *module_name, const char *function_name, size_t num_args, CallingConvention call_convention = CALLCONV_DEFAULT) : Hook(module_name, function_name, num_args, call_convention) {
    breakpoint_before = 0;
  }
  
  HookBeginEnd(const char *module_name, size_t offset, size_t num_args, CallingConvention call_convention = CALLCONV_DEFAULT) : Hook(module_name, offset, num_args, call_convention) {
    breakpoint_before = 0;
  }

protected:
  virtual InstructionResult InstrumentFunction(ModuleInfo* module, size_t function_address);

  virtual bool HandleBreakpoint(ModuleInfo *module, void *address);
  
  virtual void WriteCodeBefore(ModuleInfo* module) { }
  virtual void WriteCodeAfter(ModuleInfo* module) { }

  virtual void OnFunctionEntered() { }
  
  virtual void OnFunctionReturned() { }
  
  virtual void OnProcessExit();

private:
  HookTrailer *CreateTrailer(ModuleInfo *module);
  
  uint64_t breakpoint_before;
  std::unordered_map<uint64_t, HookTrailer *> breakpoints_after;
  std::list<HookTrailer *> unused_trailers;
};



#endif /* HOOK_H */
