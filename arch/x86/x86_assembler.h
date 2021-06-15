/*
Copyright 2021 Google LLC

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

#ifndef X86ASSEMBLER_H
#define X86ASSEMBLER_H

#include "assembler.h"

extern "C" {
#include "xed/xed-interface.h"
}

#include "tinyinst.h"

class X86Assembler : public Assembler {
 public:
  // X86Assembler(TinyInst& tinyinst) : Assembler(tinyinst) {}
  using Assembler::Assembler;
  virtual ~X86Assembler() {}
  void Init() override;

  bool DecodeInstruction(Instruction &inst,
                         const unsigned char *buffer,
                         unsigned int buffer_size) override;
  void FixInstructionAndOutput(ModuleInfo *module,
                               Instruction &inst,
                               const unsigned char *input,
                               const unsigned char *input_address_remote,
                               bool convert_call_to_jmp = false) override;
  void HandleBasicBlockEnd(
      const char *address,
      ModuleInfo *module, std::set<char *> *queue,
      std::list<std::pair<uint32_t, uint32_t>> *offset_fixes,
      Instruction &inst,
      const char *code_ptr,
      size_t offset,
      size_t last_offset) override;

  void JmpAddress(ModuleInfo *module, size_t address) override;
  void Nop(ModuleInfo *module) override;
  void Breakpoint(ModuleInfo *module) override;

  void OffsetStack(ModuleInfo *module, int32_t offset) override;
  bool IsRipRelative(ModuleInfo *module,
                     Instruction &inst,
                     size_t instruction_address,
                     size_t *mem_address) override;
  void TranslateJmp(ModuleInfo *module,
                         ModuleInfo *target_module,
                         size_t original_target,
                         size_t edge_start_address,
                         bool global_indirect,
                         size_t previous_offset) override;
  void InstrumentLocalIndirect(ModuleInfo *module,
                               Instruction &inst,
                               size_t instruction_address,
                               size_t bb_address) override;
  void InstrumentGlobalIndirect(ModuleInfo *module,
                                Instruction &inst,
                                size_t instruction_address) override;
  void FixOffset(ModuleInfo *module,
                 uint32_t jmp_offset,
                 uint32_t target_offset) override;
 private:
  inline void FixDisp4(ModuleInfo *module, int32_t disp);
  void ReadStack(ModuleInfo *module, int32_t offset);
  void WriteStack(ModuleInfo *module, int32_t offset);
  void MovIndirectTarget(ModuleInfo *module,
                         Instruction &inst,
                         size_t original_address,
                         int32_t stack_offset);

  void InstrumentRet(ModuleInfo *module,
                     Instruction &inst,
                     size_t instruction_address,
                     TinyInst::IndirectInstrumentation mode,
                     size_t bb_address);
  void PushReturnAddress(ModuleInfo *module, uint64_t return_address);

  void InvalidInstruction(ModuleInfo *module);

  int xed_mmode_;
};

#endif  // X86ASSEMBLER_H
