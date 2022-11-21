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

#ifndef ARCH_ARM64_ARM64_ASSEMBLER_H
#define ARCH_ARM64_ARM64_ASSEMBLER_H

#include "arch/arm64/arm64_helpers.h"
#include "assembler.h"
#include "tinyinst.h"

class Arm64Assembler : public Assembler {
 public:
  using Assembler::Assembler;
  virtual ~Arm64Assembler() {}
  void Init() override;

  bool DecodeInstruction(Instruction &inst, const unsigned char *buffer,
                         unsigned int buffer_size) override;
  void FixInstructionAndOutput(ModuleInfo *module, Instruction &inst,
                               const unsigned char *input,
                               const unsigned char *input_address_remote,
                               bool convert_call_to_jmp = false) override;
  void HandleBasicBlockEnd(
      const char *address, ModuleInfo *module, std::set<char *> *queue,
      std::list<std::pair<uint32_t, uint32_t>> *offset_fixes, Instruction &inst,
      const char *code_ptr, size_t offset, size_t last_offset) override;

  void JmpAddress(ModuleInfo *module, size_t address) override;
  void Nop(ModuleInfo *module) override;
  void Ret(ModuleInfo *module) override;
  size_t Breakpoint(ModuleInfo *module) override;
  void Crash(ModuleInfo *module) override;

  void OffsetStack(ModuleInfo *module, int32_t offset) override;
  bool IsRipRelative(ModuleInfo *module, Instruction &inst,
                     size_t instruction_address, size_t *mem_address) override;
  void TranslateJmp(ModuleInfo *module, ModuleInfo *target_module,
                    size_t original_target,
                    IndirectBreakpoinInfo &breakpoint_info,
                    bool global_indirect, size_t previous_offset) override;
  void InstrumentLocalIndirect(ModuleInfo *module, Instruction &inst,
                               size_t instruction_address,
                               size_t bb_address) override;
  void InstrumentGlobalIndirect(ModuleInfo *module, Instruction &inst,
                                size_t instruction_address) override;
  void FixOffset(ModuleInfo *module, uint32_t jmp_offset,
                 uint32_t target_offset) override;

 protected:
  void ReadRegStack(ModuleInfo *module, Register dst, int32_t offset);
  void WriteRegStack(ModuleInfo *module, Register src, int32_t offset);
  void EmitLoadLit(ModuleInfo *module, Register dst_reg, size_t size,
                   bool is_signed, uint64_t value);

 private:
  uint8_t MovIndirectTarget(ModuleInfo *module, Instruction &inst);

  void ReadStack(ModuleInfo *module, int32_t offset);
  void WriteStack(ModuleInfo *module, int32_t offset);

  void SetReturnAddress(ModuleInfo *module, uint64_t return_address);

  void InstrumentRet(const char *address, ModuleInfo *module,
                     std::set<char *> *queue,
                     std::list<std::pair<uint32_t, uint32_t>> *offset_fixes,
                     Instruction &inst, const char *code_ptr, size_t offset,
                     size_t last_offset);
  void InstrumentCondJmp(const char *address, ModuleInfo *module,
                         std::set<char *> *queue,
                         std::list<std::pair<uint32_t, uint32_t>> *offset_fixes,
                         Instruction &inst, const char *code_ptr, size_t offset,
                         size_t last_offset);
  void InstrumentJmp(const char *address, ModuleInfo *module,
                     std::set<char *> *queue,
                     std::list<std::pair<uint32_t, uint32_t>> *offset_fixes,
                     Instruction &inst, const char *code_ptr, size_t offset,
                     size_t last_offset);
  void InstrumentCall(const char *address, ModuleInfo *module,
                      std::set<char *> *queue,
                      std::list<std::pair<uint32_t, uint32_t>> *offset_fixes,
                      Instruction &inst, const char *code_ptr, size_t offset,
                      size_t last_offset);

  friend class LiteCov;
};
#endif  // ARCH_ARM64_ARM64_ASSEMBLER_H
