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

#include "arch/arm64/arm64_assembler.h"

#include <cassert>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <variant>

#include "arch/arm64/arm64_helpers.h"
#include "common.h"

// brk 0
uint32_t BREAKPOINT = 0xd4200000;

// nop
uint32_t NOP = 0xd503201f;

// blr xzr
uint32_t CRASH = 0xd63f03e0;

uint32_t MRS_X0_NZCV = 0xd53b4200;
uint32_t MRS_X1_NZCV = 0xd53b4201;
uint32_t MSR_NZCV_X0 = 0xd51b4200;

// strip pac tag
uint32_t XPACI_X0 = 0xdac143e0;

uint32_t RETURN = 0xd65f03c0;

void PrintInstruction(uint64_t address, arm64::Instruction &instr) {
  std::cout << "0x" << std::hex << address << ": "
            << " " << std::setw(8) << std::setfill(' ')
            << *((uint32_t *)instr.address) << "   " << instr << "\n";
}

void PrintInstruction(Instruction &inst) {
  PrintInstruction(inst.address, inst.instr);
}

// load the return address into the lr register
void Arm64Assembler::SetReturnAddress(ModuleInfo *module,
                                       uint64_t return_address) {
  EmitLoadLit(module, Register::LR, 64, false, return_address);
}

void Arm64Assembler::JmpAddress(ModuleInfo *module, size_t address) {
  FATAL("not available on arm64");
}

void Arm64Assembler::Crash(ModuleInfo *module) {
  tinyinst_.WriteCode(module, &CRASH, sizeof(CRASH));
}

size_t Arm64Assembler::Breakpoint(ModuleInfo *module) {
  size_t ret = tinyinst_.GetCurrentInstrumentedAddress(module);
  tinyinst_.WriteCode(module, &BREAKPOINT, sizeof(BREAKPOINT));
  return ret;
}

void Arm64Assembler::Nop(ModuleInfo *module) {
  tinyinst_.WriteCode(module, &NOP, sizeof(NOP));
}

void Arm64Assembler::Ret(ModuleInfo *module) {
  tinyinst_.WriteCode(module, &RETURN, sizeof(RETURN));
}

static bool IsReturnInstruction(arm64::Opcode opcode) {
  switch (opcode) {
    case arm64::Opcode::kRetaa:
    case arm64::Opcode::kRetab:
    case arm64::Opcode::kRetaaz:
    case arm64::Opcode::kRetabz:
    case arm64::Opcode::kRet:
      return true;
    default:
      return false;
  }
}

static bool IsCondJmpInstruction(arm64::Opcode opcode) {
  switch (opcode) {
    case arm64::Opcode::kBCond:
    case arm64::Opcode::kCbnz:
    case arm64::Opcode::kCbz:
    case arm64::Opcode::kTbnz:
    case arm64::Opcode::kTbz:
      return true;
    default:
      return false;
  }
}

static bool IsJmpInstruction(arm64::Opcode opcode) {
  switch (opcode) {
    case arm64::Opcode::kB:
    case arm64::Opcode::kBr:
    case arm64::Opcode::kBraa:
    case arm64::Opcode::kBraaz:
    case arm64::Opcode::kBrab:
    case arm64::Opcode::kBrabz:
      return true;
    default:
      return false;
  }
}

static bool IsCallInstruction(arm64::Opcode opcode) {
  switch (opcode) {
    case arm64::Opcode::kBl:
    case arm64::Opcode::kBlr:
    case arm64::Opcode::kBlraa:
    case arm64::Opcode::kBlraaz:
    case arm64::Opcode::kBlrab:
    case arm64::Opcode::kBlrabz:
      return true;
    default:
      return false;
  }
}

void Arm64Assembler::EmitLoadLit(ModuleInfo *module, Register dst_reg,
                                 size_t size, bool is_signed, uint64_t value) {
  //    ldr dst_reg, label_value
  //    b next_instr
  //  label_value:
  //    0x11111111
  //    0x22222222
  // next_instr
  uint64_t addr = (uint64_t)module->instrumented_code_local +
                  module->instrumented_code_allocated;
  uint32_t ldr_lit_instr = ldr_lit(dst_reg, 8, size, is_signed);
  tinyinst_.WriteCode(module, &ldr_lit_instr, sizeof(ldr_lit_instr));
  uint32_t b_instr = b(0, 12);
  tinyinst_.WriteCode(module, &b_instr, sizeof(b_instr));
  tinyinst_.WriteCode(module, &value, sizeof(value));
}

void Arm64Assembler::FixOffset(ModuleInfo *module, uint32_t jmp_offset,
                               uint32_t target_offset) {
  uint64_t instr_address =
      (uint64_t)module->instrumented_code_local + jmp_offset;
  int32_t relative_offset = target_offset - jmp_offset;
  if (relative_offset & 3) {
    FATAL("relative_offset must be aligned");
  }

  relative_offset >>= 2;

  uint32_t instr = *((uint32_t *)instr_address);
  arm64::Instruction inst = arm64::DecodeInstruction(instr_address, instr);

  uint32_t encoded_imm = 0;
  switch (inst.opcode) {
    case arm64::Opcode::kBCond:
    case arm64::Opcode::kCbnz:
    case arm64::Opcode::kCbz:
    case arm64::Opcode::kLdrLiteral:
      encoded_imm = EncodeSignedImmediate(23, 5, relative_offset);
      break;

    case arm64::Opcode::kB:
    case arm64::Opcode::kBl:
      encoded_imm = EncodeSignedImmediate(25, 0, relative_offset);
      break;

    case arm64::Opcode::kTbz:
    case arm64::Opcode::kTbnz:
      encoded_imm = EncodeSignedImmediate(18, 5, relative_offset);
      break;

    default:
      PrintInstruction(instr_address, inst);
      FATAL("Unhandled instruction: %d\n", inst.opcode);
      break;
  }

  *((uint32_t *)instr_address) |= encoded_imm;
}


void Arm64Assembler::OffsetStack(ModuleInfo *module, int32_t offset) {
  uint32_t opcode = 0;
  if (offset & 0xF) {
    FATAL("Stack must be 16 bytes aligned");
  }
  if (offset < 0) {
    opcode = sub_reg_imm(Register::SP, Register::SP, std::abs(offset));
  } else {
    opcode = add_reg_imm(Register::SP, Register::SP, offset);
  }
  tinyinst_.WriteCode(module, &opcode, sizeof(opcode));
}

// ldr x0, [sp + offset]
void Arm64Assembler::ReadStack(ModuleInfo *module, int32_t offset) {
  ReadRegStack(module, Register::X0, offset);
}

// str x0, [sp + offset]
void Arm64Assembler::WriteStack(ModuleInfo *module, int32_t offset) {
  WriteRegStack(module, Register::X0, offset);
}

// ldr x0, [sp + offset]
void Arm64Assembler::ReadRegStack(ModuleInfo *module, Register dst,
                                  int32_t offset) {
  uint32_t ldr_instr = 0;

  if (std::abs(offset) < 255) {
    ldr_instr = ldr(64, dst, Register::SP, offset);
    tinyinst_.WriteCode(module, &ldr_instr, sizeof(ldr_instr));
  }

  else if (std::abs(offset) < 4096) {
    OffsetStack(module, offset);

    ldr_instr = ldr(64, dst, Register::SP, 0);
    tinyinst_.WriteCode(module, &ldr_instr, sizeof(ldr_instr));

    OffsetStack(module, -offset);
  } else {
    FATAL("offset out of range, max is [-0x1000, +0x1000], was: %d", offset);
  }
}

// str x0, [sp + offset]
void Arm64Assembler::WriteRegStack(ModuleInfo *module, Register src,
                                   int32_t offset) {
  uint32_t str_instr = 0;

  if (std::abs(offset) < 255) {
    str_instr = str(64, src, Register::SP, offset);
    tinyinst_.WriteCode(module, &str_instr, sizeof(str_instr));
  }

  else if (std::abs(offset) < 4096) {
    OffsetStack(module, offset);

    str_instr = str(64, src, Register::SP, 0);
    tinyinst_.WriteCode(module, &str_instr, sizeof(str_instr));

    OffsetStack(module, -offset);
  }

  else {
    FATAL("offset out of range, max is [-0x1000, +0x1000], was: %d", offset);
  }
}

void Arm64Assembler::InstrumentGlobalIndirect(ModuleInfo *module,
                                              Instruction &inst,
                                              size_t instruction_address) {
  FATAL(
      "-indirect_instrumentation=global is not supported on arm64 \
         please use 'local'");
}


// returns the register number which is used by the original code
// to perform the branch.
uint8_t Arm64Assembler::GetIndirectTarget(Instruction &inst, uint8_t *is_pac) {
  Register target_address_reg = Register::X0;
  uint8_t strip_pac = 0;

  switch (inst.instr.opcode) {
    case arm64::Opcode::kBraa:
    case arm64::Opcode::kBrab:
    case arm64::Opcode::kBraaz:
    case arm64::Opcode::kBrabz:

    case arm64::Opcode::kBlraa:
    case arm64::Opcode::kBlrab:
    case arm64::Opcode::kBlraaz:
    case arm64::Opcode::kBlrabz:
      strip_pac = 1;
      // fall through
    case arm64::Opcode::kBr:
    case arm64::Opcode::kBlr:
      target_address_reg =
          reg(std::get<arm64::Register>(inst.instr.operands[0]));
      break;

    case arm64::Opcode::kRetaa:
    case arm64::Opcode::kRetab:
      strip_pac = 1;
        // fall through
    case arm64::Opcode::kRet:
      target_address_reg = Register::LR;
      break;

    default:
      FATAL("not implemented yet");
  }

  if(is_pac) *is_pac = strip_pac;
  return static_cast<uint8_t>(target_address_reg);
}

// converts an indirect jump/call into a MOV instruction
// which moves the target of the indirect call into the X0 register
// and writes this instruction into the code buffer
void Arm64Assembler::MovIndirectTarget(ModuleInfo *module, uint8_t target_address_reg, uint8_t is_pac) {
  uint32_t mov_instr = mov(Register::X0, static_cast<Register>(target_address_reg));
  tinyinst_.WriteCode(module, &mov_instr, sizeof(mov_instr));
  if (is_pac) {
    tinyinst_.WriteCode(module, &XPACI_X0, sizeof(XPACI_X0));
  }
}

// translates indirect jump or call
// using local jumptable
void Arm64Assembler::InstrumentLocalIndirect(ModuleInfo *module,
                                             Instruction &inst,
                                             size_t instruction_address,
                                             size_t bb_address) {
  if (tinyinst_.sp_offset) {
    OffsetStack(module, -tinyinst_.sp_offset);
  }

  // XXX: save few instructions if sp_offset is != 0 save instructions by
  // including the offset which is needed to store flags and x0 by including
  // it in the if clause.
  OffsetStack(module, -32);

  uint8_t is_pac = 0;
  uint8_t branch_register_number = GetIndirectTarget(inst, &is_pac);

  // stack layout
  // x0
  // x1
  // alu flags
  WriteRegStack(module, Register::X1, 16);
  WriteRegStack(module, Register::X0, 8);
  if(branch_register_number != 0) {
    tinyinst_.WriteCode(module, &MRS_X0_NZCV, sizeof(MRS_X0_NZCV));
    WriteRegStack(module, Register::X0, 0);
  } else {
    tinyinst_.WriteCode(module, &MRS_X1_NZCV, sizeof(MRS_X1_NZCV));
    WriteRegStack(module, Register::X1, 0);
  }

  // Emit instructions that load the target address to the X0 register.
  MovIndirectTarget(module, branch_register_number, is_pac);

  // InstrumentLocalIndirect iterates through a linked list until the it
  // finds the code that was generated for the target address. Jumps are
  // performed with the help of the X1 register.
  uint32_t ldr_lit_instr = ldr_lit(Register::X1, 12, 64, false);
  uint32_t br_instr = br(Register::X1);
  tinyinst_.WriteCode(module, &ldr_lit_instr, sizeof(ldr_lit_instr));
  tinyinst_.WriteCode(module, &br_instr, sizeof(br_instr));

  // The end of the list is a breakpoint which is generated here.
  size_t breakpoint_address = tinyinst_.GetCurrentInstrumentedAddress(module);
  Breakpoint(module);
  module->br_indirect_newtarget_list[breakpoint_address] = {
      module->instrumented_code_allocated, bb_address, branch_register_number,
  };

  // Write address of the breakpoint to the head of the linked list
  // (this is the address which is loaded into X2).
  uint64_t address = (uint64_t)breakpoint_address;
  tinyinst_.WriteCode(module, &address, sizeof(address));
}

void Arm64Assembler::TranslateJmp(ModuleInfo *module, ModuleInfo *target_module,
                                  size_t original_target,
                                  IndirectBreakpoinInfo& breakpoint_info,
                                  bool global_indirect,
                                  size_t previous_offset) {
  uint64_t addr = (uint64_t)module->instrumented_code_local +
                  module->instrumented_code_allocated;
  size_t translate_jmp_off = module->instrumented_code_allocated;

  // Register number that was used by the original instruction
  // to perform the branch.
  uint64_t reg_num = breakpoint_info.branch_register;

  // offset of this instruction must be fixed
  size_t ldr_offset = module->instrumented_code_allocated;
  uint32_t ldr_lit_instr =
      ldr_lit(static_cast<Register>(reg_num), 0, 64, /*is_signed*/ false);
  tinyinst_.WriteCode(module, &ldr_lit_instr, sizeof(ldr_lit_instr));

  uint32_t cmp_instr = cmp(Register::X0, static_cast<Register>(reg_num));
  tinyinst_.WriteCode(module, &cmp_instr, sizeof(cmp_instr));

  uint32_t b_cond_instr = b_cond("eq", 8);
  tinyinst_.WriteCode(module, &b_cond_instr, sizeof(b_cond_instr));

  uint32_t b_previous_list_head_instr =
      b(0, (int32_t)((int64_t)previous_offset -
                     (int64_t)module->instrumented_code_allocated));
  tinyinst_.WriteCode(module, &b_previous_list_head_instr,
                      sizeof(b_previous_list_head_instr));

  // restore registers
  // stack layout
  // x1
  // x0
  // alu flags
  ReadRegStack(module, Register::X0, 0);
  tinyinst_.WriteCode(module, &MSR_NZCV_X0, sizeof(MSR_NZCV_X0));
  ReadRegStack(module, Register::X0, 8);
  ReadRegStack(module, Register::X1, 16);
  OffsetStack(module, 32);

  if (tinyinst_.sp_offset) {
    OffsetStack(module, tinyinst_.sp_offset);
  }

  // consider indirect call/jump an edge and insert appropriate instrumentation
  tinyinst_.InstrumentEdge(module, target_module, breakpoint_info.source_bb,
                           original_target);

  size_t ldr_offset2 = module->instrumented_code_allocated;
  ldr_lit_instr =
      ldr_lit(static_cast<Register>(reg_num), 0, 64, /*is_signed*/ false);
  tinyinst_.WriteCode(module, &ldr_lit_instr, sizeof(ldr_lit_instr));
  
  uint32_t br_instr = br(static_cast<Register>(reg_num));
  tinyinst_.WriteCode(module, &br_instr, sizeof(br_instr));
  
  FixOffset(module, ldr_offset, module->instrumented_code_allocated);
  FixOffset(module, ldr_offset2, module->instrumented_code_allocated + 8);
}

static int32_t GetRipRelativeOffset(Instruction &inst) {
  int64_t off64 = 0;

  switch (inst.instr.opcode) {
    case arm64::Opcode::kBCond:
    case arm64::Opcode::kB:
    case arm64::Opcode::kBl:
      off64 = static_cast<int64_t>(
          std::get<arm64::Immediate>(inst.instr.operands[0]).value);
      break;

    case arm64::Opcode::kCbz:
    case arm64::Opcode::kCbnz:
    case arm64::Opcode::kAdr:
    case arm64::Opcode::kAdrp:
      off64 = static_cast<int64_t>(
          std::get<arm64::Immediate>(inst.instr.operands[1]).value);
      break;

    case arm64::Opcode::kTbz:
    case arm64::Opcode::kTbnz:
      off64 = static_cast<int64_t>(
          std::get<arm64::Immediate>(inst.instr.operands[2]).value);
      break;

    case arm64::Opcode::kLdrLiteral:
    case arm64::Opcode::kLdrsLiteral:
      off64 =
          std::get<arm64::ImmediateOffset>(inst.instr.operands[1]).offset.value;
      break;

    default:
      PrintInstruction(inst);
      FATAL("Instruction not implemeted yet");
      break;
  }

  int32_t off32 = static_cast<int32_t>(off64);
  if (off32 != off64) {
    FATAL("imm unexpectedly does not fit into int32 (%lld vs %d)", off64,
          off32);
  }
  return off32;
}


bool Arm64Assembler::IsRipRelative(ModuleInfo *module, Instruction &inst,
                                   size_t instruction_address,
                                   size_t *mem_address) {
  bool pc_relative = false;
  int64_t offset;

  switch (inst.instr.opcode) {
    case arm64::kLdrLiteral:
    case arm64::kLdrsLiteral:
    case arm64::kAdr:
      pc_relative = true;
      offset = GetRipRelativeOffset(inst);
      break;

    case arm64::kAdrp:
      pc_relative = true;
      offset = GetRipRelativeOffset(inst);
      offset <<= 12;
      break;

    case arm64::kPrfmLiteral:
      // ¯\_(ツ)_/¯
      pc_relative = true;
      offset = 0;
      break;

    default:
      break;
  }

  if (!pc_relative) return false;

  *mem_address = (size_t)(instruction_address + offset);
  return pc_relative;
}

void Arm64Assembler::FixInstructionAndOutput(
    ModuleInfo *module, Instruction &inst, const unsigned char *input,
    const unsigned char *input_address_remote, bool convert_call_to_jmp) {
  size_t mem_address = 0;
  bool rip_relative =
      IsRipRelative(module, inst, (size_t)input_address_remote, &mem_address);

  size_t original_instruction_size = 4;

  bool needs_fixing = rip_relative || convert_call_to_jmp;

  // fast path
  // just copy instruction bytes without encoding
  if (!needs_fixing) {
    tinyinst_.WriteCode(module, (void *)input, original_instruction_size);
    return;
  }

  if (convert_call_to_jmp) {
    FATAL("convert_call_to_jmp not implemented");
  }

  if (!rip_relative) {
    tinyinst_.WriteCode(module, (void *)input, original_instruction_size);
    return;
  }

  switch (inst.instr.opcode) {
    case arm64::Opcode::kAdr: {
      uint64_t addr = (uint64_t)input_address_remote;
      addr += GetRipRelativeOffset(inst);
      auto dst_reg = std::get<arm64::Register>(inst.instr.operands[0]);
      EmitLoadLit(module, reg(dst_reg), dst_reg.size, false, addr);
      break;
    }

    case arm64::Opcode::kAdrp: {
      uint64_t addr = ((uint64_t)input_address_remote) >> 12;
      addr += GetRipRelativeOffset(inst);
      addr <<= 12;
      auto dst_reg = std::get<arm64::Register>(inst.instr.operands[0]);
      EmitLoadLit(module, reg(dst_reg), dst_reg.size, false, addr);
      break;
    }

    case arm64::Opcode::kLdrLiteral: {
      uint64_t addr = (uint64_t)input_address_remote;
      addr += GetRipRelativeOffset(inst);
      auto dst_reg = std::get<arm64::Register>(inst.instr.operands[0]);
      EmitLoadLit(module, reg(dst_reg), 64, false, addr);
      uint32_t ldr_instr = ldr(dst_reg.size, reg(dst_reg), reg(dst_reg), 0);
      tinyinst_.WriteCode(module, &ldr_instr, sizeof(ldr_instr));
      break;
    }

    case arm64::Opcode::kLdrsLiteral: {
      FATAL("arm64::kLdrsLiteral");
      break;
    }

    case arm64::Opcode::kPrfmLiteral:
      // ¯\_(ツ)_/¯
      tinyinst_.WriteCode(module, &NOP, sizeof(NOP));
      break;

    default:
      PrintInstruction(inst);
      FATAL("not implemented yet");
      break;
  }
}

void Arm64Assembler::InstrumentRet(
    const char *address, ModuleInfo *module, std::set<char *> *queue,
    std::list<std::pair<uint32_t, uint32_t>> *offset_fixes, Instruction &inst,
    const char *code_ptr, size_t offset, size_t last_offset) {
  TinyInst::IndirectInstrumentation ii_mode =
      tinyinst_.ShouldInstrumentIndirect(module, inst,
                                         (size_t)address + last_offset);

  if (ii_mode != TinyInst::IndirectInstrumentation::II_NONE) {
    tinyinst_.InstrumentIndirect(module, inst, (size_t)address + last_offset,
                                 ii_mode, (size_t)address);
  } else {
    FixInstructionAndOutput(module, inst,
                            (unsigned char *)(code_ptr + last_offset),
                            (unsigned char *)(address + last_offset));
  }
}

static uint32_t GetInstructionWithClearedImmediateBits(Instruction &inst) {
  uint32_t instruction = *((uint32_t *)inst.instr.address);

  switch (inst.instr.opcode) {
    case arm64::Opcode::kBCond:
      // clear all bits that are used for immediate value
      instruction &= ~bits(23, 5, 0xFFFFFFFF);
      break;
    case arm64::Opcode::kTbz:
    case arm64::Opcode::kTbnz:
      instruction &= ~bits(18, 5, 0xFFFFFFFF);
      break;
    case arm64::Opcode::kCbz:
    case arm64::Opcode::kCbnz:
      instruction &= ~bits(23, 5, 0xFFFFFFFF);
      break;
    default:
      PrintInstruction(inst);
      FATAL("Instruction not implemeted yet");
      break;
  }
  return instruction;
}

void Arm64Assembler::InstrumentCondJmp(
    const char *address, ModuleInfo *module, std::set<char *> *queue,
    std::list<std::pair<uint32_t, uint32_t>> *offset_fixes, Instruction &inst,
    const char *code_ptr, size_t offset, size_t last_offset) {
  // j* target_address
  // gets instrumented as:
  //   j* label
  //   <edge instrumentation>
  //   jmp continue_address
  // label:
  //   <edge instrumentation>
  //   jmp target_address

  uint32_t cond_jmp_instr = GetInstructionWithClearedImmediateBits(inst);
  int32_t branch_offset = GetRipRelativeOffset(inst);

  const char *target_address1 = address + offset;
  const char *target_address2 = address + last_offset + branch_offset;

  if (tinyinst_.GetModule((size_t)target_address2) != module) {
    WARN("Relative jump to a differen module in bb at %p\n",
         static_cast<const void *>(address));
    tinyinst_.InvalidInstruction(module);
    return;
  }

  // preliminary encode cond branch instruction
  // offset will be changed later as we don't know
  // the size of edge instrumentation yet
  // assuming 0 for now
  size_t cond_branch_offset = module->instrumented_code_allocated;
  tinyinst_.WriteCode(module, &cond_jmp_instr, sizeof(cond_jmp_instr));

  // instrument the 1st edge
  tinyinst_.InstrumentEdge(module, module, (size_t)address,
                           (size_t)target_address1);

  uint32_t branch_instr = b(0, 0);
  // jmp target_address1
  tinyinst_.WriteCode(module, &branch_instr, sizeof(branch_instr));

  tinyinst_.FixOffsetOrEnqueue(
      module,
      (uint32_t)((size_t)target_address1 - (size_t)(module->min_address)),
      (uint32_t)(module->instrumented_code_allocated - 4), queue, offset_fixes);

  // offset to the "label:" mentioned above
  uint32_t label_offset = module->instrumented_code_allocated;

  // fix conditional branch
  FixOffset(module, cond_branch_offset, label_offset);

  // instrument the 2nd edge
  tinyinst_.InstrumentEdge(module, module, (size_t)address,
                           (size_t)target_address2);

  // jmp target_address2
  tinyinst_.WriteCode(module, &branch_instr, sizeof(branch_instr));

  tinyinst_.FixOffsetOrEnqueue(
      module,
      (uint32_t)((size_t)target_address2 - (size_t)(module->min_address)),
      (uint32_t)(module->instrumented_code_allocated - 4), queue, offset_fixes);
}

void Arm64Assembler::InstrumentJmp(
    const char *address, ModuleInfo *module, std::set<char *> *queue,
    std::list<std::pair<uint32_t, uint32_t>> *offset_fixes, Instruction &inst,
    const char *code_ptr, size_t offset, size_t last_offset) {
  // direct branch
  if (inst.instr.opcode == arm64::Opcode::kB) {
    // jmp address
    // gets instrumented as:
    // jmp fixed_address
    size_t b_instr_off = module->instrumented_code_allocated;

    int32_t branch_offset = GetRipRelativeOffset(inst);

    const char *target_address = address + last_offset + branch_offset;

    if (tinyinst_.GetModule((size_t)target_address) != module) {
      WARN("Relative jump to a differen module in bb at %p\n", (void *)address);
      tinyinst_.InvalidInstruction(module);
      return;
    }

    uint32_t branch_instr = b(0, 0);
    // jmp target_address1
    tinyinst_.WriteCode(module, &branch_instr, sizeof(branch_instr));

    tinyinst_.FixOffsetOrEnqueue(
        module,
        (uint32_t)((size_t)target_address - (size_t)(module->min_address)),
        (uint32_t)(module->instrumented_code_allocated - 4), queue,
        offset_fixes);
  }

  // indirect branch
  else {
    TinyInst::IndirectInstrumentation ii_mode =
        tinyinst_.ShouldInstrumentIndirect(module, inst,
                                           (size_t)address + last_offset);
    if (ii_mode != TinyInst::IndirectInstrumentation::II_NONE) {
      tinyinst_.InstrumentIndirect(module, inst, (size_t)address + last_offset,
                                   ii_mode, (size_t)address);
    } else {
      FixInstructionAndOutput(module, inst,
                              (unsigned char *)(code_ptr + last_offset),
                              (unsigned char *)(address + last_offset));
    }
  }
}

void Arm64Assembler::InstrumentCall(
    const char *address, ModuleInfo *module, std::set<char *> *queue,
    std::list<std::pair<uint32_t, uint32_t>> *offset_fixes, Instruction &inst,
    const char *code_ptr, size_t offset, size_t last_offset) {
  // direct branch
  if (inst.instr.opcode == arm64::Opcode::kBl) {
    // call target_address
    // gets instrumented as:
    //   call label
    //   jmp return_address
    // label:
    //   jmp target_address

    int32_t branch_offset = GetRipRelativeOffset(inst);

    const char *return_address = address + offset;
    const char *call_address = address + last_offset + branch_offset;

    if (tinyinst_.GetModule((size_t)call_address) != module) {
      WARN("Relative jump to a differen module in bb at %p\n",
           static_cast<const void *>(address));
      tinyinst_.InvalidInstruction(module);
      return;
    }

    if (!tinyinst_.patch_return_addresses) {
      uint64_t addr = (uint64_t)module->instrumented_code_allocated +
                      (uint64_t)module->instrumented_code_local;
      size_t b_instr_off = module->instrumented_code_allocated;

      uint32_t bl_instr = bl(0, 8);
      tinyinst_.WriteCode(module, &bl_instr, sizeof(bl_instr));

      size_t translated_return_address = tinyinst_.GetCurrentInstrumentedAddress(module);
      tinyinst_.OnReturnAddress(module, (size_t)return_address, translated_return_address);

      uint32_t branch_instr = b(0, 0);
      // jmp return_address
      tinyinst_.WriteCode(module, &branch_instr, sizeof(branch_instr));

      tinyinst_.FixOffsetOrEnqueue(
          module,
          (uint32_t)((size_t)return_address - (size_t)(module->min_address)),
          (uint32_t)(module->instrumented_code_allocated - 4), queue,
          offset_fixes);

      // jmp call_address
      tinyinst_.WriteCode(module, &branch_instr, sizeof(branch_instr));

      tinyinst_.FixOffsetOrEnqueue(
          module,
          (uint32_t)((size_t)call_address - (size_t)(module->min_address)),
          (uint32_t)(module->instrumented_code_allocated - 4), queue,
          offset_fixes);
    } else {
      SetReturnAddress(module, (uint64_t)return_address);

      uint32_t branch_instr = b(0, 0);
      // jmp call_address
      tinyinst_.WriteCode(module, &branch_instr, sizeof(branch_instr));

      tinyinst_.FixOffsetOrEnqueue(
          module,
          (uint32_t)((size_t)call_address - (size_t)(module->min_address)),
          (uint32_t)(module->instrumented_code_allocated - 4), queue,
          offset_fixes);
      // done, we don't need to do anything else as return gets redirected
      // later
    }
  }
  // indirect branch
  else {
    const char *return_address = address + offset;
    TinyInst::IndirectInstrumentation ii_mode =
        tinyinst_.ShouldInstrumentIndirect(module, inst,
                                           (size_t)address + last_offset);

    if (ii_mode != TinyInst::IndirectInstrumentation::II_NONE) {
      if (tinyinst_.patch_return_addresses) {
        SetReturnAddress(module, (uint64_t)return_address);

        tinyinst_.InstrumentIndirect(module, inst,
                                     (size_t)address + last_offset, ii_mode,
                                     (size_t)address);
      } else {
        //   call label
        //   jmp return_address
        //  label:
        //    <indirect instrumentation>
        uint32_t bl_instr = bl(0, 8);
        tinyinst_.WriteCode(module, &bl_instr, sizeof(bl_instr));

        size_t translated_return_address = tinyinst_.GetCurrentInstrumentedAddress(module);
        tinyinst_.OnReturnAddress(module, (size_t)return_address, translated_return_address);

        uint32_t branch_instr = b(0, 0);
        // jmp return_address
        tinyinst_.WriteCode(module, &branch_instr, sizeof(branch_instr));

        tinyinst_.FixOffsetOrEnqueue(
            module,
            (uint32_t)((size_t)return_address - (size_t)(module->min_address)),
            (uint32_t)(module->instrumented_code_allocated - 4), queue,
            offset_fixes);

        tinyinst_.InstrumentIndirect(module, inst,
                                     (size_t)address + last_offset, ii_mode,
                                     (size_t)address);
      }
    } else {
      if (tinyinst_.patch_return_addresses) {
        SetReturnAddress(module, (uint64_t)return_address);
        FixInstructionAndOutput(module, inst,
                                (unsigned char *)(code_ptr + last_offset),
                                (unsigned char *)(address + last_offset), true);
      } else {
        FixInstructionAndOutput(module, inst,
                                (unsigned char *)(code_ptr + last_offset),
                                (unsigned char *)(address + last_offset));

        size_t translated_return_address = tinyinst_.GetCurrentInstrumentedAddress(module);
        tinyinst_.OnReturnAddress(module, (size_t)return_address, translated_return_address);

        uint32_t branch_instr = b(0, 0);
        tinyinst_.WriteCode(module, &branch_instr, sizeof(branch_instr));

        tinyinst_.FixOffsetOrEnqueue(
            module,
            (uint32_t)((size_t)return_address - (size_t)(module->min_address)),
            (uint32_t)(module->instrumented_code_allocated - 4), queue,
            offset_fixes);
      }
    }
  }
}

void Arm64Assembler::HandleBasicBlockEnd(
    const char *address, ModuleInfo *module, std::set<char *> *queue,
    std::list<std::pair<uint32_t, uint32_t>> *offset_fixes, Instruction &inst,
    const char *code_ptr, size_t offset, size_t last_offset) {
  
  if (IsReturnInstruction(inst.instr.opcode)) {
    InstrumentRet(address, module, queue, offset_fixes, inst, code_ptr, offset,
                  last_offset);
  }

  else if (IsCondJmpInstruction(inst.instr.opcode)) {
    InstrumentCondJmp(address, module, queue, offset_fixes, inst, code_ptr,
                      offset, last_offset);
  } else if (IsJmpInstruction(inst.instr.opcode)) {
    InstrumentJmp(address, module, queue, offset_fixes, inst, code_ptr, offset,
                  last_offset);
  }

  else if (IsCallInstruction(inst.instr.opcode)) {
    InstrumentCall(address, module, queue, offset_fixes, inst, code_ptr, offset,
                   last_offset);
  }

  else {
    PrintInstruction(inst);
    FATAL("Unexpected control-flow instruction");
  }
}

bool Arm64Assembler::DecodeInstruction(Instruction &inst,
                                       const unsigned char *buffer,
                                       unsigned int buffer_size) {
  uint32_t opcode;
  memcpy(&opcode, buffer, sizeof(opcode));
  inst.instr = arm64::DecodeInstruction((uint64_t)buffer, opcode);
  inst.address = (size_t)buffer;
  inst.length = 4;
  inst.bbend = false;

  switch (inst.instr.opcode) {
    case arm64::Opcode::kBl:
    case arm64::Opcode::kBlr:
    case arm64::Opcode::kBlraa:
    case arm64::Opcode::kBlraaz:
    case arm64::Opcode::kBlrab:
    case arm64::Opcode::kBlrabz:
      inst.bbend = true;
      inst.iclass = InstructionClass::ICALL;
      break;

    case arm64::Opcode::kB:
    case arm64::Opcode::kBr:
    case arm64::Opcode::kBraa:
    case arm64::Opcode::kBraaz:
    case arm64::Opcode::kBrab:
    case arm64::Opcode::kBrabz:
    case arm64::Opcode::kCbnz:
    case arm64::Opcode::kCbz:
    case arm64::Opcode::kTbnz:
    case arm64::Opcode::kTbz:
    case arm64::Opcode::kBCond:
      inst.bbend = true;
      inst.iclass = InstructionClass::IJUMP;
      break;

    case arm64::Opcode::kRet:
    case arm64::Opcode::kRetaa:
    case arm64::Opcode::kRetaaz:
    case arm64::Opcode::kRetab:
    case arm64::Opcode::kRetabz:
      inst.bbend = true;
      inst.iclass = InstructionClass::RET;
      break;

    default:
      inst.iclass = InstructionClass::OTHER;
      break;
  }
  return true;
}

void Arm64Assembler::Init(){};
