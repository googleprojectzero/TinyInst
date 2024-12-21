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
#include "arch/arm64/arm64_helpers.h"
#include "common.h"
#include "instruction.h"
#include "litecov.h"

void LiteCov::NopCovInstructions(ModuleInfo *module, size_t code_offset) {
  uint32_t b_instr = b(0, skip_cov_instruction_br_off);
  WriteCodeAtOffset(module, code_offset, &b_instr, sizeof(b_instr));
  // need to commit since this isn't a part of normal instrumentation process
  CommitCode(module, code_offset, sizeof(b_instr));
}

void LiteCov::NopCmpCovInstructions(ModuleInfo *module,
                                    CmpCoverageRecord &cmp_record,
                                    int matched_width) {
  if (matched_width >= cmp_record.width - 8) {
    uint32_t b_instr = b(0, cmp_record.instrumentation_size);
    WriteCodeAtOffset(module, cmp_record.instrumentation_offset, &b_instr,
                      sizeof(b_instr));
    CommitCode(module, cmp_record.instrumentation_offset, sizeof(b_instr));
    cmp_record.ignored = true;
    return;
  }

  if (matched_width >= cmp_record.match_width) {
    cmp_record.match_width = matched_width + 8;
    char new_offset_data = static_cast<char>(cmp_record.match_width);
    WriteCodeAtOffset(module, cmp_record.match_width_offset, &new_offset_data,
                      1);
    CommitCode(module, cmp_record.instrumentation_offset, 1);
  }
}

void LiteCov::EmitCoverageInstrumentation(ModuleInfo *module,
                                          size_t bit_address,
                                          size_t mov_address) {
  //////////////////////////////////////////////////
  // mov [coverage_buffer + coverage_buffer_next], 1
  //////////////////////////////////////////////////

  Arm64Assembler *arm64asm = static_cast<Arm64Assembler *>(assembler_);

  size_t cov_instruction_start_off = module->instrumented_code_allocated;
  if (sp_offset) {
    arm64asm->OffsetStack(module, -sp_offset);
  }
  // 3 instr
  arm64asm->OffsetStack(module, -16);
  arm64asm->WriteRegStack(module, X0, 0);
  arm64asm->WriteRegStack(module, X1, 8);

  // 4 + 2 instr
  arm64asm->EmitLoadLit(module, X0, 64, false, bit_address);
  uint32_t mov = movz_imm(X1, 1);
  WriteCode(module, &mov, sizeof(mov));
  uint32_t strb = str(8, X1, X0, 0);
  WriteCode(module, &strb, sizeof(strb));

  // 3 instr
  arm64asm->ReadRegStack(module, X1, 8);
  arm64asm->ReadRegStack(module, X0, 0);
  arm64asm->OffsetStack(module, 16);

  if (sp_offset) {
    arm64asm->OffsetStack(module, sp_offset);
  }

  skip_cov_instruction_br_off = 
    module->instrumented_code_allocated - cov_instruction_start_off;
}

InstructionResult LiteCov::InstrumentInstruction(ModuleInfo *module,
                                                 Instruction &inst,
                                                 size_t bb_address,
                                                 size_t instruction_address) {
  
  InstructionResult tinyinst_ret = TinyInst::InstrumentInstruction(module, inst, bb_address, instruction_address);
  if(tinyinst_ret != INST_NOTHANDLED) return tinyinst_ret;

  if (!compare_coverage) {
    return INST_NOTHANDLED;
  }

  if (inst.instr.opcode != arm64::Opcode::kSubImmediate &&
      inst.instr.opcode != arm64::Opcode::kAddImmediate &&
      inst.instr.opcode != arm64::Opcode::kSubShiftedRegister &&
      inst.instr.opcode != arm64::Opcode::kAddShiftedRegister &&
      inst.instr.opcode != arm64::Opcode::kSubExtendedRegister &&
      inst.instr.opcode != arm64::Opcode::kAddExtendedRegister) {
    return INST_NOTHANDLED;
  }

  arm64::Register rd = std::get<arm64::Register>(inst.instr.operands[0]);
  int operand_width = rd.size;

  // Skip instructions that are unlikely to be used as compare:
  //  most compare instructions have zero register as destination
  //  switch statements use subs (setting flag)
  if (rd.name != arm64::Register::kXzr &&
      !(inst.instr.set_flags &&
        (inst.instr.opcode == arm64::Opcode::kSubImmediate ||
        inst.instr.opcode == arm64::Opcode::kSubShiftedRegister ||
        inst.instr.opcode == arm64::Opcode::kSubExtendedRegister))) {
    return INST_NOTHANDLED;
  }

  arm64::Register rn = std::get<arm64::Register>(inst.instr.operands[1]);
  if (rn.name == arm64::Register::kSp) {
    return INST_NOTHANDLED;
  }

  if (inst.instr.opcode == arm64::Opcode::kSubShiftedRegister ||
      inst.instr.opcode == arm64::Opcode::kAddShiftedRegister ||
      inst.instr.opcode == arm64::Opcode::kAddExtendedRegister ||
      inst.instr.opcode == arm64::Opcode::kSubExtendedRegister) {
    arm64::Register rm = std::get<arm64::Register>(inst.instr.operands[2]);
    if (rm.name == arm64::Register::kSp) {
      return INST_NOTHANDLED;
    }
  }

  // kSubExtendedRegister / kAddExtendedRegister might have sizes smaller than
  // 32 bit. In case of 8 bit cmp, skip, in case of 16bit cmp add and-instr
  // after xor.
  bool is_ext_16_bit = false;

  if (inst.instr.opcode == arm64::Opcode::kAddExtendedRegister ||
      inst.instr.opcode == arm64::Opcode::kSubExtendedRegister) {
    arm64::Extend extend = std::get<arm64::Extend>(inst.instr.operands[3]);

    // skip byte cmp
    if (extend.type == arm64::Extend::Type::kUxtb ||
        extend.type == arm64::Extend::Type::kSxtb) {
      return INST_NOTHANDLED;
    }
  }


  ModuleCovData *data = (ModuleCovData *)module->client_data;

  size_t bb_offset = bb_address - module->min_address;
  size_t cmp_offset = instruction_address - bb_address;
  if (cmp_offset >= 0x1000000) {
    // only allow one cmp instrumentation per bb
    WARN("Too large basic block for cmp coverage\n");
    return INST_NOTHANDLED;
  }

  // check what we matched already
  int match_width = operand_width - 8;
  for (; match_width >= 8; match_width -= 8) {
    uint64_t already_matched_code =
        GetCmpCode(bb_offset, cmp_offset, match_width);
    if (data->ignore_coverage.find(already_matched_code) !=
        data->ignore_coverage.end()) {
      break;
    }
  }
  match_width += 8;
  if (match_width == operand_width) {
    // we already have an (almost) full match
    return INST_NOTHANDLED;
  }

  size_t instrumentation_start_offset = module->instrumented_code_allocated;

  Arm64Assembler *arm64asm = static_cast<Arm64Assembler *>(assembler_);

  if (sp_offset) {
    arm64asm->OffsetStack(module, -sp_offset);
  }
  arm64asm->OffsetStack(module, -16);
  arm64asm->WriteRegStack(module, X1, 8);
  arm64asm->WriteRegStack(module, X0, 0);

  uint32_t eor_instr = 0;
  if (inst.instr.opcode == arm64::Opcode::kSubShiftedRegister ||
      inst.instr.opcode == arm64::Opcode::kAddShiftedRegister) {
    arm64::Register rn = std::get<arm64::Register>(inst.instr.operands[1]);
    arm64::Register rm = std::get<arm64::Register>(inst.instr.operands[2]);
    arm64::Shift shift = std::get<arm64::Shift>(inst.instr.operands[3]);

    eor_instr = eor_shifted_reg(operand_width, X0, reg(rn), reg(rm), shift.type,
                                shift.count);
  } else if (inst.instr.opcode == arm64::Opcode::kSubImmediate ||
             inst.instr.opcode == arm64::Opcode::kAddImmediate) {
    // Immediate encoding for xor is complex (DecodeBitMasks), hence, move
    // the imm into x0 or x1 for eor
    Register imm_reg = X0;
    if (rn.name == arm64::Register::Name::kX0) {
      imm_reg = X1;
    }

    auto imm = std::get<arm64::Immediate>(inst.instr.operands[2]);
    uint32_t mov_imm_instr = movz_imm(imm_reg, imm.value);
    WriteCode(module, &mov_imm_instr, sizeof(mov_imm_instr));

    eor_instr = eor_shifted_reg(operand_width, X0, reg(rn), imm_reg,
                                arm64::Shift::Type::kNone, 0);
  }

  else if (inst.instr.opcode == arm64::Opcode::kAddExtendedRegister ||
           inst.instr.opcode == arm64::Opcode::kSubExtendedRegister) {
    arm64::Register rn = std::get<arm64::Register>(inst.instr.operands[1]);
    arm64::Register rm = std::get<arm64::Register>(inst.instr.operands[2]);
    arm64::Extend extend = std::get<arm64::Extend>(inst.instr.operands[3]);

    if (extend.type == arm64::Extend::Type::kUxth ||
        extend.type == arm64::Extend::Type::kSxth) {
      is_ext_16_bit = true;
    }

    // ensure 32 bit op
    operand_width = 32;
    eor_instr = eor_shifted_reg(operand_width, X0, reg(rn), reg(rm),
                                arm64::Shift::Type::kNone, 0);
  }

  WriteCode(module, &eor_instr, sizeof(eor_instr));

  if (is_ext_16_bit) {
    // and x0, x0, 0xffff
    uint32_t and_instr = 0x92403c00;
    WriteCode(module, &and_instr, sizeof(and_instr));
  }

  // count leading zeros depending on operand width
  if (operand_width == 64) {
    uint32_t clz_x0_instr = 0xdac01000;
    WriteCode(module, &clz_x0_instr, sizeof(clz_x0_instr));
  } else {
    uint32_t clz_w0_instr = 0x5ac01000;
    WriteCode(module, &clz_w0_instr, sizeof(clz_w0_instr));
  }

  arm64asm->EmitLoadLit(module, X1, operand_width, false, match_width);
  size_t match_width_offset = module->instrumented_code_allocated - 8;

  uint32_t cmp_x0_x1_instr = cmp(X0, X1);
  WriteCode(module, &cmp_x0_x1_instr, sizeof(cmp_x0_x1_instr));

  size_t jmp_offset = module->instrumented_code_allocated;
  uint32_t b_lt = b_cond("lt", 0);
  WriteCode(module, &b_lt, sizeof(b_lt));

  size_t bit_address =
      (size_t)data->coverage_buffer_remote + data->coverage_buffer_next;
  arm64asm->EmitLoadLit(module, X1, 64, false, bit_address);
  size_t mov_address = GetCurrentInstrumentedAddress(module) - 8;

  uint32_t str_match = str(64, X0, X1, 0);
  WriteCode(module, &str_match, sizeof(str_match));

  arm64asm->FixOffset(module, jmp_offset, module->instrumented_code_allocated);

  arm64asm->ReadRegStack(module, X0, 0);
  arm64asm->ReadRegStack(module, X1, 8);
  arm64asm->OffsetStack(module, 16);
  if (sp_offset) {
    arm64asm->OffsetStack(module, sp_offset);
  }

  CmpCoverageRecord *cmp_record = new CmpCoverageRecord();
  cmp_record->ignored = false;
  cmp_record->width = operand_width;
  cmp_record->match_width = match_width;
  cmp_record->match_width_offset = match_width_offset;
  cmp_record->instrumentation_offset = instrumentation_start_offset;
  cmp_record->bb_address = bb_address;
  cmp_record->bb_offset = bb_offset;
  cmp_record->cmp_offset = cmp_offset;
  cmp_record->instrumentation_size =
      module->instrumented_code_allocated - instrumentation_start_offset;
  data->coverage_to_cmp[GetCmpCode(bb_offset, cmp_offset, 0)] = cmp_record;
  data->buf_to_cmp[data->coverage_buffer_next] = cmp_record;
  data->coverage_buffer_next++;

  // return INST_NOTHANDLED which causes
  // the original instruction to be repeated
  return INST_NOTHANDLED;
}
