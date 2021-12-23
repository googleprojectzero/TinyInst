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

#include "litecov.h"

#include "common.h"
#include "instruction.h"

#include "arch/x86/x86_assembler.h"
#include "arch/x86/x86_helpers.h"

// mov byte ptr [rip+offset], 1
// note: does not clobber flags
static unsigned char MOV_ADDR_1[] = {0xC6, 0x05, 0xAA, 0xAA, 0xAA, 0x0A, 0x01};

// same size as instrumentation
// used for clearing the instrumentation
// if the user wants to ignore specific pieces of coverage
// 7-byte nop taken from
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/nops.h
// thanks @tehjh
static unsigned char NOP7[] = {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00};
static unsigned char NOP5[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};

void LiteCov::NopCovInstructions(ModuleInfo *module, size_t code_offset) {
  WriteCodeAtOffset(module, code_offset, NOP7, sizeof(NOP7));
  // need to commit since this isn't a part of normal instrumentation process
  CommitCode(module, code_offset, sizeof(NOP7));
}

void LiteCov::NopCmpCovInstructions(ModuleInfo *module,
                                    CmpCoverageRecord &cmp_record,
                                    int matched_width) {
  unsigned char JMP[] = {0xe9, 0x00, 0x00, 0x00, 0x00};

  if (matched_width >= cmp_record.width - 8) {
    // ignore everything
    WriteCodeAtOffset(module, cmp_record.instrumentation_offset, JMP,
                               sizeof(JMP));
    *(int32_t *)(module->instrumented_code_local +
                 cmp_record.instrumentation_offset + sizeof(JMP) - 4) =
        (int32_t)(cmp_record.instrumentation_size - sizeof(JMP));
    CommitCode(module, cmp_record.instrumentation_offset, sizeof(JMP));
    cmp_record.ignored = true;
    return;
  }

  if (matched_width >= cmp_record.match_width) {
    cmp_record.match_width = matched_width + 8;
    char new_offset_data = static_cast<char>(cmp_record.match_width);
    WriteCodeAtOffset(module, cmp_record.match_width_offset,
                               &new_offset_data, 1);
    CommitCode(module, cmp_record.instrumentation_offset, 1);
  }
}

void LiteCov::EmitCoverageInstrumentation(ModuleInfo *module,
                                          size_t bit_address,
                                          size_t mov_address) {
  //////////////////////////////////////////////////
  // mov [coverage_buffer + coverage_buffer_next], 1
  //////////////////////////////////////////////////
  WriteCode(module, MOV_ADDR_1, sizeof(MOV_ADDR_1));
  mov_address += sizeof(MOV_ADDR_1);

  // fix the mov address/displacement
  if (child_ptr_size == 8) {
    *(int32_t *)(module->instrumented_code_local +
                 module->instrumented_code_allocated - 5) =
        (int32_t)(bit_address - mov_address);
  } else {
    *(uint32_t *)(module->instrumented_code_local +
                  module->instrumented_code_allocated - 5) =
        (uint32_t)bit_address;
  }
}

bool LiteCov::ShouldInstrumentSub(ModuleInfo *module, Instruction &cmp_instr,
                                     size_t instruction_address) {
  // look after the sub instruction
  // and check if the flags set in it
  // are used for a conditional jump or move
  xed_decoded_inst_t *cmp_xedd = &cmp_instr.xedd;

  instruction_address += xed_decoded_inst_get_length(cmp_xedd);

  AddressRange *range = GetRegion(module, instruction_address);
  if (!range) {
    return false;
  }

  uint32_t range_offset = (uint32_t)(instruction_address - (size_t)range->from);
  size_t code_size = (uint32_t)((size_t)range->to - instruction_address);
  char *code_ptr = range->data + range_offset;

  size_t offset = 0, last_offset = 0;

  xed_decoded_inst_t xedd;
  xed_error_enum_t xed_error;

  xed_state_t dstate;
  dstate.mmode = (xed_machine_mode_enum_t)child_ptr_size == 8
                     ? XED_MACHINE_MODE_LONG_64
                     : XED_MACHINE_MODE_LEGACY_32;
  dstate.stack_addr_width = (xed_address_width_enum_t)child_ptr_size;

  xed_category_enum_t category;

  while (true) {
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_error = xed_decode(&xedd, (const unsigned char *)(code_ptr + offset),
                           (unsigned int)(code_size - offset));

    if (xed_error != XED_ERROR_NONE) return false;

    size_t instruction_length = xed_decoded_inst_get_length(&xedd);

    category = xed_decoded_inst_get_category(&xedd);

    switch (category) {
      case XED_CATEGORY_CMOV:
      case XED_CATEGORY_COND_BR:
        return true;

      case XED_CATEGORY_CALL:
      case XED_CATEGORY_RET:
      case XED_CATEGORY_UNCOND_BR:
        return false;

      default:
        if (xed_decoded_inst_uses_rflags(&xedd)) return false;
        break;
    }

    last_offset = offset;
    offset += instruction_length;
  }
}

InstructionResult LiteCov::InstrumentInstruction(ModuleInfo *module,
                                                 Instruction &inst,
                                                 size_t bb_address,
                                                 size_t instruction_address) {
  if (!compare_coverage) {
    return INST_NOTHANDLED;
  }

  // jmp offset
  unsigned char JB[] = {0x0F, 0x82, 0x00, 0x00, 0x00, 0x00};

  xed_iclass_enum_t iclass;
  iclass = xed_decoded_inst_get_iclass(&inst.xedd);

  if ((iclass != XED_ICLASS_CMP) && (iclass != XED_ICLASS_SUB)) {
    return INST_NOTHANDLED;
  }

  int operand_width = xed_decoded_inst_get_operand_width(&inst.xedd);

  // printf("Cmp instruction at %llx, width: %d\n", instruction_address,
  // operand_width);

  if (operand_width <= 8) {
    return INST_NOTHANDLED;
  }

  // copy so we could modify it
  xed_decoded_inst_t cmp_xedd = inst.xedd;
  xed_decoded_inst_t *xedd = &cmp_xedd;

  xed_state_t dstate;
  dstate.mmode = (xed_machine_mode_enum_t)child_ptr_size == 8
                     ? XED_MACHINE_MODE_LONG_64
                     : XED_MACHINE_MODE_LEGACY_32;
  dstate.stack_addr_width = (xed_address_width_enum_t)child_ptr_size;

  xed_error_enum_t xed_error;
  uint32_t olen;
  unsigned char encoded[15];

  // if the 1st operand is NOT a memory operand
  // then we can replace the cmp with xor
  // and restore the operand
  // e.g. cmp eax, foo
  // to:
  // push eax
  // xor eax, foo
  // LZCNT rax, rax
  // cmp rax, #numbits
  // JA end
  // write to coverage buffer
  // end:
  // pop eax
  // original instruction
  // if it is a memory operand, then we need to
  // allocate a register and do
  // push register
  // mov register, memory
  // same as above from xor

  const xed_inst_t *xi = xed_decoded_inst_inst(xedd);

  const xed_operand_t *op1 = xed_inst_operand(xi, 0);
  xed_operand_enum_t operand1_name = xed_operand_name(op1);
  xed_reg_enum_t operand1_register = XED_REG_INVALID;
  if (operand1_name == XED_OPERAND_REG0) {
    operand1_register = xed_decoded_inst_get_reg(xedd, operand1_name);
  }

  const xed_operand_t *op2 = xed_inst_operand(xi, 1);
  xed_operand_enum_t operand2_name = xed_operand_name(op2);
  xed_reg_enum_t operand2_register = XED_REG_INVALID;
  if ((operand2_name == XED_OPERAND_REG0) ||
      (operand2_name == XED_OPERAND_REG1)) {
    operand2_register = xed_decoded_inst_get_reg(xedd, operand2_name);
  }

  // don't do instrument comparisons with RSP
  if ((operand1_register == XED_REG_RSP) ||
      (operand1_register == XED_REG_ESP) || (operand1_register == XED_REG_SP)) {
    return INST_NOTHANDLED;
  }
  if ((operand2_register == XED_REG_RSP) ||
      (operand2_register == XED_REG_ESP) || (operand2_register == XED_REG_SP)) {
    return INST_NOTHANDLED;
  }

  if (iclass == XED_ICLASS_SUB) {
    Instruction instr;
    instr.xedd = cmp_xedd;
    if (!ShouldInstrumentSub(module, instr, instruction_address)) {
      // printf("Not instrumenting SUB at %llx\n", instruction_address);
      return INST_NOTHANDLED;
    } else {
      // printf("Founf a SUB instrumentation candidate at %llx\n",
      // instruction_address);
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

  bool mov_needed = false;
  xed_reg_enum_t destination_reg;

  // check if the first param is a register
  // (if so, reuse it)
  // otherwise get a temporary register
  if (operand1_name == XED_OPERAND_REG0) {
    destination_reg = operand1_register;
  } else if (operand1_name == XED_OPERAND_MEM0) {
    mov_needed = true;
    destination_reg = GetUnusedRegister(operand2_register, operand_width);
  } else {
    FATAL("Unknown CMP first argument at %zx", instruction_address);
  }

  size_t mem_address = 0;
  bool rip_relative = assembler_->IsRipRelative(
      module, inst, instruction_address, &mem_address);

  size_t rsp_displacement = 0;
  bool rsp_relative = IsRspRelative(xedd, &rsp_displacement);

  // start with NOP that's going to be replaced with
  // JMP when the instrumentation is removed
  WriteCode(module, NOP5, sizeof(NOP5));

  if (sp_offset) {
    assembler_->OffsetStack(module, -sp_offset);
  }

  size_t stack_offset = sp_offset;

  olen = Push(&dstate, destination_reg, encoded, sizeof(encoded));
  WriteCode(module, encoded, olen);

  stack_offset += child_ptr_size;

  // todo don't do this for comparisons with rsp

  if (mov_needed) {
    // mov destination_reg, 1st_param_of_cmp
    xed_encoder_request_t mov;
    xed_encoder_request_zero_set_mode(&mov, &dstate);
    xed_encoder_request_set_iclass(&mov, XED_ICLASS_MOV);

    xed_encoder_request_set_effective_operand_width(&mov, operand_width);
    xed_encoder_request_set_effective_address_size(&mov,
                                                   dstate.stack_addr_width * 8);

    xed_encoder_request_set_reg(&mov, XED_OPERAND_REG0, destination_reg);
    xed_encoder_request_set_operand_order(&mov, 0, XED_OPERAND_REG0);

    CopyOperandFromInstruction(xedd, &mov, operand1_name, operand1_name, 1,
                               stack_offset);

    if (rip_relative) {
      FixRipDisplacement(&mov, mem_address,
                         GetCurrentInstrumentedAddress(module));
    }

    xed_error = xed_encode(&mov, encoded, sizeof(encoded), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    WriteCode(module, encoded, olen);

    // xor destination_reg, 2nd_param_of_cmp
    xed_encoder_request_t xor_inst;
    xed_encoder_request_zero_set_mode(&xor_inst, &dstate);
    xed_encoder_request_set_iclass(&xor_inst, XED_ICLASS_XOR);

    xed_encoder_request_set_effective_operand_width(&xor_inst, operand_width);
    xed_encoder_request_set_effective_address_size(&xor_inst,
                                                   dstate.stack_addr_width * 8);

    xed_encoder_request_set_reg(&xor_inst, XED_OPERAND_REG0, destination_reg);
    xed_encoder_request_set_operand_order(&xor_inst, 0, XED_OPERAND_REG0);

    xed_operand_enum_t dest_operand_name = operand2_name;
    if (dest_operand_name == XED_OPERAND_REG0) {
      // already taken above
      dest_operand_name = XED_OPERAND_REG1;
    }

    CopyOperandFromInstruction(xedd, &xor_inst, operand2_name,
                               dest_operand_name, 1, stack_offset);

    // no need to fix rip displacement here
    // as we know this won't reference memory

    xed_error = xed_encode(&xor_inst, encoded, sizeof(encoded), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    WriteCode(module, encoded, olen);

  } else {
    // just change cmp to xor
    xed_encoder_request_init_from_decode(xedd);
    xed_encoder_request_set_iclass(xedd, XED_ICLASS_XOR);

    if (rip_relative) {
      FixRipDisplacement(xedd, mem_address,
                         GetCurrentInstrumentedAddress(module));
    }

    if (rsp_relative) {
      xed_encoder_request_set_memory_displacement(xedd, rsp_displacement + stack_offset, 4);
    }

    xed_error = xed_encode(xedd, encoded, sizeof(encoded), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    WriteCode(module, encoded, olen);
  }

  olen = Lzcnt(&dstate, operand_width, destination_reg, destination_reg,
               encoded, sizeof(encoded));
  WriteCode(module, encoded, olen);

  olen = CmpImm8(&dstate, operand_width, destination_reg, match_width, encoded,
                 sizeof(encoded));
  // check hat the offset is at the end
  if (*((char *)encoded + olen - 1) != match_width) {
    FATAL("Unexpected instruction encoding");
  }
  WriteCode(module, encoded, olen);

  size_t match_width_offset = module->instrumented_code_allocated - 1;

  WriteCode(module, JB, sizeof(JB));
  size_t jmp_offset = module->instrumented_code_allocated;

  xed_reg_enum_t rip = XED_REG_INVALID;
  if (child_ptr_size == 8) rip = XED_REG_RIP;
  olen = Mov(&dstate, 8, rip, 0x12345678, Get8BitRegister(destination_reg),
             encoded, sizeof(encoded));
  // check hat the offset is at the end
  if (*((int32_t *)((char *)encoded + olen - 4)) != 0x12345678) {
    FATAL("Unexpected instruction encoding");
  }
  WriteCode(module, encoded, olen);

  size_t bit_address =
      (size_t)data->coverage_buffer_remote + data->coverage_buffer_next;
  size_t mov_address = GetCurrentInstrumentedAddress(module);

  // fix the mov address/displacement
  if (child_ptr_size == 8) {
    *(int32_t *)(module->instrumented_code_local +
                 module->instrumented_code_allocated - 4) =
        (int32_t)(bit_address - mov_address);
  } else {
    *(uint32_t *)(module->instrumented_code_local +
                  module->instrumented_code_allocated - 4) =
        (uint32_t)bit_address;
  }

  // fix the jump offset
  *(int32_t *)(module->instrumented_code_local + jmp_offset - 4) =
      (int32_t)(module->instrumented_code_allocated - jmp_offset);

  olen = Pop(&dstate, destination_reg, encoded, sizeof(encoded));
  WriteCode(module, encoded, olen);

  if (sp_offset) {
    assembler_->OffsetStack(module, sp_offset);
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
