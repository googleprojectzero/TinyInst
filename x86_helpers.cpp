#include "common.h"
#include "x86_helpers.h"

xed_reg_enum_t GetUnusedRegister(xed_reg_enum_t used_register, int operand_width) {
  switch (operand_width) {
  case 16:
    if (used_register == XED_REG_AX) return XED_REG_CX;
    return XED_REG_AX;
  case 32:
    if (used_register == XED_REG_EAX) return XED_REG_ECX;
    return XED_REG_EAX;
  case 64:
    if (used_register == XED_REG_RAX) return XED_REG_RCX;
    return XED_REG_RAX;
  default:
    FATAL("Unexpected operand width");
  }
}

xed_reg_enum_t GetFullSizeRegister(xed_reg_enum_t r, int child_ptr_size) {
  if (child_ptr_size == 8) {
    return xed_get_largest_enclosing_register(r);
  } else {
    return xed_get_largest_enclosing_register32(r);
  }
}

xed_reg_enum_t Get8BitRegister(xed_reg_enum_t r) {
  switch (r) {
  case XED_REG_AX:
  case XED_REG_EAX:
  case XED_REG_RAX:
    return XED_REG_AL;

  case XED_REG_CX:
  case XED_REG_ECX:
  case XED_REG_RCX:
    return XED_REG_CL;

  case XED_REG_DX:
  case XED_REG_EDX:
  case XED_REG_RDX:
    return XED_REG_DL;

  case XED_REG_BX:
  case XED_REG_EBX:
  case XED_REG_RBX:
    return XED_REG_BL;

  case XED_REG_SP:
  case XED_REG_ESP:
  case XED_REG_RSP:
    return XED_REG_SPL;

  case XED_REG_BP:
  case XED_REG_EBP:
  case XED_REG_RBP:
    return XED_REG_BPL;

  case XED_REG_SI:
  case XED_REG_ESI:
  case XED_REG_RSI:
    return XED_REG_SIL;

  case XED_REG_DI:
  case XED_REG_EDI:
  case XED_REG_RDI:
    return XED_REG_DIL;

  case XED_REG_R8W:
  case XED_REG_R8D:
  case XED_REG_R8:
    return XED_REG_R8B;

  case XED_REG_R9W:
  case XED_REG_R9D:
  case XED_REG_R9:
    return XED_REG_R9B;

  case XED_REG_R10W:
  case XED_REG_R10D:
  case XED_REG_R10:
    return XED_REG_R10B;

  case XED_REG_R11W:
  case XED_REG_R11D:
  case XED_REG_R11:
    return XED_REG_R11B;

  case XED_REG_R12W:
  case XED_REG_R12D:
  case XED_REG_R12:
    return XED_REG_R12B;

  case XED_REG_R13W:
  case XED_REG_R13D:
  case XED_REG_R13:
    return XED_REG_R13B;

  case XED_REG_R14W:
  case XED_REG_R14D:
  case XED_REG_R14:
    return XED_REG_R14B;

  case XED_REG_R15W:
  case XED_REG_R15D:
  case XED_REG_R15:
    return XED_REG_R15B;

  default:
    FATAL("Unknown register");
  }
}


uint32_t Push(xed_state_t *dstate, xed_reg_enum_t r, unsigned char *encoded) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  // push destination register
  xed_encoder_request_t push;
  xed_encoder_request_zero_set_mode(&push, dstate);
  xed_encoder_request_set_iclass(&push, XED_ICLASS_PUSH);
  
  xed_encoder_request_set_effective_operand_width(&push, dstate->stack_addr_width * 8);
  xed_encoder_request_set_effective_address_size(&push, dstate->stack_addr_width * 8);

  xed_encoder_request_set_reg(&push, XED_OPERAND_REG0, GetFullSizeRegister(r, dstate->stack_addr_width));
  xed_encoder_request_set_operand_order(&push, 0, XED_OPERAND_REG0);

  xed_error = xed_encode(&push, encoded, sizeof(encoded), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}

uint32_t Pop(xed_state_t *dstate, xed_reg_enum_t r, unsigned char *encoded) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  // push destination register
  xed_encoder_request_t pop;
  xed_encoder_request_zero_set_mode(&pop, dstate);
  xed_encoder_request_set_iclass(&pop, XED_ICLASS_POP);

  xed_encoder_request_set_effective_operand_width(&pop, dstate->stack_addr_width * 8);
  xed_encoder_request_set_effective_address_size(&pop, dstate->stack_addr_width * 8);

  xed_encoder_request_set_reg(&pop, XED_OPERAND_REG0, GetFullSizeRegister(r, dstate->stack_addr_width));
  xed_encoder_request_set_operand_order(&pop, 0, XED_OPERAND_REG0);

  xed_error = xed_encode(&pop, encoded, sizeof(encoded), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}


void CopyOperandFromInstruction(xed_decoded_inst_t *src,
                                xed_encoder_request_t *dest,
                                xed_operand_enum_t src_operand_name,
                                xed_operand_enum_t dest_operand_name,
                                int dest_operand_index,
                                size_t stack_offset)
{
  if ((src_operand_name >= XED_OPERAND_REG0) && (src_operand_name <= XED_OPERAND_REG8) &&
      (dest_operand_name >= XED_OPERAND_REG0) && (dest_operand_name <= XED_OPERAND_REG8))
  {
    xed_reg_enum_t r = xed_decoded_inst_get_reg(src, src_operand_name);
    xed_encoder_request_set_reg(dest, dest_operand_name, r);
  } else if (src_operand_name == XED_OPERAND_MEM0 && dest_operand_name == XED_OPERAND_MEM0) {
    xed_encoder_request_set_mem0(dest);
    xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(src, 0);
    xed_encoder_request_set_base0(dest, base_reg);
    xed_encoder_request_set_seg0(dest, xed_decoded_inst_get_seg_reg(src, 0));
    xed_encoder_request_set_index(dest, xed_decoded_inst_get_index_reg(src, 0));
    xed_encoder_request_set_scale(dest, xed_decoded_inst_get_scale(src, 0));
    // in case where base is rsp, disp needs fixing
    if ((base_reg == XED_REG_SP) || (base_reg == XED_REG_ESP) || (base_reg == XED_REG_RSP)) {
      int64_t disp = xed_decoded_inst_get_memory_displacement(src, 0) + stack_offset;
      // always use disp width 4 in this case
      xed_encoder_request_set_memory_displacement(dest, disp, 4);
    } else {
      xed_encoder_request_set_memory_displacement(dest,
        xed_decoded_inst_get_memory_displacement(src, 0),
        xed_decoded_inst_get_memory_displacement_width(src, 0));
    }
    // int length = xed_decoded_inst_get_memory_operand_length(xedd, 0);
    xed_encoder_request_set_memory_operand_length(dest,
      xed_decoded_inst_get_memory_operand_length(src, 0));
  } else if (src_operand_name == XED_OPERAND_IMM0 && dest_operand_name == XED_OPERAND_IMM0) {
    uint64_t imm = xed_decoded_inst_get_unsigned_immediate(src);
    uint32_t width = xed_decoded_inst_get_immediate_width(src);
    xed_encoder_request_set_uimm0(dest, imm, width);
  } else if (src_operand_name == XED_OPERAND_IMM0SIGNED && dest_operand_name == XED_OPERAND_IMM0SIGNED) {
    int32_t imm = xed_decoded_inst_get_signed_immediate(src);
    uint32_t width = xed_decoded_inst_get_immediate_width(src);
    xed_encoder_request_set_simm(dest, imm, width);
  } else {
    FATAL("Unsupported param");
  }
  xed_encoder_request_set_operand_order(dest, dest_operand_index, dest_operand_name);
}


uint32_t Mov(xed_state_t *dstate, uint32_t operand_width, xed_reg_enum_t base_reg, int32_t displacement, xed_reg_enum_t r2, unsigned char *encoded) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  xed_encoder_request_t mov;
  xed_encoder_request_zero_set_mode(&mov, dstate);
  xed_encoder_request_set_iclass(&mov, XED_ICLASS_MOV);

  xed_encoder_request_set_effective_operand_width(&mov, operand_width);
  xed_encoder_request_set_effective_address_size(&mov, dstate->stack_addr_width * 8);

  xed_encoder_request_set_mem0(&mov);
  xed_encoder_request_set_base0(&mov, base_reg);
  xed_encoder_request_set_memory_displacement(&mov, displacement, 4);
  // int length = xed_decoded_inst_get_memory_operand_length(xedd, 0);
  xed_encoder_request_set_memory_operand_length(&mov, operand_width / 8);
  xed_encoder_request_set_operand_order(&mov, 0, XED_OPERAND_MEM0);

  xed_encoder_request_set_reg(&mov, XED_OPERAND_REG0, r2);
  xed_encoder_request_set_operand_order(&mov, 1, XED_OPERAND_REG0);

  xed_error = xed_encode(&mov, encoded, sizeof(encoded), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}

uint32_t Lzcnt(xed_state_t *dstate, uint32_t operand_width, xed_reg_enum_t dest_reg, xed_reg_enum_t src_reg, unsigned char *encoded) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  xed_encoder_request_t lzcnt;
  xed_encoder_request_zero_set_mode(&lzcnt, dstate);
  xed_encoder_request_set_iclass(&lzcnt, XED_ICLASS_LZCNT);

  xed_encoder_request_set_effective_operand_width(&lzcnt, operand_width);
  //xed_encoder_request_set_effective_address_size(&lzcnt, operand_width);

  xed_encoder_request_set_reg(&lzcnt, XED_OPERAND_REG0, dest_reg);
  xed_encoder_request_set_operand_order(&lzcnt, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_reg(&lzcnt, XED_OPERAND_REG1, src_reg);
  xed_encoder_request_set_operand_order(&lzcnt, 1, XED_OPERAND_REG1);

  xed_error = xed_encode(&lzcnt, encoded, sizeof(encoded), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}

uint32_t CmpImm8(xed_state_t *dstate, uint32_t operand_width, xed_reg_enum_t dest_reg, uint64_t imm, unsigned char *encoded) {
  uint32_t olen;
  xed_error_enum_t xed_error;

  xed_encoder_request_t lzcnt;
  xed_encoder_request_zero_set_mode(&lzcnt, dstate);
  xed_encoder_request_set_iclass(&lzcnt, XED_ICLASS_CMP);

  xed_encoder_request_set_effective_operand_width(&lzcnt, operand_width);
  // xed_encoder_request_set_effective_address_size(&lzcnt, operand_width);

  xed_encoder_request_set_reg(&lzcnt, XED_OPERAND_REG0, dest_reg);
  xed_encoder_request_set_operand_order(&lzcnt, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_uimm0_bits(&lzcnt, imm, 8);
  xed_encoder_request_set_operand_order(&lzcnt, 1, XED_OPERAND_IMM0);

  xed_error = xed_encode(&lzcnt, encoded, sizeof(encoded), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;
}

uint32_t GetInstructionLength(xed_encoder_request_t *inst) {
  unsigned int olen;
  unsigned char tmp[15];
  xed_error_enum_t xed_error;
  
  xed_error = xed_encode(inst, tmp, sizeof(tmp), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  return olen;

}

void FixRipDisplacement(xed_encoder_request_t *inst, size_t mem_address, size_t fixed_instruction_address) {
  // fake displacement, just to get length
  xed_encoder_request_set_memory_displacement(inst, 0x7777777, 4);
  uint32_t inst_length = GetInstructionLength(inst);
  
  size_t instruction_end_addr = fixed_instruction_address + inst_length;
  int64_t fixed_disp = (int64_t)(mem_address) - (int64_t)(instruction_end_addr);
  if (llabs(fixed_disp) > 0x7FFFFFFF) FATAL("Offset larger than 2G");
  
  xed_encoder_request_set_memory_displacement(inst, fixed_disp, 4);
}
