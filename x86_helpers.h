#pragma once

extern "C" {
#include "xed/xed-interface.h"
}

xed_reg_enum_t GetFullSizeRegister(xed_reg_enum_t r, int child_ptr_size);
xed_reg_enum_t GetUnusedRegister(xed_reg_enum_t used_register, int operand_width);
xed_reg_enum_t Get8BitRegister(xed_reg_enum_t r);

uint32_t Push(xed_state_t *dstate, xed_reg_enum_t r, unsigned char *encoded);
uint32_t Pop(xed_state_t *dstate, xed_reg_enum_t r, unsigned char *encoded);

uint32_t Mov(xed_state_t *dstate, uint32_t operand_width,
             xed_reg_enum_t base_reg, int32_t displacement,
             xed_reg_enum_t r2, unsigned char *encoded);

uint32_t Lzcnt(xed_state_t *dstate, uint32_t operand_width,
               xed_reg_enum_t dest_reg, xed_reg_enum_t src_reg,
               unsigned char *encoded);

uint32_t CmpImm8(xed_state_t *dstate, uint32_t operand_width,
                 xed_reg_enum_t dest_reg, uint64_t imm,
                 unsigned char *encoded);

void CopyOperandFromInstruction(xed_decoded_inst_t *src,
                                xed_encoder_request_t *dest,
                                xed_operand_enum_t src_operand_name,
                                xed_operand_enum_t dest_operand_name,
                                int dest_operand_index,
                                size_t stack_offset);

uint32_t GetInstructionLength(xed_encoder_request_t *inst);

void FixRipDisplacement(xed_encoder_request_t *inst,
                        size_t mem_address,
                        size_t fixed_instruction_address);
