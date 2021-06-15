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

#include "arch/x86/x86_assembler.h"

// int3
unsigned char BREAKPOINT[] = {0xCC};

// nop
unsigned char NOP[] = {0x90};

// jmp offset
unsigned char JMP[] = {0xe9, 0x00, 0x00, 0x00, 0x00};

// call offset
unsigned char CALL[] = {0xe8, 0x00, 0x00, 0x00, 0x00};

// warning, this is rip-relative on x64 but absolute on 32-bit
// jmp [offset]
unsigned char JMP_MEM[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};

// lea rsp, [rsp + disp]
unsigned char LEARSP[] = {0x48, 0x8d, 0xa4, 0x24, 0x00, 0x00, 0x00, 0x00};
// lea esp, [esp + disp]
unsigned char LEAESP[] = {0x8D, 0xA4, 0x24, 0x00, 0x00, 0x00, 0x00};

// push flags
// push rax
// push rbx
unsigned char PUSH_FAB[] = {0x9c, 0x50, 0x53};

// push flags
// push rax
unsigned char PUSH_FA[] = {0x9c, 0x50};

// push flags
unsigned char PUSH_F[] = {0x9c};

// push rax
unsigned char PUSH_A[] = {0x50};

// push rbx
unsigned char PUSH_B[] = {0x53};

// pop rbx
// pop rax
// pop flags
unsigned char POP_BAF[] = {0x5B, 0x58, 0x9d};

// pop rax
// pop flags
unsigned char POP_AF[] = {0x58, 0x9d};

// pop rax
unsigned char POP_A[] = {0x58};

// and rbx, constant
unsigned char AND_RBX[] = {0x48, 0x81, 0xe3, 0x00, 0x00, 0x00, 0x00};
// and ebx, constant
unsigned char AND_EBX[] = {0x81, 0xe3, 0x00, 0x00, 0x00, 0x00};

// mov rbx, rax
unsigned char MOV_RBXRAX[] = {0x48, 0x89, 0xC3};
// mov ebx, eax
unsigned char MOV_EBXEAX[] = {0x89, 0xC3};

// add rbx, [offset]
unsigned char ADD_RBXRIPRELATIVE[] = {0x48, 0x03, 0x1D, 0x00, 0x00, 0x00, 0x00};
// add ebx, [offset]
unsigned char ADD_EBXRIPRELATIVE[] = {0x03, 0x1D, 0x00, 0x00, 0x00, 0x00};

// jmp [rbx]
unsigned char JMP_B[] = {0xFF, 0x23};

// cmp rax, [offset]
unsigned char CMP_RAX[] = {0x48, 0x3B, 0x05, 0x00, 0x00, 0x00, 0x00};
// cmp eax, [offset]
unsigned char CMP_EAX[] = {0x3B, 0x05, 0x00, 0x00, 0x00, 0x00};

// je offset
unsigned char JE[] = {0x0F, 0x84, 0x00, 0x00, 0x00, 0x00};

// mov [rsp], imm
unsigned char WRITE_SP_IMM[] = {0xC7, 0x04, 0x24, 0xAA, 0xAA, 0xAA, 0xAA};
// mov [rsp+4], imm
unsigned char WRITE_SP_4_IMM[] = {0xC7, 0x44, 0x24, 0x04,
                                  0xAA, 0xAA, 0xAA, 0xAA};

// mov rax, [rsp + offset]
unsigned char MOV_RAX_RSPMEM[] = {0x48, 0x8B, 0x84, 0x24,
                                  0xAA, 0xAA, 0xAA, 0x0A};
// mov eax, [esp + offset]
unsigned char MOV_EAX_ESPMEM[] = {0x8B, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A};

// mov [rsp + offset], rax
unsigned char MOV_RSPMEM_RAX[] = {0x48, 0x89, 0x84, 0x24,
                                  0xAA, 0xAA, 0xAA, 0x0A};
// mov [esp + offset], eax
unsigned char MOV_ESPMEM_EAX[] = {0x89, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A};

// mov byte ptr [0], 0
unsigned char CRASH_64[] = {0xC6, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char CRASH_32[] = {0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00};

// fixes the memory displacement of the current instruction
// (assumes it is in the 4 last bytes)
inline void X86Assembler::FixDisp4(ModuleInfo *module, int32_t disp) {
  *(int32_t *)(module->instrumented_code_local +
               module->instrumented_code_allocated - 4) = disp;
}

void X86Assembler::Breakpoint(ModuleInfo *module) {
  tinyinst_.WriteCode(module, &BREAKPOINT, sizeof(BREAKPOINT));
}

void X86Assembler::Nop(ModuleInfo *module) {
  tinyinst_.WriteCode(module, &NOP, sizeof(NOP));
}

void X86Assembler::JmpAddress(ModuleInfo *module, size_t address) {
  // just insert a jump to address
  tinyinst_.WriteCode(module, JMP_MEM, sizeof(JMP_MEM));
  if (tinyinst_.child_ptr_size == 4) {
    FixDisp4(module, tinyinst_.GetCurrentInstrumentedAddress(module));
  }
  tinyinst_.WritePointer(module, (size_t)address);
}

// checks if the instruction uses RIP-relative addressing,
// e.g. mov rax, [rip+displacement]; call [rip+displacement]
// and, if so, returns the memory address being referenced
bool X86Assembler::IsRipRelative(ModuleInfo *module,
                                 Instruction& inst,
                                 size_t instruction_address,
                                 size_t *mem_address) {
  bool rip_relative = false;
  int64_t disp;

  uint32_t memops = xed_decoded_inst_number_of_memory_operands(&inst.xedd);

  for (uint32_t i = 0; i < memops; i++) {
    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(&inst.xedd, i);
    switch (base) {
      case XED_REG_RIP:
      case XED_REG_EIP:
      case XED_REG_IP:
        rip_relative = true;
        disp = xed_decoded_inst_get_memory_displacement(&inst.xedd, i);
        break;
      default:
        break;
    }
  }

  if (!rip_relative) return false;

  size_t instruction_size = xed_decoded_inst_get_length(&inst.xedd);
  *mem_address = (size_t)(instruction_address + instruction_size + disp);

  return rip_relative;
}

// adds/subtracts a given offset to the stack pointer
// this is done using LEA instruction rather than ADD/SUB
// to avoid clobbering the flags
void X86Assembler::OffsetStack(ModuleInfo *module, int32_t offset) {
  // lea rsp, [rsp + offset]
  if (tinyinst_.child_ptr_size == 8) {
    tinyinst_.WriteCode(module, LEARSP, sizeof(LEARSP));
  } else {
    tinyinst_.WriteCode(module, LEAESP, sizeof(LEAESP));
  }

  FixDisp4(module, offset);
}

// mov rax, [rsp + offset]
void X86Assembler::ReadStack(ModuleInfo *module, int32_t offset) {
  if (tinyinst_.child_ptr_size == 8) {
    tinyinst_.WriteCode(module, MOV_RAX_RSPMEM, sizeof(MOV_RAX_RSPMEM));
  } else {
    tinyinst_.WriteCode(module, MOV_EAX_ESPMEM, sizeof(MOV_EAX_ESPMEM));
  }
  FixDisp4(module, offset);
}

// mov [rsp + offset], rax
void X86Assembler::WriteStack(ModuleInfo *module, int32_t offset) {
  if (tinyinst_.child_ptr_size == 8) {
    tinyinst_.WriteCode(module, MOV_RSPMEM_RAX, sizeof(MOV_RSPMEM_RAX));
  } else {
    tinyinst_.WriteCode(module, MOV_ESPMEM_EAX, sizeof(MOV_ESPMEM_EAX));
  }
  FixDisp4(module, offset);
}

// adds another observed original_target -> actual_target pair
// to the golbal jumptable at the appropriate location
void X86Assembler::TranslateJmp(ModuleInfo *module,
                                ModuleInfo *target_module,
                                size_t original_target,
                                size_t edge_start_address,
                                bool global_indirect,
                                size_t previous_offset) {

  // cmp RAX, [original_target]
  if (tinyinst_.child_ptr_size == 8) {
    tinyinst_.WriteCode(module, CMP_RAX, sizeof(CMP_RAX));
  } else {
    tinyinst_.WriteCode(module, CMP_EAX, sizeof(CMP_EAX));
  }
  size_t cmp_offset = module->instrumented_code_allocated;

  // je label
  tinyinst_.WriteCode(module, JE, sizeof(JE));
  FixDisp4(module, sizeof(JMP));

  // jmp previous_list_head
  tinyinst_.WriteCode(module, JMP, sizeof(JMP));
  FixDisp4(module, (int32_t)((int64_t)previous_offset -
                             (int64_t)module->instrumented_code_allocated));

  // (maybe) pop RBX
  // pop RAX
  // pop flags
  if (global_indirect) {
    tinyinst_.WriteCode(module, POP_BAF, sizeof(POP_BAF));
  } else {
    tinyinst_.WriteCode(module, POP_AF, sizeof(POP_AF));
  }

  if (tinyinst_.sp_offset) {
    OffsetStack(module, tinyinst_.sp_offset);
  }

  // consider indirect call/jump an edge and insert appropriate instrumentation
  tinyinst_.InstrumentEdge(module, target_module, edge_start_address,
                           original_target);

  // jmp [actual_target]
  tinyinst_.WriteCode(module, JMP_MEM, sizeof(JMP_MEM));

  if (tinyinst_.child_ptr_size == 8) {
    FixDisp4(module, (int32_t)tinyinst_.child_ptr_size);
    *(int32_t *)(module->instrumented_code_local + cmp_offset - 4) =
    (int32_t)((int64_t)module->instrumented_code_allocated -
              (int64_t)cmp_offset);
  } else {
    FixDisp4(module,
             (int32_t)(tinyinst_.GetCurrentInstrumentedAddress(module) +
             tinyinst_.child_ptr_size));
    *(int32_t *)(module->instrumented_code_local + cmp_offset - 4) =
        (int32_t)tinyinst_.GetCurrentInstrumentedAddress(module);
  }
}

void X86Assembler::InstrumentRet(ModuleInfo *module,
                                 Instruction &inst,
                                 size_t instruction_address,
                                 TinyInst::IndirectInstrumentation mode,
                                 size_t bb_address) {
  // lots of moving around, but the problem is
  // we need to store context in the same place
  // where the return address is

  // at the end, the stack must be
  // saved RAX
  // saved EFLAGS
  // <sp_offset>
  // and RAX must contain return address

  // store rax to a safe offset
  int32_t ax_offset = -tinyinst_.sp_offset - 2 * tinyinst_.child_ptr_size;
  WriteStack(module, ax_offset);
  // copy return address to a safe offset
  int32_t ret_offset = ax_offset - tinyinst_.child_ptr_size;
  ReadStack(module, 0);
  WriteStack(module, ret_offset);
  // get ret immediate
  int32_t imm = (int32_t)xed_decoded_inst_get_unsigned_immediate(&inst.xedd);
  // align the stack
  int32_t ret_pop =
      (int32_t)tinyinst_.child_ptr_size + imm - tinyinst_.sp_offset;
  OffsetStack(module, ret_pop);  // pop
  ax_offset -= ret_pop;
  ret_offset -= ret_pop;
  // write data to stack
  tinyinst_.WriteCode(module, PUSH_F, sizeof(PUSH_F));
  ax_offset += tinyinst_.child_ptr_size;
  ret_offset += tinyinst_.child_ptr_size;
  ReadStack(module, ax_offset);
  tinyinst_.WriteCode(module, PUSH_A, sizeof(PUSH_A));
  ax_offset += tinyinst_.child_ptr_size;
  ret_offset += tinyinst_.child_ptr_size;
  ReadStack(module, ret_offset);
  tinyinst_.InstrumentIndirect(module,
                               inst,
                               instruction_address,
                               mode,
                               bb_address);
}

// converts an indirect jump/call into a MOV instruction
// which moves the target of the indirect call into the RAX/EAX reguster
// and writes this instruction into the code buffer
void X86Assembler::MovIndirectTarget(ModuleInfo *module,
                                     Instruction &inst,
                                     size_t original_address,
                                     int32_t stack_offset) {
  size_t mem_address = 0;
  bool rip_relative =
      IsRipRelative(module, inst, original_address, &mem_address);

  xed_error_enum_t xed_error;
  uint32_t olen;

  const xed_inst_t *xi = xed_decoded_inst_inst(&inst.xedd);
  const xed_operand_t *op = xed_inst_operand(xi, 0);
  xed_operand_enum_t operand_name = xed_operand_name(op);

  xed_state_t dstate;
  dstate.mmode = (xed_machine_mode_enum_t)tinyinst_.child_ptr_size == 8
                     ? XED_MACHINE_MODE_LONG_64
                     : XED_MACHINE_MODE_LEGACY_32;
  dstate.stack_addr_width = (xed_address_width_enum_t)tinyinst_.child_ptr_size;

  xed_reg_enum_t dest_reg;
  if (tinyinst_.child_ptr_size == 4) {
    dest_reg = XED_REG_EAX;
  } else {
    dest_reg = XED_REG_RAX;
  }

  xed_encoder_request_t mov;
  xed_encoder_request_zero_set_mode(&mov, &dstate);
  xed_encoder_request_set_iclass(&mov, XED_ICLASS_MOV);

  xed_encoder_request_set_effective_operand_width(
      &mov, (uint32_t)(tinyinst_.child_ptr_size * 8));
  xed_encoder_request_set_effective_address_size(
      &mov, (uint32_t)(tinyinst_.child_ptr_size * 8));

  xed_encoder_request_set_reg(&mov, XED_OPERAND_REG0, dest_reg);
  xed_encoder_request_set_operand_order(&mov, 0, XED_OPERAND_REG0);

  if (operand_name == XED_OPERAND_MEM0) {
    xed_encoder_request_set_mem0(&mov);
    xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(&inst.xedd, 0);
    xed_encoder_request_set_base0(&mov, base_reg);
    xed_encoder_request_set_seg0(&mov, xed_decoded_inst_get_seg_reg(&inst.xedd, 0));
    xed_encoder_request_set_index(&mov,
                                  xed_decoded_inst_get_index_reg(&inst.xedd, 0));
    xed_encoder_request_set_scale(&mov, xed_decoded_inst_get_scale(&inst.xedd, 0));
    // in an unlikely case where base is rsp, disp needs fixing
    // this is because we pushed stuff on the stack
    if ((base_reg == XED_REG_SP) || (base_reg == XED_REG_ESP) ||
        (base_reg == XED_REG_RSP)) {
      // printf("base = sp\n");
      int64_t disp =
          xed_decoded_inst_get_memory_displacement(&inst.xedd, 0) + stack_offset;
      // always use disp width 4 in this case
      xed_encoder_request_set_memory_displacement(&mov, disp, 4);
    } else {
      xed_encoder_request_set_memory_displacement(
          &mov, xed_decoded_inst_get_memory_displacement(&inst.xedd, 0),
          xed_decoded_inst_get_memory_displacement_width(&inst.xedd, 0));
    }
    xed_encoder_request_set_memory_operand_length(
        &mov, xed_decoded_inst_get_memory_operand_length(&inst.xedd, 0));
    xed_encoder_request_set_operand_order(&mov, 1, XED_OPERAND_MEM0);
  } else if (operand_name == XED_OPERAND_REG0) {
    xed_encoder_request_set_reg(
        &mov,
        XED_OPERAND_REG1,
        xed_decoded_inst_get_reg(&inst.xedd, XED_OPERAND_REG0));
    xed_encoder_request_set_operand_order(&mov, 1, XED_OPERAND_REG1);
  } else {
    FATAL("Unexpected operand in indirect jump/call");
  }

  unsigned char encoded[15];
  xed_error = xed_encode(&mov, encoded, sizeof(encoded), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  if (rip_relative) {
    // fix displacement
    size_t out_instruction_size = olen;
    int64_t fixed_disp =
        (int64_t)mem_address -
        (int64_t)((size_t)module->instrumented_code_remote +
                  module->instrumented_code_allocated +
                  out_instruction_size);
    xed_encoder_request_set_memory_displacement(&mov, fixed_disp, 4);
    xed_error = xed_encode(&mov, encoded, sizeof(encoded), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    if (olen != out_instruction_size) {
      FATAL("Unexpected instruction size");
    }
  }

  tinyinst_.WriteCode(module, encoded, olen);
}

// translates indirect jump or call
// using global jumptable
void X86Assembler::InstrumentGlobalIndirect(ModuleInfo *module,
                                            Instruction &inst,
                                            size_t instruction_address) {
  if (xed_decoded_inst_get_category(&inst.xedd) != XED_CATEGORY_RET) {
    if (tinyinst_.sp_offset) {
      OffsetStack(module, -tinyinst_.sp_offset);
    }

    // push eflags
    // push RAX
    // push RBX
    tinyinst_.WriteCode(module, PUSH_FAB, sizeof(PUSH_FAB));

    int32_t stack_offset = tinyinst_.sp_offset + 3 * tinyinst_.child_ptr_size;

    if (xed_decoded_inst_get_category(&inst.xedd) == XED_CATEGORY_CALL) {
      stack_offset += tinyinst_.child_ptr_size;
    }

    MovIndirectTarget(module, inst, instruction_address, stack_offset);
  } else {
    // stack already set up, just push RBX
    tinyinst_.WriteCode(module, PUSH_B, sizeof(PUSH_B));
  }

  // mov rbx, rax
  // and rbx, (JUMPTABLE_SIZE - 1) * child_ptr_size
  if (tinyinst_.child_ptr_size == 8) {
    tinyinst_.WriteCode(module, MOV_RBXRAX, sizeof(MOV_RBXRAX));
    tinyinst_.WriteCode(module, AND_RBX, sizeof(AND_RBX));
  } else {
    tinyinst_.WriteCode(module, MOV_EBXEAX, sizeof(MOV_EBXEAX));
    tinyinst_.WriteCode(module, AND_EBX, sizeof(AND_EBX));
  }
  FixDisp4(module, (int32_t)((JUMPTABLE_SIZE - 1) * tinyinst_.child_ptr_size));

  // add rbx, [jumptable_address]
  if (tinyinst_.child_ptr_size == 8) {
    tinyinst_.WriteCode(module, ADD_RBXRIPRELATIVE, sizeof(ADD_RBXRIPRELATIVE));
    FixDisp4(module, (int32_t)((int64_t)module->jumptable_address_offset -
                               (int64_t)module->instrumented_code_allocated));
  } else {
    tinyinst_.WriteCode(module, ADD_EBXRIPRELATIVE, sizeof(ADD_EBXRIPRELATIVE));
    FixDisp4(module, (int32_t)((size_t)module->instrumented_code_remote +
                               module->jumptable_address_offset));
  }

  // jmp RBX
  tinyinst_.WriteCode(module, JMP_B, sizeof(JMP_B));
}

// translates indirect jump or call
// using local jumptable
void X86Assembler::InstrumentLocalIndirect(ModuleInfo *module,
                                           Instruction &inst,
                                           size_t instruction_address,
                                           size_t bb_address) {
  if (xed_decoded_inst_get_category(&inst.xedd) != XED_CATEGORY_RET) {
    if (tinyinst_.sp_offset) {
      OffsetStack(module, -tinyinst_.sp_offset);
    }

    // push eflags
    // push RAX
    tinyinst_.WriteCode(module, PUSH_FA, sizeof(PUSH_FA));

    int32_t stack_offset = tinyinst_.sp_offset + 2 * tinyinst_.child_ptr_size;

    if (xed_decoded_inst_get_category(&inst.xedd) == XED_CATEGORY_CALL) {
      stack_offset += tinyinst_.child_ptr_size;
    }

    MovIndirectTarget(module, inst, instruction_address, stack_offset);
  } else {
    // stack already set up
  }

  // jmp [breakpoint]
  tinyinst_.WriteCode(module, JMP_MEM, sizeof(JMP_MEM));

  size_t breakpoint_address = tinyinst_.GetCurrentInstrumentedAddress(module);

  if (tinyinst_.child_ptr_size == 8) {
    FixDisp4(module, 1);
  } else {
    FixDisp4(module, (int32_t)(breakpoint_address + 1));
  }

  // int3
  Breakpoint(module);
  module->br_indirect_newtarget_list[breakpoint_address] = {
      module->instrumented_code_allocated, bb_address};

  // breakpoint_address
  if (tinyinst_.child_ptr_size == 8) {
    uint64_t address = (uint64_t)breakpoint_address;
    tinyinst_.WriteCode(module, &address, sizeof(address));
  } else {
    uint32_t address = (uint32_t)breakpoint_address;
    tinyinst_.WriteCode(module, &address, sizeof(address));
  }
}

// pushes return address on the target stack
void X86Assembler::PushReturnAddress(ModuleInfo *module,
                                     uint64_t return_address) {
  // printf("retun address: %llx\n", return_address);
  // write the original return address
  OffsetStack(module, -(int)tinyinst_.child_ptr_size);
  uint32_t return_lo = (uint32_t)(((uint64_t)return_address) & 0xFFFFFFFF);
  uint32_t return_hi = (uint32_t)(((uint64_t)return_address) >> 32);

  // mov dword ptr [sp], return_lo
  tinyinst_.WriteCode(module, WRITE_SP_IMM, sizeof(WRITE_SP_IMM));
  *(uint32_t *)(module->instrumented_code_local +
                module->instrumented_code_allocated - 4) = return_lo;

  if (tinyinst_.child_ptr_size == 8) {
    // mov dword ptr [sp+4], return_hi
    tinyinst_.WriteCode(module, WRITE_SP_4_IMM, sizeof(WRITE_SP_4_IMM));
    *(uint32_t *)(module->instrumented_code_local +
                  module->instrumented_code_allocated - 4) = return_hi;
  }
}

// outputs instruction into the translated code buffer
// fixes stuff like rip-relative addressing
void X86Assembler::FixInstructionAndOutput(
    ModuleInfo *module,
    Instruction &inst,
    const unsigned char *input,
    const unsigned char *input_address_remote,
    bool convert_call_to_jmp) {
  size_t mem_address = 0;
  bool rip_relative =
      IsRipRelative(module, inst, (size_t)input_address_remote, &mem_address);

  size_t original_instruction_size = xed_decoded_inst_get_length(&inst.xedd);

  bool needs_fixing = rip_relative || convert_call_to_jmp;

  // fast path
  // just copy instruction bytes without encoding
  if (!needs_fixing) {
    tinyinst_.WriteCode(module, (void *)input, original_instruction_size);
    return;
  }

  unsigned int olen;
  xed_encoder_request_init_from_decode(&inst.xedd);
  xed_error_enum_t xed_error;
  unsigned char tmp[15];

  if (convert_call_to_jmp) {
    xed_encoder_request_set_iclass(&inst.xedd, XED_ICLASS_JMP);
  }

  if (!rip_relative) {
    xed_error = xed_encode(&inst.xedd, tmp, sizeof(tmp), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    tinyinst_.WriteCode(module, tmp, olen);
    return;
  }

  size_t instruction_end_addr;
  int64_t fixed_disp;

  instruction_end_addr = (size_t)module->instrumented_code_remote +
                         module->instrumented_code_allocated +
                         original_instruction_size;

  // encode an instruction once just to get the instruction size
  // as it needs not be the original size
  fixed_disp = (int64_t)(mem_address) - (int64_t)(instruction_end_addr);

  if (llabs(fixed_disp) > 0x7FFFFFFF) FATAL("Offset larger than 2G");

  xed_encoder_request_set_memory_displacement(&inst.xedd, fixed_disp, 4);
  xed_error = xed_encode(&inst.xedd, tmp, sizeof(tmp), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  size_t out_instruction_size = olen;
  if ((module->instrumented_code_allocated + out_instruction_size) >
      module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  instruction_end_addr = (size_t)module->instrumented_code_remote +
                         module->instrumented_code_allocated +
                         out_instruction_size;

  fixed_disp = (int64_t)(mem_address) - (int64_t)(instruction_end_addr);

  if (llabs(fixed_disp) > 0x7FFFFFFF) FATAL("Offset larger than 2G");

  xed_encoder_request_set_memory_displacement(&inst.xedd, fixed_disp, 4);
  xed_error = xed_encode(&inst.xedd,
                         (unsigned char *)(module->instrumented_code_local +
                                           module->instrumented_code_allocated),
                         (uint32_t)(module->instrumented_code_size -
                                    module->instrumented_code_allocated),
                         &olen);

  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }
  if (olen != out_instruction_size) {
    FATAL("Unexpected instruction size");
  }

  module->instrumented_code_allocated += olen;
}


// when an invalid instruction is encountered
// emit a breakpoint followed by crashing the process
void X86Assembler::InvalidInstruction(ModuleInfo *module) {
  size_t breakpoint_address = (size_t)module->instrumented_code_remote +
                              module->instrumented_code_allocated;
  Breakpoint(module);
  module->invalid_instructions.insert(breakpoint_address);
  if (tinyinst_.child_ptr_size == 8) {
    tinyinst_.WriteCode(module, CRASH_64, sizeof(CRASH_64));
  } else {
    tinyinst_.WriteCode(module, CRASH_32, sizeof(CRASH_32));
  }
}

bool X86Assembler::DecodeInstruction(Instruction &inst,
                                     const unsigned char *buffer,
                                     unsigned int buffer_size) {
  xed_state_t dstate;
  dstate.mmode = (xed_machine_mode_enum_t)tinyinst_.child_ptr_size == 8
                     ? XED_MACHINE_MODE_LONG_64
                     : XED_MACHINE_MODE_LEGACY_32;
  dstate.stack_addr_width = (xed_address_width_enum_t)tinyinst_.child_ptr_size;

  xed_decoded_inst_zero_set_mode(&inst.xedd, &dstate);
  xed_error_enum_t xed_error = xed_decode(&inst.xedd, buffer, buffer_size);

  if (xed_error != XED_ERROR_NONE) return false;

  inst.address = (size_t)buffer;
  inst.length = xed_decoded_inst_get_length(&inst.xedd);
  inst.bbend = false;
  xed_category_enum_t category = xed_decoded_inst_get_category(&inst.xedd);
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&inst.xedd);


  switch (iclass) {
    case XED_ICLASS_JMP:
      inst.iclass = InstructionClass::IJUMP;
      break;
    case XED_ICLASS_CALL_NEAR:
      inst.iclass = InstructionClass::ICALL;
      break;
    default:
      inst.iclass = InstructionClass::NONE;
      break;
  }

  switch (category) {
    case XED_CATEGORY_RET:
      inst.iclass = InstructionClass::RET;
      if(iclass == XED_ICLASS_RET_NEAR) {
        inst.iclass = InstructionClass::RET_NEAR;
      }
    case XED_CATEGORY_CALL:
    case XED_CATEGORY_UNCOND_BR:
    case XED_CATEGORY_COND_BR:
      inst.bbend = true;
      break;
    default:
      break;
  }
  return true;
}

// fixes an offset in the jump instruction (at offset jmp_offset in the
// instrumented code) to jump to the given basic block (at offset bb in the
// original code)
void X86Assembler::FixOffset(ModuleInfo *module,
                             uint32_t jmp_offset,
                             uint32_t target_offset) {
  int32_t jmp_relative_offset =
    (int32_t)target_offset - (int32_t)(jmp_offset + 4);
  *(int32_t *)(module->instrumented_code_local + jmp_offset) =
    jmp_relative_offset;
}

void X86Assembler::HandleBasicBlockEnd(
    const char *address,
    ModuleInfo *module,
    std::set<char *> *queue,
    std::list<std::pair<uint32_t, uint32_t>> *offset_fixes,
    Instruction &inst,
    const char *code_ptr,
    size_t offset,
    size_t last_offset) {
  if (!inst.bbend) {
    // WARN("Could not find end of bb at %p.\n", address);
    InvalidInstruction(module);
    return;
  }

  xed_error_enum_t xed_error;
  xed_category_enum_t category = xed_decoded_inst_get_category(&inst.xedd);
  if (category == XED_CATEGORY_RET) {
    TinyInst::IndirectInstrumentation ii_mode =
      tinyinst_.ShouldInstrumentIndirect(module,
                                         inst,
                                         (size_t)address + last_offset);

    if (ii_mode != TinyInst::IndirectInstrumentation::II_NONE) {
      InstrumentRet(module, inst, (size_t)address + last_offset, ii_mode,
                    (size_t)address);
    } else {
      FixInstructionAndOutput(
        module,
        inst,
        (unsigned char *)(code_ptr + last_offset),
        (unsigned char *)(address + last_offset));
    }

  } else if (category == XED_CATEGORY_COND_BR) {
    // j* target_address
    // gets instrumented as:
    //   j* label
    //   <edge instrumentation>
    //   jmp continue_address
    // label:
    //   <edge instrumentation>
    //   jmp target_address

    // must have an operand
    const xed_inst_t *xi = xed_decoded_inst_inst(&inst.xedd);
    const xed_operand_t *op = xed_inst_operand(xi, 0);
    xed_operand_enum_t operand_name = xed_operand_name(op);

    if (operand_name != XED_OPERAND_RELBR) {
      FATAL("Error getting branch target");
    }

    int32_t disp = xed_decoded_inst_get_branch_displacement(&inst.xedd);
    uint32_t disp_width =
        xed_decoded_inst_get_branch_displacement_width(&inst.xedd);
    if (disp_width == 0) {
      FATAL("Error getting branch target");
    }

    const char *target_address1 = address + offset;
    const char *target_address2 = address + offset + disp;

    if (tinyinst_.GetModule((size_t)target_address2) != module) {
      WARN("Relative jump to a differen module in bb at %p\n", address);
      InvalidInstruction(module);
      return;
    }

    // preliminary encode jump instruction
    // displacement might be changed later as we don't know
    // the size of edge instrumentation yet
    // assuming 0 for now
    int32_t fixed_disp = sizeof(JMP);
    unsigned char encoded[15];
    unsigned int olen;
    unsigned int jump_size;
    xed_encoder_request_init_from_decode(&inst.xedd);
    xed_encoder_request_set_branch_displacement(&inst.xedd,
                                                fixed_disp,
                                                disp_width);
    xed_error = xed_encode(&inst.xedd, encoded, sizeof(encoded), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    jump_size = olen;
    size_t jump_start_offset = module->instrumented_code_allocated;
    tinyinst_.WriteCode(module, encoded, jump_size);
    size_t jump_end_offset = module->instrumented_code_allocated;

    // instrument the 1st edge
    tinyinst_.InstrumentEdge(module, module, (size_t)address,
                             (size_t)target_address1);

    // jmp target_address1
    tinyinst_.WriteCode(module, JMP, sizeof(JMP));

    tinyinst_.FixOffsetOrEnqueue(
        module,
        (uint32_t)((size_t)target_address1 - (size_t)(module->min_address)),
        (uint32_t)(module->instrumented_code_allocated - 4), queue,
        offset_fixes);

    // time to fix that conditional jump offset
    if ((module->instrumented_code_allocated - jump_end_offset) != fixed_disp) {
      fixed_disp =
          (int32_t)(module->instrumented_code_allocated - jump_end_offset);
      xed_encoder_request_set_branch_displacement(&inst.xedd,
                                                  fixed_disp,
                                                  disp_width);
      xed_error = xed_encode(&inst.xedd, encoded, sizeof(encoded), &olen);
      if (xed_error != XED_ERROR_NONE) {
        FATAL("Error encoding instruction");
      }
      if (jump_size != olen) {
        FATAL("Instruction size changed?");
      }
      tinyinst_.WriteCodeAtOffset(module, jump_start_offset, encoded,
                                  jump_size);
    }

    // instrument the 2nd edge
    tinyinst_.InstrumentEdge(module, module, (size_t)address,
                             (size_t)target_address2);

    // jmp target_address2
    tinyinst_.WriteCode(module, JMP, sizeof(JMP));

    tinyinst_.FixOffsetOrEnqueue(
        module,
        (uint32_t)((size_t)target_address2 - (size_t)(module->min_address)),
        (uint32_t)(module->instrumented_code_allocated - 4),
        queue,
        offset_fixes);

  } else if (category == XED_CATEGORY_UNCOND_BR) {
    // must have an operand
    const xed_inst_t *xi = xed_decoded_inst_inst(&inst.xedd);
    const xed_operand_t *op = xed_inst_operand(xi, 0);

    xed_operand_enum_t operand_name = xed_operand_name(op);

    if (operand_name == XED_OPERAND_RELBR) {
      // jmp address
      // gets instrumented as:
      // jmp fixed_address

      int32_t disp = xed_decoded_inst_get_branch_displacement(&inst.xedd);
      uint32_t disp_width =
          xed_decoded_inst_get_branch_displacement_width(&inst.xedd);
      if (disp_width == 0) {
        FATAL("Error getting branch target");
      }

      const char *target_address = address + offset + disp;

      if (tinyinst_.GetModule((size_t)target_address) != module) {
        WARN("Relative jump to a differen module in bb at %p\n", address);
        InvalidInstruction(module);
        return;
      }

      // jmp target_address
      tinyinst_.WriteCode(module, JMP, sizeof(JMP));

      tinyinst_.FixOffsetOrEnqueue(
          module,
          (uint32_t)((size_t)target_address - (size_t)(module->min_address)),
          (uint32_t)(module->instrumented_code_allocated - 4), queue,
          offset_fixes);

    } else {
      TinyInst::IndirectInstrumentation ii_mode =
        tinyinst_.ShouldInstrumentIndirect(module,
                                           inst,
                                           (size_t)address + last_offset);

      if (ii_mode != TinyInst::IndirectInstrumentation::II_NONE) {
        tinyinst_.InstrumentIndirect(module, inst,
                                     (size_t)address + last_offset, ii_mode,
                                     (size_t)address);
      } else {
        FixInstructionAndOutput(
          module,
          inst,
          (unsigned char *)(code_ptr + last_offset),
          (unsigned char *)(address + last_offset));
      }
    }

  } else if (category == XED_CATEGORY_CALL) {
    // must have an operand
    const xed_inst_t *xi = xed_decoded_inst_inst(&inst.xedd);
    const xed_operand_t *op = xed_inst_operand(xi, 0);

    xed_operand_enum_t operand_name = xed_operand_name(op);

    if (operand_name == XED_OPERAND_RELBR) {
      // call target_address
      // gets instrumented as:
      //   call label
      //   jmp return_address
      // label:
      //   jmp target_address

      int32_t disp = xed_decoded_inst_get_branch_displacement(&inst.xedd);
      uint32_t disp_width =
          xed_decoded_inst_get_branch_displacement_width(&inst.xedd);
      if (disp_width == 0) {
        FATAL("Error getting branch target");
      }

      const char *return_address = address + offset;
      const char *call_address = address + offset + disp;

      if (tinyinst_.GetModule((size_t)call_address) != module) {
        WARN("Relative jump to a differen module in bb at %p\n", address);
        InvalidInstruction(module);
        return;
      }

      // fix the displacement and emit the call
      if (!tinyinst_.patch_return_addresses) {
        unsigned char encoded[15];
        unsigned int olen;
        xed_encoder_request_init_from_decode(&inst.xedd);
        xed_encoder_request_set_branch_displacement(&inst.xedd,
                                                    sizeof(JMP),
                                                    disp_width);
        xed_error = xed_encode(&inst.xedd, encoded, sizeof(encoded), &olen);
        if (xed_error != XED_ERROR_NONE) {
          FATAL("Error encoding instruction");
        }
        tinyinst_.WriteCode(module, encoded, olen);

        // jmp return_address
        tinyinst_.WriteCode(module, JMP, sizeof(JMP));

        tinyinst_.FixOffsetOrEnqueue(
            module,
            (uint32_t)((size_t)return_address - (size_t)(module->min_address)),
            (uint32_t)(module->instrumented_code_allocated - 4), queue,
            offset_fixes);

        // jmp call_address
        tinyinst_.WriteCode(module, JMP, sizeof(JMP));

        tinyinst_.FixOffsetOrEnqueue(
            module,
            (uint32_t)((size_t)call_address - (size_t)(module->min_address)),
            (uint32_t)(module->instrumented_code_allocated - 4), queue,
            offset_fixes);

      } else {
        PushReturnAddress(module, (uint64_t)return_address);

        // jmp call_address
        tinyinst_.WriteCode(module, JMP, sizeof(JMP));

        tinyinst_.FixOffsetOrEnqueue(
            module,
            (uint32_t)((size_t)call_address - (size_t)(module->min_address)),
            (uint32_t)(module->instrumented_code_allocated - 4), queue,
            offset_fixes);

        // done, we don't need to do anything else as return gets redirected
        // later
      }

    } else /* CALL, operand_name != XED_OPERAND_RELBR */ {
      const char *return_address = address + offset;

      TinyInst::IndirectInstrumentation ii_mode =
        tinyinst_.ShouldInstrumentIndirect(module,
                                           inst,
                                           (size_t)address + last_offset);

      if (ii_mode != TinyInst::IndirectInstrumentation::II_NONE) {
        if (tinyinst_.patch_return_addresses) {
          PushReturnAddress(module, (uint64_t)return_address);

          tinyinst_.InstrumentIndirect(module, inst,
                                       (size_t)address + last_offset,
                                       ii_mode,
                                       (size_t)address);

        } else {
          //   call label
          //   jmp return_address
          //  label:
          //    <indirect instrumentation>

          tinyinst_.WriteCode(module, CALL, sizeof(CALL));
          FixDisp4(module, sizeof(JMP));

          tinyinst_.WriteCode(module, JMP, sizeof(JMP));

          tinyinst_.FixOffsetOrEnqueue(
              module,
              (uint32_t)((size_t)return_address -
                         (size_t)(module->min_address)),
              (uint32_t)(module->instrumented_code_allocated - 4), queue,
              offset_fixes);

          tinyinst_.InstrumentIndirect(module, inst,
                                       (size_t)address + last_offset, ii_mode,
                                       (size_t)address);
        }

      } else {
        if (tinyinst_.patch_return_addresses) {
          PushReturnAddress(module, (uint64_t)return_address);
          // xed_decoded_inst_t jmp;
          // CallToJmp(&xedd, &jmp);
          FixInstructionAndOutput(
            module,
            inst,
            (unsigned char *)(code_ptr + last_offset),
            (unsigned char *)(address + last_offset), true);
        } else {
          FixInstructionAndOutput(
            module,
            inst,
            (unsigned char *)(code_ptr + last_offset),
            (unsigned char *)(address + last_offset));

          tinyinst_.WriteCode(module, JMP, sizeof(JMP));

          tinyinst_.FixOffsetOrEnqueue(
              module,
              (uint32_t)((size_t)return_address -
                         (size_t)(module->min_address)),
              (uint32_t)(module->instrumented_code_allocated - 4), queue,
              offset_fixes);
        }
      }
    }
  }
}

void X86Assembler::Init() {
  xed_tables_init();
}
