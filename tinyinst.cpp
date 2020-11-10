/*
Copyright 2020 Google LLC

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

#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include <list>
using namespace std;

#include "tinyinst.h"

extern "C" {
#include "xed/xed-interface.h"
}

// nop
unsigned char NOP[] = { 0x90 };

// jmp offset
unsigned char JMP[] = { 0xe9, 0x00, 0x00, 0x00, 0x00 };

//call offset
unsigned char CALL[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };

// warning, this is rip-relative on x64 but absolute on 32-bit
// jmp [offset]
unsigned char JMP_MEM[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };

// lea rsp, [rsp + disp]
unsigned char LEARSP[] = { 0x48, 0x8d, 0xa4, 0x24, 0x00, 0x00, 0x00, 0x00 };
// lea esp, [esp + disp]
unsigned char LEAESP[] = { 0x8D, 0xA4, 0x24, 0x00, 0x00, 0x00, 0x00 };

// push flags
// push rax
// push rbx
unsigned char PUSH_FAB[] = { 0x9c, 0x50, 0x53 };

// push flags
// push rax
unsigned char PUSH_FA[] = { 0x9c, 0x50 };

// push flags
unsigned char PUSH_F[] = { 0x9c };

// push rax
unsigned char PUSH_A[] = { 0x50 };

// push rbx
unsigned char PUSH_B[] = { 0x53 };

// pop rbx
// pop rax
// pop flags
unsigned char POP_BAF[] = { 0x5B, 0x58, 0x9d };

// pop rax
// pop flags
unsigned char POP_AF[] = { 0x58, 0x9d };

// pop rax
unsigned char POP_A[] = { 0x58 };

// and rbx, constant
unsigned char AND_RBX[] = { 0x48, 0x81, 0xe3, 0x00, 0x00, 0x00, 0x00 };
// and ebx, constant
unsigned char AND_EBX[] = { 0x81, 0xe3, 0x00, 0x00, 0x00, 0x00 };

// mov rbx, rax
unsigned char MOV_RBXRAX[] = { 0x48, 0x89, 0xC3 };
// mov ebx, eax
unsigned char MOV_EBXEAX[] = { 0x89, 0xC3 };

// add rbx, [offset]
unsigned char ADD_RBXRIPRELATIVE[] = { 0x48, 0x03, 0x1D, 0x00, 0x00, 0x00, 0x00 };
// add ebx, [offset]
unsigned char ADD_EBXRIPRELATIVE[] = { 0x03, 0x1D, 0x00, 0x00, 0x00, 0x00 };

// jmp [rbx]
unsigned char JMP_B[] = { 0xFF, 0x23 };

// cmp rax, [offset]
unsigned char CMP_RAX[] = { 0x48, 0x3B, 0x05, 0x00, 0x00, 0x00, 0x00 };
// cmp eax, [offset]
unsigned char CMP_EAX[] = { 0x3B, 0x05, 0x00, 0x00, 0x00, 0x00 };

// je offset
unsigned char JE[] = { 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };

// mov [rsp], imm
unsigned char WRITE_SP_IMM[] = { 0xC7, 0x04, 0x24, 0xAA, 0xAA, 0xAA, 0xAA };
// mov [rsp+4], imm
unsigned char WRITE_SP_4_IMM[] = { 0xC7, 0x44, 0x24, 0x04, 0xAA, 0xAA, 0xAA, 0xAA };

// mov rax, [rsp + offset]
unsigned char MOV_RAX_RSPMEM[] = { 0x48, 0x8B, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A };
// mov eax, [esp + offset]
unsigned char MOV_EAX_ESPMEM[] = { 0x8B, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A };

// mov [rsp + offset], rax
unsigned char MOV_RSPMEM_RAX[] = { 0x48, 0x89, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A };
// mov [esp + offset], eax
unsigned char MOV_ESPMEM_EAX[] = { 0x89, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A };

// mov byte ptr [0], 0
unsigned char CRASH_64[] = { 0xC6, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char CRASH_32[] = { 0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };

TinyInst::ModuleInfo::ModuleInfo() {
  module_name[0] = 0;
  module_header = NULL;
  min_address = 0;
  max_address = 0;
  loaded = false;
  instrumented = false;
  instrumented_code_local = NULL;
  instrumented_code_remote = NULL;
  instrumented_code_remote_previous = NULL;
  instrumented_code_size = 0;
}

void TinyInst::ModuleInfo::ClearInstrumentation() {
  instrumented = false;

  for (auto iter = executable_ranges.begin(); iter != executable_ranges.end(); iter++) {
    if (iter->data) free(iter->data);
  }
  executable_ranges.clear();
  code_size = 0;

  if (instrumented_code_local) free(instrumented_code_local);

  instrumented_code_local = NULL;
  instrumented_code_remote = NULL;
  instrumented_code_remote_previous = NULL;

  instrumented_code_size = 0;
  instrumented_code_allocated = 0;

  basic_blocks.clear();

  br_indirect_newtarget_global = 0;
  br_indirect_newtarget_list.clear();

  jumptable_offset = 0;
  jumptable_address_offset = 0;

  invalid_instructions.clear();
  tracepoints.clear();
}

void TinyInst::InvalidateCrossModuleLink(CrossModuleLink *link) {
  ModuleInfo *module1 = link->module1;
  size_t original_value = ReadPointer(module1, link->offset1);
  WritePointerAtOffset(module1, original_value, link->offset1 + child_ptr_size);
  CommitCode(module1, link->offset1 + child_ptr_size, child_ptr_size);
}

void TinyInst::FixCrossModuleLink(CrossModuleLink *link) {
  ModuleInfo *module1 = link->module1;
  ModuleInfo *module2 = link->module2;

  size_t original_value = (size_t)module2->min_address + link->offset2;
  size_t translated_value = GetTranslatedAddress(module2, original_value);

  WritePointerAtOffset(module1, original_value, link->offset1);
  WritePointerAtOffset(module1, translated_value, link->offset1 + child_ptr_size);

  CommitCode(module1, link->offset1, 2 * child_ptr_size);
}

void TinyInst::InvalidateCrossModuleLinks(ModuleInfo *module) {
  for (auto iter = cross_module_links.begin(); iter != cross_module_links.end(); iter++) {
    if (iter->module2 == module) {
      InvalidateCrossModuleLink(&(*iter));
    }
  }
}

void TinyInst::InvalidateCrossModuleLinks() {
  for (auto iter = cross_module_links.begin(); iter != cross_module_links.end(); iter++) {
    InvalidateCrossModuleLink(&(*iter));
  }
}

void TinyInst::FixCrossModuleLinks(ModuleInfo *module) {
  for (auto iter = cross_module_links.begin(); iter != cross_module_links.end(); iter++) {
    if (iter->module2 == module) {
      FixCrossModuleLink(&(*iter));
    }
  }
}

void TinyInst::ClearCrossModuleLinks(ModuleInfo *module) {
  auto iter = cross_module_links.begin();
  while (iter != cross_module_links.end()) {
    if (iter->module1 == module) {
      iter = cross_module_links.erase(iter);
    } else {
      iter++;
    }
  }
}

void TinyInst::ClearCrossModuleLinks() {
  cross_module_links.clear();
}

// Global jumptable for indirect jumps/calls.
// This is an array of size JUMPTABLE_SIZE where each entry initially
// points to indirect_breakpoint_address.
// When a new indirect jump/call target is detected, this will cause a breakpoint
// which will be resolved by adding a new entry into this hashtable.
void TinyInst::InitGlobalJumptable(ModuleInfo *module) {
  size_t code_size_before = module->instrumented_code_allocated;

  module->jumptable_offset = module->instrumented_code_allocated;

  module->br_indirect_newtarget_global = 
    (size_t)module->instrumented_code_remote + 
    module->instrumented_code_allocated + 
    JUMPTABLE_SIZE * child_ptr_size + 
    child_ptr_size;

  for (size_t i = 0; i < JUMPTABLE_SIZE; i++) {
    WritePointer(module, module->br_indirect_newtarget_global);
  }

  module->jumptable_address_offset = module->instrumented_code_allocated;
  WritePointer(module, (size_t)module->instrumented_code_remote + module->jumptable_offset);

  unsigned char breakpoint = 0xCC;
  WriteCode(module, &breakpoint, 1);

  size_t code_size_after = module->instrumented_code_allocated;

  CommitCode(module, code_size_before, (code_size_after - code_size_before));
}

// Writes the modified code from the debugger process into the target process
void TinyInst::CommitCode(ModuleInfo *module, size_t start_offset, size_t size) {
  if (!module->instrumented_code_remote) return;

  RemoteWrite(module->instrumented_code_remote + start_offset,
              module->instrumented_code_local + start_offset,
              size);
}

// Checks if there is sufficient space and writes code at the current offset
void TinyInst::WriteCode(ModuleInfo *module, void *data, size_t size) {
  if (module->instrumented_code_allocated + size > module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  memcpy(module->instrumented_code_local + module->instrumented_code_allocated, data, size);
  module->instrumented_code_allocated += size;
}

// Checks if there is sufficient space and writes code at the chosen offset
void TinyInst::WriteCodeAtOffset(ModuleInfo *module, size_t offset, void *data, size_t size) {
  if (offset + size > module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  memcpy(module->instrumented_code_local + offset, data, size);

  if (offset + size > module->instrumented_code_allocated) {
    module->instrumented_code_allocated = offset + size;
  }
}

// writes a pointer to the instrumented code
void TinyInst::WritePointer(ModuleInfo *module, size_t value) {
  if (module->instrumented_code_allocated + child_ptr_size > module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  if (child_ptr_size == 8) {
    *(uint64_t *)(module->instrumented_code_local + module->instrumented_code_allocated) =
      (uint64_t)value;
  } else {
    *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated) =
      (uint32_t)value;
  }

  module->instrumented_code_allocated += child_ptr_size;
}

// writes a pointer to the instrumented code
void TinyInst::WritePointerAtOffset(ModuleInfo *module, size_t value, size_t offset) {
  if (offset + child_ptr_size > module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  if (child_ptr_size == 8) {
    *(uint64_t *)(module->instrumented_code_local + offset) = (uint64_t)value;
  } else {
    *(uint32_t *)(module->instrumented_code_local + offset) = (uint32_t)value;
  }

  if (offset + child_ptr_size > module->instrumented_code_allocated) {
    module->instrumented_code_allocated += offset + child_ptr_size;
  }
}

// reads a pointer from the instrumented code
size_t TinyInst::ReadPointer(ModuleInfo *module, size_t offset) {
  if (child_ptr_size == 8) {
    return (size_t)(*(uint64_t *)(module->instrumented_code_local + offset));
  } else {
    return (size_t)(*(uint32_t *)(module->instrumented_code_local + offset));
  }
}

// fixes an offset in the jump instruction (at offset jmp_offset in the instrumented code)
// to jump to the given basic block (at offset bb in the original code)
// in case the basic block hasn't been instrumented yet, queues it for instrumentation
void TinyInst::FixOffsetOrEnqueue(ModuleInfo *module,
                                  uint32_t bb,
                                  uint32_t jmp_offset,
                                  std::set<char *> *queue,
                                  std::list<std::pair<uint32_t, uint32_t>> *offset_fixes)
{
  auto iter = module->basic_blocks.find(bb);
  if (iter == module->basic_blocks.end()) {
    char *address = (char *)module->min_address + bb;
    if (queue->find(address) == queue->end()) {
      queue->insert(address);
    }
    offset_fixes->push_back({ bb, jmp_offset });
  } else {
    int32_t jmp_relative_offset = (int32_t)iter->second - (int32_t)(jmp_offset + 4);
    *(int32_t *)(module->instrumented_code_local + jmp_offset) = jmp_relative_offset;
  }
}

// adds/subtracts a given offset to the stack pointer
// this is done using LEA instruction rather than ADD/SUB
// to avoid clobbering the flags
void TinyInst::OffsetStack(ModuleInfo *module, int32_t offset) {
  // lea rsp, [rsp + offset]
  if (child_ptr_size == 8) {
    WriteCode(module, LEARSP, sizeof(LEARSP));
  } else {
    WriteCode(module, LEAESP, sizeof(LEAESP));
  }

  FixDisp4(module, offset);
}

// mov rax, [rsp + offset]
void TinyInst::ReadStack(ModuleInfo *module, int32_t offset) {
  if (child_ptr_size == 8) {
    WriteCode(module, MOV_RAX_RSPMEM, sizeof(MOV_RAX_RSPMEM));
  } else {
    WriteCode(module, MOV_EAX_ESPMEM, sizeof(MOV_EAX_ESPMEM));
  }
  FixDisp4(module, offset);
}

// mov [rsp + offset], rax
void TinyInst::WriteStack(ModuleInfo *module, int32_t offset) {
  if (child_ptr_size == 8) {
    WriteCode(module, MOV_RSPMEM_RAX, sizeof(MOV_RSPMEM_RAX));
  } else {
    WriteCode(module, MOV_ESPMEM_EAX, sizeof(MOV_ESPMEM_EAX));
  }
  FixDisp4(module, offset);
}

// converts an indirect jump/call into a MOV instruction
// which moves the target of the indirect call into the RAX/EAX reguster
// and writes this instruction into the code buffer
void TinyInst::MovIndirectTarget(ModuleInfo *module,
                                 xed_decoded_inst_t *xedd,
                                 size_t original_address,
                                 int32_t stack_offset)
{
  size_t mem_address = 0;
  bool rip_relative = IsRipRelative(module, xedd, original_address, &mem_address);

  xed_error_enum_t xed_error;
  uint32_t olen;

  const xed_inst_t* xi = xed_decoded_inst_inst(xedd);
  const xed_operand_t* op = xed_inst_operand(xi, 0);
  xed_operand_enum_t operand_name = xed_operand_name(op);

  xed_state_t dstate;
  dstate.mmode = (xed_machine_mode_enum_t)xed_mmode;
  dstate.stack_addr_width = (xed_address_width_enum_t)child_ptr_size;

  xed_reg_enum_t dest_reg;
  if (child_ptr_size == 4) {
    dest_reg = XED_REG_EAX;
  } else {
    dest_reg = XED_REG_RAX;
  }

  xed_encoder_request_t mov;
  xed_encoder_request_zero_set_mode(&mov, &dstate);
  xed_encoder_request_set_iclass(&mov, XED_ICLASS_MOV);

  xed_encoder_request_set_effective_operand_width(&mov, (uint32_t)(child_ptr_size * 8));
  xed_encoder_request_set_effective_address_size(&mov, (uint32_t)(child_ptr_size * 8));

  xed_encoder_request_set_reg(&mov, XED_OPERAND_REG0, dest_reg);
  xed_encoder_request_set_operand_order(&mov, 0, XED_OPERAND_REG0);

  if (operand_name == XED_OPERAND_MEM0) {
    xed_encoder_request_set_mem0(&mov);
    xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(xedd, 0);
    xed_encoder_request_set_base0(&mov, base_reg);
    xed_encoder_request_set_seg0(&mov, xed_decoded_inst_get_seg_reg(xedd, 0));
    xed_encoder_request_set_index(&mov, xed_decoded_inst_get_index_reg(xedd, 0));
    xed_encoder_request_set_scale(&mov, xed_decoded_inst_get_scale(xedd, 0));
    // in an unlikely case where base is rsp, disp needs fixing
    // this is because we pushed stuff on the stack
    if ((base_reg == XED_REG_SP) || (base_reg == XED_REG_ESP) || (base_reg == XED_REG_RSP)) {
      // printf("base = sp\n");
      int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0) + stack_offset;
      // always use disp width 4 in this case
      xed_encoder_request_set_memory_displacement(&mov, disp, 4);
    } else {
      xed_encoder_request_set_memory_displacement(&mov,
        xed_decoded_inst_get_memory_displacement(xedd, 0),
        xed_decoded_inst_get_memory_displacement_width(xedd, 0));
    }
    xed_encoder_request_set_memory_operand_length(&mov,
      xed_decoded_inst_get_memory_operand_length(xedd, 0));
    xed_encoder_request_set_operand_order(&mov, 1, XED_OPERAND_MEM0);
  } else if (operand_name == XED_OPERAND_REG0) {
    xed_encoder_request_set_reg(&mov, XED_OPERAND_REG1,
      xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0));
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
    int64_t fixed_disp = (int64_t)mem_address -
      (int64_t)((size_t)module->instrumented_code_remote +
        module->instrumented_code_allocated + out_instruction_size);
    xed_encoder_request_set_memory_displacement(&mov, fixed_disp, 4);
    xed_error = xed_encode(&mov, encoded, sizeof(encoded), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    if (olen != out_instruction_size) {
      FATAL("Unexpected instruction size");
    }
  }

  WriteCode(module, encoded, olen);
}

// various breapoints
bool TinyInst::HandleBreakpoint(void *address) {
  ModuleInfo *module = GetModuleFromInstrumented((size_t)address);
  if (!module) return false;

  // bb tracing
  if (trace_basic_blocks) {
    auto iter = module->tracepoints.find((size_t)address);
    if (iter != module->tracepoints.end()) {

      printf("TRACE: Executing basic block, original at %p, instrumented at %p\n",
             (void *)iter->second, (void *)iter->first);

      return true;
    } else {
      printf("TRACE: Breakpoint\n");
    }
  }

  // indirect jump new target
  if (HandleIndirectJMPBreakpoint(address)) return true;

  // invalid instruction
  if (module->invalid_instructions.find((size_t)address) != module->invalid_instructions.end()) {
    WARN("Attempting to execute an instruction TinyInst couldn't translate");
    WARN("This could be either due to a bug in the target or the bug/incompatibility in TinyInst");
    WARN("The target will crash now");
    return true;
  }

  return false;
}

// handles a breakpoint that occurs
// when an indirect jump or call wants to go to a previously
// unseen target
bool TinyInst::HandleIndirectJMPBreakpoint(void *address) {
  if (indirect_instrumentation_mode == II_NONE) return false;

  ModuleInfo *module = GetModuleFromInstrumented((size_t)address);
  if (!module) return false;

  bool is_indirect_breakpoint = false;
  bool global_indirect;

  size_t list_head_offset;
  size_t instruction_address = 0;

  if ((size_t)address == module->br_indirect_newtarget_global) {
    is_indirect_breakpoint = true;
    global_indirect = true;
  } else {
    auto iter = module->br_indirect_newtarget_list.find((size_t)address);
    if (iter != module->br_indirect_newtarget_list.end()) {
      is_indirect_breakpoint = true;
      global_indirect = false;
      list_head_offset = iter->second.list_head;
      instruction_address = iter->second.source_bb;
    }
  }

  if (!is_indirect_breakpoint) return false;

  size_t original_address = GetRegister(RAX);

  // if it's a global indirect, list head must be calculated from target
  // otherwise it's a per-callsite indirect and the list head was set earlier
  if (global_indirect) {
    list_head_offset = module->jumptable_offset +
                       original_address & ((JUMPTABLE_SIZE - 1) * child_ptr_size);
  }

  size_t translated_address;
  ModuleInfo *target_module = GetModule((size_t)original_address);

  if (target_module == module) {
    translated_address = GetTranslatedAddress(module, original_address);
  } else if (target_module && instrument_cross_module_calls) {
    translated_address = GetTranslatedAddress(target_module, original_address);
  } else {
    translated_address = original_address;
  }

  // printf("Adding jumptable entry, %p -> %p\n",
  //        (void *)original_address, (void *)translated_address);

  size_t entry_offset = AddTranslatedJump(module,
                                          target_module,
                                          original_address,
                                          translated_address,
                                          list_head_offset,
                                          instruction_address,
                                          global_indirect);

  // redirect execution to just created entry which should handle it immediately
  SetRegister(RIP, (size_t)module->instrumented_code_remote + entry_offset);

  return true;
}


// adds another observed original_target -> actual_target pair
// to the golbal jumptable at the appropriate location
size_t TinyInst::AddTranslatedJump(ModuleInfo *module,
                                   ModuleInfo *target_module,
                                   size_t original_target,
                                   size_t actual_target,
                                   size_t list_head_offset,
                                   size_t edge_start_address,
                                   bool global_indirect)
{
  size_t entry_offset = module->instrumented_code_allocated;

  size_t previous;
  size_t previous_offset;

  // gets the previous list head
  if (child_ptr_size == 8) {
    previous = (size_t)(*(uint64_t *)(module->instrumented_code_local + list_head_offset));
  }
  else {
    previous = *(uint32_t *)(module->instrumented_code_local + list_head_offset);
  }
  previous_offset = previous - (size_t)module->instrumented_code_remote;

  // cmp RAX, [original_target]
  if (child_ptr_size == 8) {
    WriteCode(module, CMP_RAX, sizeof(CMP_RAX));
  } else {
    WriteCode(module, CMP_EAX, sizeof(CMP_EAX));
  }
  size_t cmp_offset = module->instrumented_code_allocated;

  // je label
  WriteCode(module, JE, sizeof(JE));
  FixDisp4(module, sizeof(JMP));

  // jmp previous_list_head
  WriteCode(module, JMP, sizeof(JMP));
  FixDisp4(module, (int32_t)((int64_t)previous_offset -
                             (int64_t)module->instrumented_code_allocated));


  // (maybe) pop RBX
  // pop RAX
  // pop flags
  if (global_indirect) {
    WriteCode(module, POP_BAF, sizeof(POP_BAF));
  } else {
    WriteCode(module, POP_AF, sizeof(POP_AF));
  }

  if (sp_offset) {
    OffsetStack(module, sp_offset);
  }

  // consider indirect call/jump an edge and insert appropriate instrumentation
  InstrumentEdge(module, target_module, edge_start_address, original_target);

  // jmp [actual_target]
  WriteCode(module, JMP_MEM, sizeof(JMP_MEM));

  if (child_ptr_size == 8) {
    FixDisp4(module, (int32_t)child_ptr_size);
    *(int32_t *)(module->instrumented_code_local + cmp_offset - 4) =
      (int32_t)((int64_t)module->instrumented_code_allocated - (int64_t)cmp_offset);
  } else {
    FixDisp4(module, (int32_t)(GetCurrentInstrumentedAddress(module) + child_ptr_size));
    *(int32_t *)(module->instrumented_code_local + cmp_offset - 4) =
      (int32_t)GetCurrentInstrumentedAddress(module);
  }

  if (target_module && (module != target_module)) {
    CrossModuleLink link;
    link.module1 = module;
    link.module2 = target_module;
    link.offset1 = module->instrumented_code_allocated;
    link.offset2 = original_target - (size_t)target_module->min_address;
    // printf("Cross module link to %p\n", (void *)original_target);
    cross_module_links.push_back(link);
  }

  WritePointer(module, original_target);
  WritePointer(module, actual_target);

  // add to the head of the linked list
  if (child_ptr_size == 8) {
    *(uint64_t *)(module->instrumented_code_local + list_head_offset) =
      (uint64_t)((size_t)module->instrumented_code_remote + entry_offset);
  } else {
    *(uint32_t *)(module->instrumented_code_local + list_head_offset) =
      (uint32_t)((size_t)module->instrumented_code_remote + entry_offset);
  }

  CommitCode(module, list_head_offset, child_ptr_size);
  CommitCode(module, entry_offset, module->instrumented_code_allocated - entry_offset);

  return entry_offset;
}

TinyInst::IndirectInstrumentation TinyInst::ShouldInstrumentIndirect(
  ModuleInfo *module,
  xed_decoded_inst_t *xedd,
  size_t instruction_address)
{
  xed_category_enum_t category;
  category = xed_decoded_inst_get_category(xedd);

  xed_iclass_enum_t iclass;
  iclass = xed_decoded_inst_get_iclass(xedd);
 
  if (category == XED_CATEGORY_RET) {
    if (!patch_return_addresses) return II_NONE;
    if (iclass != XED_ICLASS_RET_NEAR) return II_NONE;
  } else {
    if ((iclass != XED_ICLASS_JMP) && (iclass != XED_ICLASS_CALL_NEAR)) return II_NONE;
  }

  if (indirect_instrumentation_mode != II_AUTO) {
    return indirect_instrumentation_mode;
  } else {
    // default to the most performant mode which is II_GLOBAL
    return II_GLOBAL;
  }
}

void TinyInst::InstrumentRet(ModuleInfo *module,
                             xed_decoded_inst_t *xedd,
                             size_t instruction_address,
                             IndirectInstrumentation mode,
                             size_t bb_address)
{
  // lots of moving around, but the problem is
  // we need to store context in the same place
  // where the return address is

  // at the end, the stack must be
  // saved RAX
  // saved EFLAGS
  // <sp_offset>
  // and RAX must contain return address

  // store rax to a safe offset
  int32_t ax_offset = -sp_offset - 2 * child_ptr_size;
  WriteStack(module, ax_offset);
  // copy return address to a safe offset
  int32_t ret_offset = ax_offset - child_ptr_size;
  ReadStack(module, 0);
  WriteStack(module, ret_offset);
  // get ret immediate
  int32_t imm = (int32_t)xed_decoded_inst_get_unsigned_immediate(xedd);
  // align the stack
  int32_t ret_pop = (int32_t)child_ptr_size + imm - sp_offset;
  OffsetStack(module, ret_pop); //pop
  ax_offset -= ret_pop;
  ret_offset -= ret_pop;
  // write data to stack
  WriteCode(module, PUSH_F, sizeof(PUSH_F));
  ax_offset += child_ptr_size;
  ret_offset += child_ptr_size;
  ReadStack(module, ax_offset);
  WriteCode(module, PUSH_A, sizeof(PUSH_A));
  ax_offset += child_ptr_size;
  ret_offset += child_ptr_size;
  ReadStack(module, ret_offset);
  InstrumentIndirect(module, xedd, instruction_address, mode, bb_address);
}

void TinyInst::InstrumentIndirect(ModuleInfo *module,
                                  xed_decoded_inst_t *xedd,
                                  size_t instruction_address,
                                  IndirectInstrumentation mode,
                                  size_t bb_address)
{
  if (mode == II_GLOBAL) {
    InstrumentGlobalIndirect(module, xedd, instruction_address);
  } else if (mode == II_LOCAL) {
    InstrumentLocalIndirect(module, xedd, instruction_address, bb_address);
  } else {
    FATAL("Unexpected IndirectInstrumentation value");
  }
}

// translates indirect jump or call
// using global jumptable
void TinyInst::InstrumentGlobalIndirect(ModuleInfo *module,
                                        xed_decoded_inst_t *xedd,
                                        size_t instruction_address)
{
  if (xed_decoded_inst_get_category(xedd) != XED_CATEGORY_RET) {

    if (sp_offset) {
      OffsetStack(module, -sp_offset);
    }

    // push eflags
    // push RAX
    // push RBX
    WriteCode(module, PUSH_FAB, sizeof(PUSH_FAB));

    int32_t stack_offset = sp_offset + 3 * child_ptr_size;

    if (xed_decoded_inst_get_category(xedd) == XED_CATEGORY_CALL) {
      stack_offset += child_ptr_size;
    }

    MovIndirectTarget(module, xedd, instruction_address, stack_offset);
  } else {
    // stack already set up, just push RBX
    WriteCode(module, PUSH_B, sizeof(PUSH_B));
  }

  // mov rbx, rax
  // and rbx, (JUMPTABLE_SIZE - 1) * child_ptr_size
  if (child_ptr_size == 8) {
    WriteCode(module, MOV_RBXRAX, sizeof(MOV_RBXRAX));
    WriteCode(module, AND_RBX, sizeof(AND_RBX));
  } else {
    WriteCode(module, MOV_EBXEAX, sizeof(MOV_EBXEAX));
    WriteCode(module, AND_EBX, sizeof(AND_EBX));
  }
  FixDisp4(module, (int32_t)((JUMPTABLE_SIZE - 1) * child_ptr_size));

  // add rbx, [jumptable_address]
  if (child_ptr_size == 8) {
    WriteCode(module, ADD_RBXRIPRELATIVE, sizeof(ADD_RBXRIPRELATIVE));
    FixDisp4(module, (int32_t)((int64_t)module->jumptable_address_offset - (int64_t)module->instrumented_code_allocated));
  } else {
    WriteCode(module, ADD_EBXRIPRELATIVE, sizeof(ADD_EBXRIPRELATIVE));
    FixDisp4(module, (int32_t)((size_t)module->instrumented_code_remote + module->jumptable_address_offset));
  }

  // jmp RBX
  WriteCode(module, JMP_B, sizeof(JMP_B));
}

// translates indirect jump or call
// using local jumptable
void TinyInst::InstrumentLocalIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address, size_t bb_address) {
  if (xed_decoded_inst_get_category(xedd) != XED_CATEGORY_RET) {
    if (sp_offset) {
      OffsetStack(module, -sp_offset);
    }


    // push eflags
    // push RAX
    WriteCode(module, PUSH_FA, sizeof(PUSH_FA));

    int32_t stack_offset = sp_offset + 2 * child_ptr_size;

    if (xed_decoded_inst_get_category(xedd) == XED_CATEGORY_CALL) {
      stack_offset += child_ptr_size;
    }

    MovIndirectTarget(module, xedd, instruction_address, stack_offset);
  } else {
    // stack already set up
  }

  // jmp [breakpoint]
  WriteCode(module, JMP_MEM, sizeof(JMP_MEM));

  size_t breakpoint_address = GetCurrentInstrumentedAddress(module);

  if (child_ptr_size == 8) {
    FixDisp4(module, 1);
  } else {
    FixDisp4(module, (int32_t)(breakpoint_address + 1));
  }

  // int3
  unsigned char breakpoint = 0xCC;
  WriteCode(module, &breakpoint, 1);
  module->br_indirect_newtarget_list[breakpoint_address]
    = { module->instrumented_code_allocated, bb_address };

  // breakpoint_address
  if (child_ptr_size == 8) {
    uint64_t address = (uint64_t)breakpoint_address;
    WriteCode(module, &address, sizeof(address));
  } else {
    uint32_t address = (uint32_t)breakpoint_address;
    WriteCode(module, &address, sizeof(address));
  }
}

// pushes return address on the target stack
void TinyInst::PushReturnAddress(ModuleInfo *module, uint64_t return_address) {
  // printf("retun address: %llx\n", return_address);
  // write the original return address
  OffsetStack(module, -(int)child_ptr_size);
  uint32_t return_lo = (uint32_t)(((uint64_t)return_address) & 0xFFFFFFFF);
  uint32_t return_hi = (uint32_t)(((uint64_t)return_address) >> 32);

  // mov dword ptr [sp], return_lo
  WriteCode(module, WRITE_SP_IMM, sizeof(WRITE_SP_IMM));
  *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4)
    = return_lo;

  if (child_ptr_size == 8) {
    // mov dword ptr [sp+4], return_hi
    WriteCode(module, WRITE_SP_4_IMM, sizeof(WRITE_SP_4_IMM));
    *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4)
      = return_hi;
  }
}

// checks if the instruction uses RIP-relative addressing,
// e.g. mov rax, [rip+displacement]; call [rip+displacement]
// and, if so, returns the memory address being referenced
bool TinyInst::IsRipRelative(ModuleInfo *module,
                             xed_decoded_inst_t *xedd,
                             size_t instruction_address,
                             size_t *mem_address)
{
  bool rip_relative = false;
  int64_t disp;

  uint32_t memops = xed_decoded_inst_number_of_memory_operands(xedd);

  for (uint32_t i = 0; i<memops; i++) {
    xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, i);
    switch (base) {
    case XED_REG_RIP:
    case XED_REG_EIP:
    case XED_REG_IP:
      rip_relative = true;
      disp = xed_decoded_inst_get_memory_displacement(xedd, i);
      break;
    default:
      break;
    }
  }

  if (!rip_relative) return false;

  size_t instruction_size = xed_decoded_inst_get_length(xedd);
  *mem_address = (size_t)(instruction_address + instruction_size + disp);

  return rip_relative;
}

// outputs instruction into the translated code buffer
// fixes stuff like rip-relative addressing
void TinyInst::FixInstructionAndOutput(ModuleInfo *module,
                                       xed_decoded_inst_t *xedd,
                                       unsigned char *input,
                                       unsigned char *input_address_remote,
                                       bool convert_call_to_jmp)
{
  size_t mem_address = 0;
  bool rip_relative = IsRipRelative(module, xedd, (size_t)input_address_remote, &mem_address);

  size_t original_instruction_size = xed_decoded_inst_get_length(xedd);

  bool needs_fixing = rip_relative || convert_call_to_jmp;

  // fast path
  // just copy instruction bytes without encoding
  if (!needs_fixing) {
    WriteCode(module, input, original_instruction_size);
    return;
  }

  unsigned int olen;
  xed_encoder_request_init_from_decode(xedd);
  xed_error_enum_t xed_error;
  unsigned char tmp[15];

  if (convert_call_to_jmp) {
    xed_encoder_request_set_iclass(xedd, XED_ICLASS_JMP);
  }

  if (!rip_relative) {
    xed_error = xed_encode(xedd, tmp, sizeof(tmp), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    WriteCode(module, tmp, olen);
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
  xed_encoder_request_set_memory_displacement(xedd, fixed_disp, 4);
  xed_error = xed_encode(xedd, tmp, sizeof(tmp), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  size_t out_instruction_size = olen;
  if ((module->instrumented_code_allocated + out_instruction_size) >
      module->instrumented_code_size)
  {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  instruction_end_addr = (size_t)module->instrumented_code_remote +
                         module->instrumented_code_allocated +
                         out_instruction_size;

  fixed_disp = (int64_t)(mem_address) - (int64_t)(instruction_end_addr);
  if (llabs(fixed_disp) > 0x7FFFFFFF) FATAL("Offset larger than 2G");
  xed_encoder_request_set_memory_displacement(xedd, fixed_disp, 4);
  xed_error = xed_encode(xedd, 
    (unsigned char *)(module->instrumented_code_local + module->instrumented_code_allocated),
    (uint32_t)(module->instrumented_code_size - module->instrumented_code_allocated),
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
void TinyInst::InvalidInstruction(ModuleInfo *module) {
  unsigned char breakpoint = 0xCC;
  size_t breakpoint_address = (size_t)module->instrumented_code_remote +
                              module->instrumented_code_allocated;
  WriteCode(module, &breakpoint, 1);
  module->invalid_instructions.insert(breakpoint_address);
  if (child_ptr_size == 8) {
    WriteCode(module, CRASH_64, sizeof(CRASH_64));
  } else {
    WriteCode(module, CRASH_32, sizeof(CRASH_32));
  }
}

void TinyInst::TranslateBasicBlock(char *address,
                                   ModuleInfo *module,
                                   set<char *> *queue,
                                   list<pair<uint32_t, uint32_t>> *offset_fixes)
{
  uint32_t original_offset = (uint32_t)((size_t)address - (size_t)(module->min_address));
  uint32_t translated_offset = (uint32_t)module->instrumented_code_allocated;

  // printf("Instrumenting bb, original at %p, instrumented at %p\n",
  //        address, module->instrumented_code_remote + translated_offset);

  module->basic_blocks.insert({ original_offset, translated_offset });

  AddressRange *range = GetRegion(module, (size_t)address);
  if (!range) {
    // just insert a jump to address
    WriteCode(module, JMP_MEM, sizeof(JMP_MEM));
    WritePointer(module, (size_t)address);
    return;
  }

  uint32_t range_offset = (uint32_t)((size_t)address - (size_t)range->from);
  size_t code_size = (uint32_t)((size_t)range->to - (size_t)address);
  char *code_ptr = range->data + range_offset;

  size_t offset = 0, last_offset = 0;

  xed_decoded_inst_t xedd;
  xed_error_enum_t xed_error;

  xed_state_t dstate;
  dstate.mmode = (xed_machine_mode_enum_t)xed_mmode;
  dstate.stack_addr_width = (xed_address_width_enum_t)child_ptr_size;

  xed_category_enum_t category;
  bool bbend = false;

  if (trace_basic_blocks) {
    unsigned char breakpoint = 0xCC;
    size_t breakpoint_address = (size_t)module->instrumented_code_remote +
                                module->instrumented_code_allocated;
    WriteCode(module, &breakpoint, 1);
    module->tracepoints[breakpoint_address] = (size_t)address;
  } else if (GetTargetMethodAddress()) {
    // hack, allow 1 byte of unused space at the beginning
    // of the target method. This is needed because we
    // are setting a brekpoint here. If this breakpoint falls
    // into code inserted by the client, and the client modifies
    // that code later, we loose the breakpoint.
    if(GetTargetMethodAddress() == address) {
      WriteCode(module, NOP, sizeof(NOP));
    }
  }

  // write pre-bb instrumentation
  InstrumentBasicBlock(module, (size_t)address);

  while (true) {
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_error = xed_decode(&xedd, 
                           (const unsigned char *)(code_ptr + offset),
                           (unsigned int)(code_size - offset));

    if (xed_error != XED_ERROR_NONE) break;

    size_t instruction_length = xed_decoded_inst_get_length(&xedd);

    // instruction-level-instrumentation
    InstructionResult instrumentation_result =
      InstrumentInstruction(module, &xedd, (size_t)address, (size_t)address + offset);

    switch (instrumentation_result) {
    case INST_HANDLED:
      offset += instruction_length;
      continue;
    case INST_STOPBB:
      return;
    case INST_NOTHANDLED:
    default:
      break;
    }

    category = xed_decoded_inst_get_category(&xedd);

    switch (category) {
    case XED_CATEGORY_CALL:
    case XED_CATEGORY_RET:
    case XED_CATEGORY_UNCOND_BR:
    case XED_CATEGORY_COND_BR:
      bbend = true;
      break;
    default:
      break;
    }

    last_offset = offset;
    offset += instruction_length;

    if (bbend) break;

    FixInstructionAndOutput(module,
                            &xedd,
                            (unsigned char *)(code_ptr + last_offset),
                            (unsigned char *)(address + last_offset));
  }

  if (!bbend) {
    // WARN("Could not find end of bb at %p.\n", address);
    InvalidInstruction(module);
    return;
  }

  if (category == XED_CATEGORY_RET) {

    IndirectInstrumentation ii_mode = ShouldInstrumentIndirect(module,
                                                               &xedd,
                                                               (size_t)address + last_offset);

    if (ii_mode != II_NONE) {
      InstrumentRet(module,
                    &xedd,
                    (size_t)address + last_offset,
                    ii_mode,
                    (size_t)address);
    } else {
      FixInstructionAndOutput(module,
                              &xedd,
                              (unsigned char *)(code_ptr + last_offset),
                              (unsigned char *)(address + last_offset));
    }

  } else if(category == XED_CATEGORY_COND_BR) {
    // j* target_address
    // gets instrumented as:
    //   j* label
    //   <edge instrumentation>
    //   jmp continue_address
    // label:
    //   <edge instrumentation>
    //   jmp target_address

    // must have an operand
    const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
    const xed_operand_t* op = xed_inst_operand(xi, 0);
    xed_operand_enum_t operand_name = xed_operand_name(op);

    if (operand_name != XED_OPERAND_RELBR) {
      FATAL("Error getting branch target");
    }

    int32_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
    uint32_t disp_width = xed_decoded_inst_get_branch_displacement_width(&xedd);
    if (disp_width == 0) {
      FATAL("Error getting branch target");
    }

    char* target_address1 = address + offset;
    char* target_address2 = address + offset + disp;

    if (GetModule((size_t)target_address2) != module) {
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
    xed_encoder_request_init_from_decode(&xedd);
    xed_encoder_request_set_branch_displacement(&xedd, fixed_disp, disp_width);
    xed_error = xed_encode(&xedd, encoded, sizeof(encoded), &olen);
    if (xed_error != XED_ERROR_NONE) {
      FATAL("Error encoding instruction");
    }
    jump_size = olen;
    size_t jump_start_offset = module->instrumented_code_allocated;
    WriteCode(module, encoded, jump_size);
    size_t jump_end_offset = module->instrumented_code_allocated;

    // instrument the 1st edge
    InstrumentEdge(module, module, (size_t)address, (size_t)target_address1);

    // jmp target_address1
    WriteCode(module, JMP, sizeof(JMP));

    FixOffsetOrEnqueue(module,
      (uint32_t)((size_t)target_address1 - (size_t)(module->min_address)),
      (uint32_t)(module->instrumented_code_allocated - 4),
      queue, offset_fixes);

    // time to fix that conditional jump offset
    if ((module->instrumented_code_allocated - jump_end_offset) != fixed_disp) {
      fixed_disp = (int32_t)(module->instrumented_code_allocated - jump_end_offset);
      xed_encoder_request_set_branch_displacement(&xedd, fixed_disp, disp_width);
      xed_error = xed_encode(&xedd, encoded, sizeof(encoded), &olen);
      if (xed_error != XED_ERROR_NONE) {
        FATAL("Error encoding instruction");
      }
      if (jump_size != olen) {
        FATAL("Instruction size changed?");
      }
      WriteCodeAtOffset(module, jump_start_offset, encoded, jump_size);
    }

    // instrument the 2nd edge
    InstrumentEdge(module, module, (size_t)address, (size_t)target_address2);

    // jmp target_address2
    WriteCode(module, JMP, sizeof(JMP));

    FixOffsetOrEnqueue(module,
      (uint32_t)((size_t)target_address2 - (size_t)(module->min_address)),
      (uint32_t)(module->instrumented_code_allocated - 4),
      queue, offset_fixes);

  } else if (category == XED_CATEGORY_UNCOND_BR) {
    // must have an operand
    const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
    const xed_operand_t* op = xed_inst_operand(xi, 0);

    xed_operand_enum_t operand_name = xed_operand_name(op);

    if (operand_name == XED_OPERAND_RELBR) {

      // jmp address
      // gets instrumented as:
      // jmp fixed_address

      int32_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
      uint32_t disp_width = xed_decoded_inst_get_branch_displacement_width(&xedd);
      if (disp_width == 0) {
        FATAL("Error getting branch target");
      }

      char *target_address = address + offset + disp;

      if (GetModule((size_t)target_address) != module) {
        WARN("Relative jump to a differen module in bb at %p\n", address);
        InvalidInstruction(module);
        return;
      }

      // jmp target_address
      WriteCode(module, JMP, sizeof(JMP));

      FixOffsetOrEnqueue(module,
        (uint32_t)((size_t)target_address - (size_t)(module->min_address)),
        (uint32_t)(module->instrumented_code_allocated - 4),
        queue, offset_fixes);

    } else {
      IndirectInstrumentation ii_mode =
        ShouldInstrumentIndirect(module,
                                 &xedd,
                                 (size_t)address + last_offset);

      if (ii_mode != II_NONE) {
        InstrumentIndirect(module,
                           &xedd,
                           (size_t)address + last_offset,
                           ii_mode,
                           (size_t)address);
      } else {
        FixInstructionAndOutput(module,
                                &xedd,
                                (unsigned char *)(code_ptr + last_offset),
                                (unsigned char *)(address + last_offset));
      }
    }

  } else if (category == XED_CATEGORY_CALL) {
    // must have an operand
    const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
    const xed_operand_t* op = xed_inst_operand(xi, 0);

    xed_operand_enum_t operand_name = xed_operand_name(op);

    if (operand_name == XED_OPERAND_RELBR) {
      // call target_address
      // gets instrumented as:
      //   call label
      //   jmp return_address
      // label:
      //   jmp target_address

      int32_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
      uint32_t disp_width = xed_decoded_inst_get_branch_displacement_width(&xedd);
      if (disp_width == 0) {
        FATAL("Error getting branch target");
      }

      char* return_address = address + offset;
      char *call_address = address + offset + disp;

      if (GetModule((size_t)call_address) != module) {
        WARN("Relative jump to a differen module in bb at %p\n", address);
        InvalidInstruction(module);
        return;
      }

      // fix the displacement and emit the call
      if (!patch_return_addresses) {
        unsigned char encoded[15];
        unsigned int olen;
        xed_encoder_request_init_from_decode(&xedd);
        xed_encoder_request_set_branch_displacement(&xedd, sizeof(JMP), disp_width);
        xed_error = xed_encode(&xedd, encoded, sizeof(encoded), &olen);
        if (xed_error != XED_ERROR_NONE) {
          FATAL("Error encoding instruction");
        }
        WriteCode(module, encoded, olen);

        // jmp return_address
        WriteCode(module, JMP, sizeof(JMP));

        FixOffsetOrEnqueue(module,
          (uint32_t)((size_t)return_address - (size_t)(module->min_address)),
          (uint32_t)(module->instrumented_code_allocated - 4),
          queue, offset_fixes);

        // jmp call_address
        WriteCode(module, JMP, sizeof(JMP));

        FixOffsetOrEnqueue(module,
          (uint32_t)((size_t)call_address - (size_t)(module->min_address)),
          (uint32_t)(module->instrumented_code_allocated - 4),
          queue, offset_fixes);

      } else {

        PushReturnAddress(module, (uint64_t)return_address);

        // jmp call_address
        WriteCode(module, JMP, sizeof(JMP));

        FixOffsetOrEnqueue(module,
          (uint32_t)((size_t)call_address - (size_t)(module->min_address)),
          (uint32_t)(module->instrumented_code_allocated - 4),
          queue, offset_fixes);

        // done, we don't need to do anything else as return gets redirected later
      }

    } else /* CALL, operand_name != XED_OPERAND_RELBR */ {
      char* return_address = address + offset;

      IndirectInstrumentation ii_mode =
        ShouldInstrumentIndirect(module,
                                 &xedd,
                                 (size_t)address + last_offset);

      if (ii_mode != II_NONE) {

        if (patch_return_addresses) {

          PushReturnAddress(module, (uint64_t)return_address);

          InstrumentIndirect(module,
                             &xedd,
                             (size_t)address + last_offset,
                             ii_mode,
                             (size_t)address);

        } else {
          //   call label
          //   jmp return_address
          //  label:
          //    <indirect instrumentation>

          WriteCode(module, CALL, sizeof(CALL));
          FixDisp4(module, sizeof(JMP));

          WriteCode(module, JMP, sizeof(JMP));

          FixOffsetOrEnqueue(module,
            (uint32_t)((size_t)return_address - (size_t)(module->min_address)),
            (uint32_t)(module->instrumented_code_allocated - 4),
            queue, offset_fixes);

          InstrumentIndirect(module,
                             &xedd,
                             (size_t)address + last_offset,
                             ii_mode,
                             (size_t)address);
        }

      } else {
        if (patch_return_addresses) {
          PushReturnAddress(module, (uint64_t)return_address);
          //xed_decoded_inst_t jmp;
          //CallToJmp(&xedd, &jmp);
          FixInstructionAndOutput(module,
                                  &xedd,
                                  (unsigned char *)(code_ptr + last_offset),
                                  (unsigned char *)(address + last_offset),
                                  true);
        } else {
          FixInstructionAndOutput(module,
                                  &xedd,
                                  (unsigned char *)(code_ptr + last_offset),
                                  (unsigned char *)(address + last_offset));

          WriteCode(module, JMP, sizeof(JMP));

          FixOffsetOrEnqueue(module,
            (uint32_t)((size_t)return_address - (size_t)(module->min_address)),
            (uint32_t)(module->instrumented_code_allocated - 4),
            queue,
            offset_fixes);
        }
      }
    }
  }
}

// starting from address, starts instrumenting code in the module
// any other basic blocks detected during instrumentation
// (e.g. jump, call targets) get added to the queue
// and instrumented as well
void TinyInst::TranslateBasicBlockRecursive(char *address, ModuleInfo *module) {
  set<char *> queue;
  list<pair<uint32_t, uint32_t>> offset_fixes;

  size_t code_size_before = module->instrumented_code_allocated;

  TranslateBasicBlock(address, module, &queue, &offset_fixes);

  while (!queue.empty()) {
    address = *queue.begin();
    TranslateBasicBlock(address, module, &queue, &offset_fixes);
    queue.erase(address);
  }

  for (auto iter = offset_fixes.begin(); iter != offset_fixes.end(); iter++) {
    uint32_t bb = iter->first;
    uint32_t jmp_offset = iter->second;

    auto bb_iter = module->basic_blocks.find(bb);
    if (bb_iter == module->basic_blocks.end()) {
      FATAL("Couldn't fix jump offset\n");
    }

    int32_t jmp_relative_offset = (int32_t)bb_iter->second - (int32_t)(jmp_offset + 4);
    *(int32_t *)(module->instrumented_code_local + jmp_offset) = jmp_relative_offset;
  }

  size_t code_size_after = module->instrumented_code_allocated;

  // Commit everything in one go here
  CommitCode(module, code_size_before, (code_size_after - code_size_before));
}

// gets ModuleInfo for the module specified by name
TinyInst::ModuleInfo *TinyInst::GetModuleByName(const char *name) {
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if (_stricmp(cur_module->module_name.c_str(), name) == 0) {
      return cur_module;
    }
  }

  return NULL;
}

// gets module corresponding to address
TinyInst::ModuleInfo *TinyInst::GetModule(size_t address) {
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if (!cur_module->loaded) continue;
    if (!cur_module->instrumented) continue;
    if ((address >= (size_t)cur_module->min_address) &&
        (address < (size_t)cur_module->max_address))
    {
      if (GetRegion(cur_module, address)) {
        return cur_module;
      }
    }
  }

  return NULL;
}

// gets a memory region corresponding to address
TinyInst::AddressRange *TinyInst::GetRegion(ModuleInfo *module, size_t address) {
  for (auto iter = module->executable_ranges.begin();
       iter != module->executable_ranges.end(); iter++)
  {
    AddressRange *cur_range = &(*iter);
    if (((size_t)address >= cur_range->from) && ((size_t)address < cur_range->to)) {
      return cur_range;
      break;
    }
  }

  return NULL;
}

// gets module where address falls into instrumented code buffer
TinyInst::ModuleInfo *TinyInst::GetModuleFromInstrumented(size_t address) {
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if (!cur_module->loaded) continue;
    if (!cur_module->instrumented) continue;
    if ((address >= (size_t)cur_module->instrumented_code_remote) &&
        (address < ((size_t)cur_module->instrumented_code_remote +
                    cur_module->instrumented_code_allocated)))
    {
      return cur_module;
      break;
    }
  }

  return NULL;
}

void TinyInst::OnCrashed(Exception *exception_record) {
  char *address = (char *)exception_record->ip;

  printf("Exception at address %p\n", address);
  if (exception_record->type == ACCESS_VIOLATION) {
    // printf("Access type: %d\n", (int)exception_record->ExceptionInformation[0]);
    printf("Access address: %p\n", exception_record->access_address);
  }

  ModuleInfo *module = GetModuleFromInstrumented((size_t)address);
  if (!module) return;

  printf("Exception in instrumented module %s\n", module->module_name.c_str());
  size_t offset = (size_t)address - (size_t)module->instrumented_code_remote;
  
  printf("Code before:\n");
  size_t offset_from;
  if (offset < 10) offset_from = 0;
  else offset_from = offset - 10;
  for (size_t i = offset_from; i < offset; i++) {
    printf("%02x ", (unsigned char)(module->instrumented_code_local[i]));
  }
  printf("Code after:\n");
  size_t offset_to = offset + 0x10;
  if (offset_to > module->instrumented_code_size)
    offset_to = module->instrumented_code_size;
  for (size_t i = offset; i < offset_to; i++) {
    printf("%02x ", (unsigned char)(module->instrumented_code_local[i]));
  }
}

// gets the address in the instrumented code corresponding to
// address in the original module
size_t TinyInst::GetTranslatedAddress(ModuleInfo *module, size_t address) {
  uint32_t offset = (uint32_t)(address - (size_t)module->min_address);
  uint32_t translated_offset;

  if (!GetRegion(module, address)) return address;

  auto iter = module->basic_blocks.find(offset);
  if (iter == module->basic_blocks.end()) {
    TranslateBasicBlockRecursive((char *)address, module);

    iter = module->basic_blocks.find(offset);
    if (iter == module->basic_blocks.end()) {
      FATAL("Can't find translated basic block");
    }
  }

  translated_offset = iter->second;

  return (size_t)module->instrumented_code_remote + translated_offset;
}

size_t TinyInst::GetTranslatedAddress(size_t address) {
  ModuleInfo *module = GetModule(address);
  if (!module) return address;
  if (!module->instrumented) return address;
  return GetTranslatedAddress(module, address);
}

// checks if address falls into one of the instrumented modules
// and if so, redirects execution to the translated code
bool TinyInst::TryExecuteInstrumented(char *address) {
  ModuleInfo *module = GetModule((size_t)address);

  if (!module) return false;
  if (!GetRegion(module, (size_t)address)) return false;

  if (trace_module_entries) {
    printf("TRACE: Entered module %s at address %p\n", module->module_name.c_str(), address);
  }

  size_t translated_address = GetTranslatedAddress(module, (size_t)address);
  OnModuleEntered(module, (size_t)address);

  SetRegister(RIP, translated_address);

  return true;
}

// clears all instrumentation data from module locally
// and if clear_remote_data is set, also in the remote process 
void TinyInst::ClearInstrumentation(ModuleInfo *module) {
  if (module->instrumented_code_remote) {
    RemoteFree(module->instrumented_code_remote,
               module->instrumented_code_size);
    module->instrumented_code_remote = NULL;
  }
  module->ClearInstrumentation();
  OnModuleUninstrumented(module);
  ClearCrossModuleLinks(module);
}

void TinyInst::InstrumentModule(ModuleInfo *module) {
  if (instrumentation_disabled) return;

  // if the module was previously instrumented
  // just reuse the same data
  if (persist_instrumentation_data && module->instrumented) {
    ProtectCodeRanges(&module->executable_ranges);
    FixCrossModuleLinks(module);
    printf("Module %s already instrumented, "
           "reusing instrumentation data\n",
           module->module_name.c_str());
    return;
  }

  ExtractCodeRanges(module->module_header,
                    module->min_address,
                    module->max_address,
                    &module->executable_ranges,
                    &module->code_size);

  // allocate buffer for instrumented code
  module->instrumented_code_size = module->code_size * CODE_SIZE_MULTIPLIER;
  if ((indirect_instrumentation_mode == II_GLOBAL) ||
      (indirect_instrumentation_mode == II_AUTO))
  {
    module->instrumented_code_size += child_ptr_size * JUMPTABLE_SIZE;
  }

  module->instrumented_code_allocated = 0;
  module->instrumented_code_local =
    (char *)malloc(module->instrumented_code_size);
  if (!module->instrumented_code_local) {
    FATAL("Error allocating local code buffer\n");
  }

  module->instrumented_code_remote =
    (char *)RemoteAllocateNear((uint64_t)module->min_address,
                               (uint64_t)module->max_address,
                               module->instrumented_code_size,
                               READEXECUTE);

  if (!module->instrumented_code_remote) {
    // TODO also try allocating after the module
    FATAL("Error allocating remote code buffer\n");
  }

  if ((indirect_instrumentation_mode == II_GLOBAL) ||
      (indirect_instrumentation_mode == II_AUTO))
  {
    InitGlobalJumptable(module);
  }

  module->instrumented = true;
  FixCrossModuleLinks(module);

  printf("Instrumented module %s, code size: %zd\n",
         module->module_name.c_str(), module->code_size);

  OnModuleInstrumented(module);
}

// walks the list of modules and instruments
// all loaded so far
void TinyInst::InstrumentAllLoadedModules() {
  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if (cur_module->module_header && cur_module->max_address) {
      if (!cur_module->loaded) continue;
      InstrumentModule(cur_module);
    }
  }
}

// should we instrument coverage for this module
TinyInst::ModuleInfo *TinyInst::IsInstrumentModule(char *module_name) {
  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++)
  {
    ModuleInfo *cur_module = *iter;
    if (_stricmp(module_name, cur_module->module_name.c_str()) == 0) {
      return cur_module;
    }
  }
  return NULL;
}

void TinyInst::OnInstrumentModuleLoaded(void *module, ModuleInfo *target_module) {
  if (target_module->instrumented &&
      target_module->module_header &&
      (target_module->module_header != (void *)module))
  {
    WARN("Instrumented module loaded on a different address than seen previously\n"
         "Module will need to be re-instrumented. Expect a drop in performance.");
    ClearInstrumentation(target_module);
  }

  target_module->module_header = (void *)module;
  GetImageSize(target_module->module_header,
               &target_module->min_address,
               &target_module->max_address);
  target_module->loaded = true;

  if (target_function_defined) {
    if (target_reached) InstrumentModule(target_module);
  } else if (child_entrypoint_reached) {
    InstrumentModule(target_module);
  }
}

// called when a potentialy interesting module gets loaded
void TinyInst::OnModuleLoaded(void *module, char *module_name) {
  Debugger::OnModuleLoaded(module, module_name);

  ModuleInfo *instrument_module = IsInstrumentModule(module_name);
  if (instrument_module) {
    OnInstrumentModuleLoaded(module, instrument_module);
  }
}

// called when a potentialy interesting module gets loaded
void TinyInst::OnModuleUnloaded(void *module) {
  Debugger::OnModuleUnloaded(module);

  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++)
  {
    ModuleInfo *cur_module = *iter;
    if (cur_module->module_header == (void *)module) {
      cur_module->loaded = false;
      if (!persist_instrumentation_data) {
        ClearInstrumentation(cur_module);
      }
      InvalidateCrossModuleLinks(cur_module);
    }
  }
}

void TinyInst::OnTargetMethodReached() {
  Debugger::OnTargetMethodReached();

  if (target_function_defined) InstrumentAllLoadedModules();
}

void TinyInst::OnEntrypoint() {
  Debugger::OnEntrypoint();

  if(!target_function_defined) InstrumentAllLoadedModules();
}


bool TinyInst::OnException(Exception *exception_record) {
  switch (exception_record->type)
  {
  case BREAKPOINT:
    if (HandleBreakpoint(exception_record->ip)) {
      return true;
    }
  case ACCESS_VIOLATION:
    if (exception_record->maybe_execute_violation) {
      // possibly we are trying to executed code in an instrumented module
      if (TryExecuteInstrumented((char *)exception_record->access_address)) {
        return true;
      }
    }
  default:
    break;
  }

  return false;
}

void TinyInst::OnProcessCreated() {
  Debugger::OnProcessCreated();

  if (child_ptr_size == 8) {
    xed_mmode = XED_MACHINE_MODE_LONG_64;
  } else {
    xed_mmode = XED_MACHINE_MODE_LEGACY_32;
  }
}

void TinyInst::OnProcessExit() {
  Debugger::OnProcessExit();

  // clear all instrumentation data
  for (auto iter = instrumented_modules.begin();
       iter != instrumented_modules.end(); iter++)
  {
    ModuleInfo *cur_module = *iter;
    cur_module->loaded = false;
    cur_module->ClearInstrumentation();
  }
  // clear cross-module links
  ClearCrossModuleLinks();
}

// initializes instrumentation from command line options
void TinyInst::Init(int argc, char **argv) {
  // init the debugger first
  Debugger::Init(argc, argv);

  instrumentation_disabled = false;

  patch_return_addresses = GetBinaryOption("-patch_return_addresses", argc, argv, false);
  instrument_cross_module_calls = GetBinaryOption("-instrument_cross_module_calls", argc, argv, true);
  persist_instrumentation_data = GetBinaryOption("-persist_instrumentation_data", argc, argv, true);

  trace_basic_blocks = GetBinaryOption("-trace_basic_blocks", argc, argv, false);
  trace_module_entries = GetBinaryOption("-trace_module_entries", argc, argv, false);

  sp_offset = GetIntOption("-stack_offset", argc, argv, 0);

  xed_tables_init();

  list <char *> module_names;
  GetOptionAll("-instrument_module", argc, argv, &module_names);
  for (auto iter = module_names.begin(); iter != module_names.end(); iter++) {
    ModuleInfo *new_module = new ModuleInfo();
    new_module->module_name = *iter;
    instrumented_modules.push_back(new_module);
  }

  char *option;

  indirect_instrumentation_mode = II_AUTO;
  option = GetOption("-indirect_instrumentation", argc, argv);
  if (option) {
    if (strcmp(option, "none") == 0)
      indirect_instrumentation_mode = II_NONE;
    else if (strcmp(option, "local") == 0)
      indirect_instrumentation_mode = II_LOCAL;
    else if (strcmp(option, "global") == 0)
      indirect_instrumentation_mode = II_GLOBAL;
    else if (strcmp(option, "auto") == 0)
      indirect_instrumentation_mode = II_AUTO;
    else
      FATAL("Unknown indirect instrumentation mode");
  }
}
