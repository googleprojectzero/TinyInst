#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include "windows.h"
#include "psapi.h"
#include "dbghelp.h"

#include <list>
using namespace std;

#include "common.h"
#include "liteinst.h"

extern "C" {
#include "xed/xed-interface.h"
}

unsigned char JMP[] = { 0xe9, 0x00, 0x00, 0x00, 0x00 };
unsigned char CALL[] = { 0xe8, 0x00, 0x00, 0x00, 0x00 };
unsigned char JMP_MEM[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };

unsigned char LEARSP[] = { 0x48, 0x8d, 0xa4, 0x24, 0x00, 0x00, 0x00, 0x00 };
unsigned char LEAESP[] = { 0x67, 0x8d, 0xa4, 0x24, 0x00, 0x00, 0x00, 0x00 };
unsigned char PUSH_FAB[] = { 0x9c, 0x50, 0x53 };
unsigned char PUSH_FA[] = { 0x9c, 0x50 };
unsigned char PUSH_F[] = { 0x9c };
unsigned char PUSH_A[] = { 0x50 };
unsigned char PUSH_B[] = { 0x53 };
unsigned char POP_BAF[] = { 0x5B, 0x58, 0x9d };
unsigned char POP_AF[] = { 0x58, 0x9d };
unsigned char POP_A[] = { 0x58 };
unsigned char AND_RBX[] = { 0x48, 0x81, 0xe3, 0x00, 0x00, 0x00, 0x00 };
unsigned char AND_EBX[] = { 0x81, 0xe3, 0x00, 0x00, 0x00, 0x00 };
unsigned char MOV_RBXRAX[] = { 0x48, 0x89, 0xC3 };
unsigned char MOV_EBXEAX[] = { 0x89, 0xC3 };
unsigned char ADD_RBXRIPRELATIVE[] = { 0x48, 0x03, 0x1D, 0x00, 0x00, 0x00, 0x00 };
unsigned char ADD_EBXRIPRELATIVE[] = { 0x48, 0x03, 0x1D, 0x00, 0x00, 0x00, 0x00 };
unsigned char JMP_B[] = { 0xFF, 0x23 };
unsigned char CMP_RAX[] = { 0x48, 0x3B, 0x05, 0x00, 0x00, 0x00, 0x00 };
unsigned char CMP_EAX[] = { 0x3B, 0x05, 0x00, 0x00, 0x00, 0x00 };
unsigned char JE[] = { 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 };

unsigned char WRITE_SP_IMM[] = { 0xC7, 0x04, 0x24, 0xAA, 0xAA, 0xAA, 0xAA };
unsigned char WRITE_SP_4_IMM[] = { 0xC7, 0x44, 0x24, 0x04, 0xAA, 0xAA, 0xAA, 0xAA };

unsigned char MOV_RAX_RSPMEM[] = { 0x48, 0x8B, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A };
unsigned char MOV_EAX_ESPMEM[] = { 0x8B, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A };

unsigned char MOV_RSPMEM_RAX[] = { 0x48, 0x89, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A };
unsigned char MOV_ESPMEM_EAX[] = { 0x89, 0x84, 0x24, 0xAA, 0xAA, 0xAA, 0x0A };

// Global jumptable for indirect jumps/calls.
// This is an array of size JUMPTABLE_SIZE where each entry initially
// points to indirect_breakpoint_address.
// When a new indirect jump/call target is detected, this will cause a breakpoint
// which will be resolved by adding a new entry into this hashtable.
void LiteInst::InitGlobalJumptable(ModuleInfo *module) {
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
void LiteInst::CommitCode(ModuleInfo *module, size_t start_offset, size_t size) {
  size_t size_written;
  if (!WriteProcessMemory(
    child_handle, 
    module->instrumented_code_remote + start_offset, 
    module->instrumented_code_local + start_offset, 
    size, 
    &size_written)) {
      FATAL("Error writing target memory\n");
  }
}

// Checks if there is sufficient space and writes code at the current offset
void LiteInst::WriteCode(ModuleInfo *module, void *data, size_t size) {
  if (module->instrumented_code_allocated + size > module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  memcpy(module->instrumented_code_local + module->instrumented_code_allocated, data, size);
  module->instrumented_code_allocated += size;
}

// Checks if there is sufficient space and writes code at the chosen offset
void LiteInst::WriteCodeAtOffset(ModuleInfo *module, size_t offset, void *data, size_t size) {
  if (offset + size > module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  memcpy(module->instrumented_code_local + offset, data, size);

  if (offset + size > module->instrumented_code_allocated) {
    module->instrumented_code_allocated = offset + size;
  }
}

void LiteInst::WritePointer(ModuleInfo *module, size_t value) {
  if (module->instrumented_code_allocated + child_ptr_size > module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  if (child_ptr_size == 8) {
    *(uint64_t *)(module->instrumented_code_local + module->instrumented_code_allocated) = (uint64_t)value;
  } else {
    *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated) = (uint32_t)value;
  }

  module->instrumented_code_allocated += child_ptr_size;
}

// fixes an offset in the jump instruction (at offset jmp_offset in the instrumented code)
// to jump to the given basic block (at offset bb in the original code)
// in case the basic block hasn't been instrumented yet, queues it for instrumentation
void LiteInst::FixOffsetOrEnqueue(ModuleInfo *module, uint32_t bb, uint32_t jmp_offset, std::set<char *> *queue, std::list<std::pair<uint32_t, uint32_t>> *offset_fixes) {
  auto iter = module->basic_blocks.find(bb);
  if (iter == module->basic_blocks.end()) {
    char *address = (char *)module->base + bb;
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
void LiteInst::OffsetStack(ModuleInfo *module, int32_t offset) {
  if (child_ptr_size == 8) {
    WriteCode(module, LEARSP, sizeof(LEARSP));
  } else {
    WriteCode(module, LEAESP, sizeof(LEAESP));
  }

  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = offset;
}

void LiteInst::ReadStack(ModuleInfo *module, int32_t offset) {
  if (child_ptr_size == 8) {
    WriteCode(module, MOV_RAX_RSPMEM, sizeof(MOV_RAX_RSPMEM));
  } else {
    WriteCode(module, MOV_EAX_ESPMEM, sizeof(MOV_EAX_ESPMEM));
  }
  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = offset;
}

void LiteInst::WriteStack(ModuleInfo *module, int32_t offset) {
  if (child_ptr_size == 8) {
    WriteCode(module, MOV_RSPMEM_RAX, sizeof(MOV_RSPMEM_RAX));
  } else {
    WriteCode(module, MOV_ESPMEM_EAX, sizeof(MOV_ESPMEM_EAX));
  }
  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = offset;
}



// converts an indirect jump/call into a MOV instruction
// which moves the target of the indirect call into the RAX/EAX reguster
// and writes this instruction into the code buffer
void LiteInst::MovIndirectTarget(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t original_address) {
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
    xed_encoder_request_set_base0(&mov, xed_decoded_inst_get_base_reg(xedd, 0));
    xed_encoder_request_set_seg0(&mov, xed_decoded_inst_get_seg_reg(xedd, 0));
    xed_encoder_request_set_index(&mov, xed_decoded_inst_get_index_reg(xedd, 0));
    xed_encoder_request_set_scale(&mov, xed_decoded_inst_get_scale(xedd, 0));
    xed_encoder_request_set_memory_displacement(&mov,
      xed_decoded_inst_get_memory_displacement(xedd, 0),
      xed_decoded_inst_get_memory_displacement_width(xedd, 0));
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
      (int64_t)((size_t)module->instrumented_code_remote + module->instrumented_code_allocated + out_instruction_size);
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

bool LiteInst::HandleBreakpoint(void *address, DWORD thread_id) {
  if (trace_basic_blocks) {
    auto iter = tracepoints.find((size_t)address);
    if (iter != tracepoints.end()) {

      printf("TRACE: Executing basic block, original at %p, instrumented at %p\n", (void *)iter->second, (void *)iter->first);

      return true;
    } else {
      printf("TRACE: Breakpoint\n");
    }
  }

  if (HandleIndirectJMPBreakpoint(address, thread_id)) return true;

  return false;
}

bool LiteInst::HandleIndirectJMPBreakpoint(void *address, DWORD thread_id) {
  if (indirect_instrumentation_mode == II_NONE) return false;

  ModuleInfo *module = GetModuleFromInstrumented((char *)address);
  if (!module) return false;

  bool is_indirect_breakpoint = false;
  bool global_indirect;

  size_t list_head_offset;

  if ((size_t)address == module->br_indirect_newtarget_global) {
    is_indirect_breakpoint = true;
    global_indirect = true;
  } else {
    auto iter = module->br_indirect_newtarget_list.find((size_t)address);
    if (iter != module->br_indirect_newtarget_list.end()) {
      is_indirect_breakpoint = true;
      global_indirect = false;
      list_head_offset = iter->second;
    }
  }

  if (!is_indirect_breakpoint) return false;

  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_ALL;
  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  GetThreadContext(thread_handle, &lcContext);

#ifdef _WIN64
  size_t original_address = lcContext.Rax;
#else
  size_t original_address = lcContext.Eax;
#endif

  // if it's a global indirect, list head must be calculated from target
  // otherwise it's a per-callsite indirect and the list head was set earlier
  if (global_indirect) {
    list_head_offset = module->jumptable_offset + original_address & ((JUMPTABLE_SIZE - 1) * child_ptr_size);
  }

  size_t translated_address;
  ModuleInfo *target_module = GetModule((char *)original_address);

  if (target_module == module) {
    translated_address = GetTranslatedAddress(module, original_address);
  } else if (target_module && instrument_cross_module_calls) {
    translated_address = GetTranslatedAddress(target_module, original_address);
  } else {
    translated_address = original_address;
  }

  // printf("Adding jumptable entry, %p -> %p\n", (void *)original_address, (void *)translated_address);

  size_t entry_offset = AddTranslatedJump(module, original_address, translated_address, list_head_offset, global_indirect);

  // redirect execution to just created entry which should handle it immediately
#ifdef _WIN64
  lcContext.Rip = (size_t)module->instrumented_code_remote + entry_offset;
#else
  lcContext.Eip = (size_t)module->instrumented_code_remote + entry_offset;
#endif

  SetThreadContext(thread_handle, &lcContext);
  CloseHandle(thread_handle);

  return true;
}


// adds another observed original_target -> actual_target pair
// to the golbal jumptable at the appropriate location
size_t LiteInst::AddTranslatedJump(ModuleInfo *module, size_t original_target, size_t actual_target, size_t list_head_offset, bool global_indirect) {
  size_t entry_offset = module->instrumented_code_allocated;

  size_t previous;
  size_t previous_offset;

  if (child_ptr_size == 8) {
    previous = *(uint64_t *)(module->instrumented_code_local + list_head_offset);
  }
  else {
    previous = *(uint32_t *)(module->instrumented_code_local + list_head_offset);
  }
  previous_offset = previous - (size_t)module->instrumented_code_remote;

  if (child_ptr_size == 8) {
    WriteCode(module, CMP_RAX, sizeof(CMP_RAX));
  } else {
    WriteCode(module, CMP_EAX, sizeof(CMP_EAX));
  }
  size_t cmp_offset = module->instrumented_code_allocated;

  // *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = sizeof(JE) + sizeof(JMP) + sizeof()

  WriteCode(module, JE, sizeof(JE));
  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = sizeof(JMP);

  WriteCode(module, JMP, sizeof(JMP));
  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) =
    (int32_t)((int64_t)previous_offset - (int64_t)module->instrumented_code_allocated);

  if (global_indirect) {
    WriteCode(module, POP_BAF, sizeof(POP_BAF));
  } else {
    WriteCode(module, POP_AF, sizeof(POP_AF));
  }

  if (sp_offset) {
    OffsetStack(module, sp_offset);
  }

  WriteCode(module, JMP_MEM, sizeof(JMP_MEM));
  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = (int32_t)child_ptr_size;
  *(int32_t *)(module->instrumented_code_local + cmp_offset - 4) = (int32_t)((int64_t)module->instrumented_code_allocated - (int64_t)cmp_offset);

  WritePointer(module, original_target);
  WritePointer(module, actual_target);

  // link
  if (child_ptr_size == 8) {
    *(uint64_t *)(module->instrumented_code_local + list_head_offset) = (uint64_t)((size_t)module->instrumented_code_remote + entry_offset);
  } else {
    *(uint32_t *)(module->instrumented_code_local + list_head_offset) = (uint32_t)((size_t)module->instrumented_code_remote + entry_offset);
  }

  CommitCode(module, list_head_offset, child_ptr_size);
  CommitCode(module, entry_offset, module->instrumented_code_allocated - entry_offset);

  return entry_offset;
}

LiteInst::IndirectInstrumentation LiteInst::ShouldInstrumentIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address) {
  if (indirect_instrumentation_mode != II_AUTO) {
    return indirect_instrumentation_mode;
  } else {
    // default to the most performant mode which is II_GLOBAL
    return II_GLOBAL;
  }

  // below is an attempt to not instrument indirect jump/calls that lead to
  // non-instrumented modules (e.g. imports)
  // however, this didn't result in better performance, hence commented out

  /*size_t mem_address = 0;

  // check if a target for an indirect jump appears outside of the current module
  // if so, don't instrument
  // intended to handle exports quickly
  if (IsRipRelative(module, xedd, instruction_address, &mem_address)) {
    uint64_t jump_target = 0;
    size_t size_read;

    if (!ReadProcessMemory(child_handle, (void *)mem_address, &jump_target, child_ptr_size, &size_read)) {
      FATAL("Error in ReadProcessMemory");
    }
    if (size_read != child_ptr_size) {
      FATAL("Error in ReadProcessMemory");
    }

    // no idea what it is yet
    if (jump_target == 0) return II_GLOBAL;

    ModuleInfo *target_module = GetModule((char *)jump_target);

    if (target_module == module) {
      return II_GLOBAL;
    } else if (target_module && instrument_cross_module_calls) {
      return II_GLOBAL;
    } else {
      // jump / call to another module, don't instrument
      // printf("none\n");
      return II_NONE;
    }
  }

  return II_GLOBAL; */
}

void LiteInst::InstrumentIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address, IndirectInstrumentation mode) {
  if (mode == II_GLOBAL) {
    InstrumentGlobalIndirect(module, xedd, instruction_address);
  } else if (mode == II_LOCAL) {
    InstrumentLocalIndirect(module, xedd, instruction_address);
  } else {
    FATAL("Unexpected IndirectInstrumentation value");
  }
}

// translates indirect jump or call
void LiteInst::InstrumentGlobalIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address) {
  if (xed_decoded_inst_get_category(xedd) != XED_CATEGORY_RET) {

    if (sp_offset) {
      OffsetStack(module, -sp_offset);
    }

    WriteCode(module, PUSH_FAB, sizeof(PUSH_FAB));

    MovIndirectTarget(module, xedd, instruction_address);
  } else {
    // stack already set up, just save B
    WriteCode(module, PUSH_B, sizeof(PUSH_B));
  }

  if (child_ptr_size == 8) {
    WriteCode(module, MOV_RBXRAX, sizeof(MOV_RBXRAX));
    WriteCode(module, AND_RBX, sizeof(AND_RBX));
  } else {
    WriteCode(module, MOV_EBXEAX, sizeof(MOV_EBXEAX));
    WriteCode(module, AND_EBX, sizeof(AND_EBX));
  }
  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4)
    = (int32_t)((JUMPTABLE_SIZE - 1) * child_ptr_size);

  if (child_ptr_size == 8) {
    WriteCode(module, ADD_RBXRIPRELATIVE, sizeof(ADD_RBXRIPRELATIVE));
  } else {
    WriteCode(module, ADD_EBXRIPRELATIVE, sizeof(ADD_EBXRIPRELATIVE));
  }
  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4)
    = (int32_t)((int64_t)module->jumptable_address_offset - (int64_t)module->instrumented_code_allocated);

  WriteCode(module, JMP_B, sizeof(JMP_B));
}

// translates indirect jump or call
void LiteInst::InstrumentLocalIndirect(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address) {
  if (xed_decoded_inst_get_category(xedd) != XED_CATEGORY_RET) {
    if (sp_offset) {
      OffsetStack(module, -sp_offset);
    }

    WriteCode(module, PUSH_FA, sizeof(PUSH_FA));

    MovIndirectTarget(module, xedd, instruction_address);
  } else {
    // stack already set up
  }

  WriteCode(module, JMP_MEM, sizeof(JMP_MEM));
  *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = 1;

  size_t breakpoint_address = (size_t)(module->instrumented_code_remote + module->instrumented_code_allocated);
  unsigned char breakpoint = 0xCC;
  WriteCode(module, &breakpoint, 1);
  module->br_indirect_newtarget_list[breakpoint_address] = module->instrumented_code_allocated;

  if (child_ptr_size == 8) {
    uint64_t address = (uint64_t)breakpoint_address;
    WriteCode(module, &address, sizeof(address));
  } else {
    uint32_t address = (uint32_t)breakpoint_address;
    WriteCode(module, &address, sizeof(address));
  }
}

void LiteInst::PushReturnAddress(ModuleInfo *module, uint64_t return_address) {
  // printf("retun address: %llx\n", return_address);
  // write the original return address
  OffsetStack(module, -(int)child_ptr_size);
  uint32_t return_lo = (uint32_t)(((uint64_t)return_address) & 0xFFFFFFFF);
  uint32_t return_hi = (uint32_t)(((uint64_t)return_address) >> 32);

  WriteCode(module, WRITE_SP_IMM, sizeof(WRITE_SP_IMM));
  *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = return_lo;

  if (child_ptr_size == 8) {
    WriteCode(module, WRITE_SP_4_IMM, sizeof(WRITE_SP_4_IMM));
    *(uint32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = return_hi;
  }
}

// checks if the instruction uses RIP-relative addressing,
// e.g. mov rax, [rip+displacement]; call [rip+displacement]
bool LiteInst::IsRipRelative(ModuleInfo *module, xed_decoded_inst_t *xedd, size_t instruction_address, size_t *mem_address) {
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
  *mem_address = instruction_address + instruction_size + disp;

  return rip_relative;
}

// outputs instruction into the translated code buffer
// fixes stuff like rip-relative addressing
void LiteInst::FixInstructionAndOutput(ModuleInfo *module, xed_decoded_inst_t *xedd, unsigned char *input, unsigned char *input_address_remote, bool convert_to_jmp) {
  size_t mem_address = 0;
  bool rip_relative = IsRipRelative(module, xedd, (size_t)input_address_remote, &mem_address);

  size_t original_instruction_size = xed_decoded_inst_get_length(xedd);

  bool needs_fixing = rip_relative || convert_to_jmp;

  // fast path
  if (!needs_fixing) {
    WriteCode(module, input, original_instruction_size);
    return;
  }

  unsigned int olen;
  xed_encoder_request_init_from_decode(xedd);
  xed_error_enum_t xed_error;
  unsigned char tmp[15];

  if (convert_to_jmp) {
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

  int64_t fixed_disp;

  // encode an instruction once just to get the instruction size
  // as it needs not be the original size
  fixed_disp = (int64_t)(mem_address) -
    (int64_t)((size_t)module->instrumented_code_remote + module->instrumented_code_allocated + original_instruction_size);
  xed_encoder_request_set_memory_displacement(xedd, fixed_disp, 4);
  xed_error = xed_encode(xedd, tmp, sizeof(tmp), &olen);
  if (xed_error != XED_ERROR_NONE) {
    FATAL("Error encoding instruction");
  }

  size_t out_instruction_size = olen;
  if ((module->instrumented_code_allocated + out_instruction_size) > module->instrumented_code_size) {
    FATAL("Insufficient memory allocated for instrumented code");
  }

  fixed_disp = (int64_t)(mem_address) -
    (int64_t)((size_t)module->instrumented_code_remote + module->instrumented_code_allocated + out_instruction_size);
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
  

bool LiteInst::TranslateBasicBlock(char *address, ModuleInfo *module, set<char *> *queue, list<pair<uint32_t, uint32_t>> *offset_fixes) {
  AddressRange *range;

  // printf("processing basic block %p, instrumented code size: %lld\n", address, module->instrumented_code_allocated);

  /*if ((size_t)address == 0x00007FFA8B4558D5) {
    bool test = true;
  }*/

  for (auto iter = module->executable_ranges.begin(); iter != module->executable_ranges.end(); iter++) {
    AddressRange *cur_range = &(*iter);
    if (((size_t)address >= cur_range->from) && ((size_t)address < cur_range->to)) {
      range = cur_range;
      break;
    }
  }

  if (!range) {
    FATAL("Address %p not found in any executable sections\n", address);
  }

  uint32_t range_offset = (uint32_t)((size_t)address - (size_t)range->from);
  size_t code_size = (uint32_t)((size_t)range->to - (size_t)address);
  char *code_ptr = range->data + range_offset;

  uint32_t original_offset = (uint32_t)((size_t)address - (size_t)(module->base));
  uint32_t translated_offset = (uint32_t)module->instrumented_code_allocated;

  char *translated_code = NULL;

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
    size_t breakpoint_address = (size_t)module->instrumented_code_remote + module->instrumented_code_allocated;
    WriteCode(module, &breakpoint, 1);
    tracepoints[breakpoint_address] = (size_t)address;
  }

  // write pre-bb instrumentation
  InstrumentBasicBlock(module, (size_t)address);

  while (true) {
    xed_decoded_inst_zero_set_mode(&xedd, &dstate);
    xed_error = xed_decode(&xedd, (const unsigned char *)(code_ptr + offset), (unsigned int)(code_size - offset));
    if (xed_error != XED_ERROR_NONE) break;

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
    offset += xed_decoded_inst_get_length(&xedd);

    if (bbend) break;

    FixInstructionAndOutput(module, &xedd, (unsigned char *)(code_ptr + last_offset), (unsigned char *)(address + last_offset));
  }

  if (!bbend) {
    // TODO
    FATAL("Decoder failed without finding the bb end");
  }

  if (category == XED_CATEGORY_RET) {

    bool should_patch_ret = patch_return_addresses;

    if (should_patch_ret) {
      xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xedd);
      if (iclass != XED_ICLASS_RET_NEAR) {
        should_patch_ret = false;
      }
    }

    if (should_patch_ret) {
      IndirectInstrumentation ii_mode = ShouldInstrumentIndirect(module, &xedd, (size_t)address + last_offset);
      if (ii_mode != II_NONE) {
        // lots of moving around, but the problem is
        // we need to store context in the same place
        // where the return address is

        // store rax to a safe offset
        int32_t ax_offset = -sp_offset - 2 * child_ptr_size;
        WriteStack(module, ax_offset);
        // copy return address to a safe offset
        int32_t ret_offset = ax_offset - child_ptr_size;
        ReadStack(module, 0);
        WriteStack(module, ret_offset);
        // get ret immediate
        int32_t imm = (int32_t)xed_decoded_inst_get_unsigned_immediate(&xedd);
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
        InstrumentIndirect(module, &xedd, (size_t)address + last_offset, ii_mode);
      } else {
        // just output returns normally
        FixInstructionAndOutput(module, &xedd, (unsigned char *)(code_ptr + last_offset), (unsigned char *)(address + last_offset));
      }
    } else {
      // just output returns normally
      FixInstructionAndOutput(module, &xedd, (unsigned char *)(code_ptr + last_offset), (unsigned char *)(address + last_offset));
    }

  } else if(category == XED_CATEGORY_COND_BR) {
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

    if (GetModule(target_address2) != module) {
      FATAL("Relative jump to a differen module?\n");
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
    InstrumentEdge(module, (size_t)address + last_offset, (size_t)target_address1);

    // jump to the actual location
    WriteCode(module, JMP, sizeof(JMP));

    FixOffsetOrEnqueue(module,
      (uint32_t)((size_t)target_address1 - (size_t)(module->base)),
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
    InstrumentEdge(module, (size_t)address + last_offset, (size_t)target_address2);

    // jump to the actual location
    WriteCode(module, JMP, sizeof(JMP));

    FixOffsetOrEnqueue(module,
      (uint32_t)((size_t)target_address2 - (size_t)(module->base)),
      (uint32_t)(module->instrumented_code_allocated - 4),
      queue, offset_fixes);

  } else if (category == XED_CATEGORY_UNCOND_BR) {
    // must have an operand
    const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
    const xed_operand_t* op = xed_inst_operand(xi, 0);

    xed_operand_enum_t operand_name = xed_operand_name(op);

    if (operand_name == XED_OPERAND_RELBR) {
      int32_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
      uint32_t disp_width = xed_decoded_inst_get_branch_displacement_width(&xedd);
      if (disp_width == 0) {
        FATAL("Error getting branch target");
      }

      char *target_address = address + offset + disp;

      if (GetModule(target_address) != module) {
        FATAL("Relative jump to a differen module?\n");
      }

      // jump to translated target address
      WriteCode(module, JMP, sizeof(JMP));

      FixOffsetOrEnqueue(module,
        (uint32_t)((size_t)target_address - (size_t)(module->base)),
        (uint32_t)(module->instrumented_code_allocated - 4),
        queue, offset_fixes);

    } else {
      IndirectInstrumentation ii_mode = ShouldInstrumentIndirect(module, &xedd, (size_t)address + last_offset);

      if (ii_mode != II_NONE) {
        InstrumentIndirect(module, &xedd, (size_t)address + last_offset, ii_mode);
      } else {
        FixInstructionAndOutput(module, &xedd, (unsigned char *)(code_ptr + last_offset), (unsigned char *)(address + last_offset));
      }
    }

  } else if (category == XED_CATEGORY_CALL) {
    // must have an operand
    const xed_inst_t* xi = xed_decoded_inst_inst(&xedd);
    const xed_operand_t* op = xed_inst_operand(xi, 0);

    xed_operand_enum_t operand_name = xed_operand_name(op);

    if (operand_name == XED_OPERAND_RELBR) {
      int32_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
      uint32_t disp_width = xed_decoded_inst_get_branch_displacement_width(&xedd);
      if (disp_width == 0) {
        FATAL("Error getting branch target");
      }

      char* return_address = address + offset;
      char *call_address = address + offset + disp;

      if (GetModule(call_address) != module) {
        FATAL("Relative call to a differen module?\n");
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

        // jump to bb after call continues
        WriteCode(module, JMP, sizeof(JMP));

        FixOffsetOrEnqueue(module,
          (uint32_t)((size_t)return_address - (size_t)(module->base)),
          (uint32_t)(module->instrumented_code_allocated - 4),
          queue, offset_fixes);

        // jump to translated code target
        WriteCode(module, JMP, sizeof(JMP));

        FixOffsetOrEnqueue(module,
          (uint32_t)((size_t)call_address - (size_t)(module->base)),
          (uint32_t)(module->instrumented_code_allocated - 4),
          queue, offset_fixes);

      } else {

        PushReturnAddress(module, (uint64_t)return_address);

        // jump to target
        WriteCode(module, JMP, sizeof(JMP));

        FixOffsetOrEnqueue(module,
          (uint32_t)((size_t)call_address - (size_t)(module->base)),
          (uint32_t)(module->instrumented_code_allocated - 4),
          queue, offset_fixes);

        // done, we don't need to do anything else as return gets redirected later
      }

    } else {
      char* return_address = address + offset;

      IndirectInstrumentation ii_mode = ShouldInstrumentIndirect(module, &xedd, (size_t)address + last_offset);

      if (ii_mode != II_NONE) {

        if (patch_return_addresses) {

          PushReturnAddress(module, (uint64_t)return_address);

          InstrumentIndirect(module, &xedd, (size_t)address + last_offset, ii_mode);

        } else {
          WriteCode(module, CALL, sizeof(CALL));
          *(int32_t *)(module->instrumented_code_local + module->instrumented_code_allocated - 4) = sizeof(JMP);

          WriteCode(module, JMP, sizeof(JMP));

          FixOffsetOrEnqueue(module,
            (uint32_t)((size_t)return_address - (size_t)(module->base)),
            (uint32_t)(module->instrumented_code_allocated - 4),
            queue, offset_fixes);

          InstrumentIndirect(module, &xedd, (size_t)address + last_offset, ii_mode);
        }

      } else {
        if (patch_return_addresses) {
          PushReturnAddress(module, (uint64_t)return_address);
          //xed_decoded_inst_t jmp;
          //CallToJmp(&xedd, &jmp);
          FixInstructionAndOutput(module, &xedd, (unsigned char *)(code_ptr + last_offset), (unsigned char *)(address + last_offset), true);
        } else {
          FixInstructionAndOutput(module, &xedd, (unsigned char *)(code_ptr + last_offset), (unsigned char *)(address + last_offset));

          WriteCode(module, JMP, sizeof(JMP));

          FixOffsetOrEnqueue(module,
            (uint32_t)((size_t)return_address - (size_t)(module->base)),
            (uint32_t)(module->instrumented_code_allocated - 4),
            queue, offset_fixes);
        }
      }
    }
  }

  module->basic_blocks.insert({ original_offset, translated_offset });

  return true;
}

bool LiteInst::TranslateBasicBlockRecursive(char *address, ModuleInfo *module) {
  set<char *> queue;
  list<pair<uint32_t, uint32_t>> offset_fixes;

  size_t code_size_before = module->instrumented_code_allocated;

  if (!TranslateBasicBlock(address, module, &queue, &offset_fixes)) {
    return false;
  }

  while (!queue.empty()) {
    address = *queue.begin();
    if (!TranslateBasicBlock(address, module, &queue, &offset_fixes)) {
      FATAL("Error translating %p", address);
    }
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

  return true;
}

LiteInst::ModuleInfo *LiteInst::GetModule(char *address) {
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if ((address >= cur_module->base) && (address < (char *)cur_module->base + cur_module->size)) {
      return cur_module;
      break;
    }
  }

  return NULL;
}

LiteInst::ModuleInfo *LiteInst::GetModuleFromInstrumented(char *address) {
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if ((address >= cur_module->instrumented_code_remote) && 
      (address < cur_module->instrumented_code_remote + cur_module->instrumented_code_allocated)) {
      return cur_module;
      break;
    }
  }

  return NULL;
}

void LiteInst::Debug(EXCEPTION_RECORD *exception_record) {
  char *address = (char *)exception_record->ExceptionAddress;
  ModuleInfo *module = NULL;
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if ((address >= cur_module->instrumented_code_remote) && (address < (char *)cur_module->instrumented_code_remote + cur_module->instrumented_code_size)) {
      module = cur_module;
      break;
    }
  }

  if (!module) return;

  printf("Exception in instrumented module %s\n", module->module_name);
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

size_t LiteInst::GetTranslatedAddress(ModuleInfo *module, size_t address) {
  uint32_t offset = (uint32_t)(address - (size_t)module->base);
  uint32_t translated_offset;

  auto iter = module->basic_blocks.find(offset);
  if (iter == module->basic_blocks.end()) {
    if (!TranslateBasicBlockRecursive((char *)address, module)) return false;

    iter = module->basic_blocks.find(offset);
    if (iter == module->basic_blocks.end()) {
      FATAL("Can't find translated basic block???");
    }
  }

  translated_offset = iter->second;

  return (size_t)module->instrumented_code_remote + translated_offset;
}


bool LiteInst::TryExecuteInstrumented(char *address, DWORD thread_id) {
  ModuleInfo *module = GetModule(address);

  if (!module) return false;

  if (trace_module_entries) {
    printf("TRACE: Entered module %s at address %p\n", module->module_name, address);
  }

  size_t translated_address = GetTranslatedAddress(module, (size_t)address);

  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_ALL;
  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  GetThreadContext(thread_handle, &lcContext);

  // redirect execution to translated code
#ifdef _WIN64
  lcContext.Rip = translated_address;
#else
  lcContext.Eip = translated_address;
#endif

  SetThreadContext(thread_handle, &lcContext);
  CloseHandle(thread_handle);

  return true;
}

void LiteInst::InstrumentModule(ModuleInfo *module) {
  LPCVOID end_address = (char *)module->base + module->size;
  LPCVOID cur_address = module->base;
  MEMORY_BASIC_INFORMATION meminfobuf;

  AddressRange newRange;

  // TODO: do we need to redo this if module was loaded before
  for (auto iter = module->executable_ranges.begin(); iter != module->executable_ranges.end(); iter++) {
    free(iter->data);
  }
  module->executable_ranges.clear();
  module->code_size = 0;

  while (cur_address < end_address) {
    size_t ret = VirtualQueryEx(child_handle, cur_address, &meminfobuf, sizeof(MEMORY_BASIC_INFORMATION));
    if (!ret) break;

    if (meminfobuf.Protect & 0xF0) {
      // printf("%p, %llx, %lx\n", meminfobuf.BaseAddress, meminfobuf.RegionSize, meminfobuf.Protect);

      size_t size_read;
      newRange.data = (char *)malloc(meminfobuf.RegionSize);
      if (!ReadProcessMemory(child_handle, meminfobuf.BaseAddress, newRange.data, meminfobuf.RegionSize, &size_read)) {
        FATAL("Error in ReadProcessMemory");
      }
      if (size_read != meminfobuf.RegionSize) {
        FATAL("Error in ReadProcessMemory");
      }

      uint8_t low = meminfobuf.Protect & 0xFF;
      low = low >> 4;
      DWORD newProtect = (meminfobuf.Protect & 0xFFFFFF00) + low;
      DWORD oldProtect;
      if (!VirtualProtectEx(child_handle, meminfobuf.BaseAddress, meminfobuf.RegionSize, newProtect, &oldProtect)) {
        FATAL("Error in VirtualProtectEx");
      }

      newRange.from = (size_t)meminfobuf.BaseAddress;
      newRange.to = (size_t)meminfobuf.BaseAddress + meminfobuf.RegionSize;
      module->executable_ranges.push_back(newRange);

      module->code_size += newRange.to - newRange.from;
    }

    cur_address = (char *)meminfobuf.BaseAddress + meminfobuf.RegionSize;
  }

  if (module->instrumented_code_size) {
    FATAL("Module was already loaded, TODO\n");
  }

  // Alternative, but requires Windows 10
  /* module->instrumented_code_size = module->code_size * 2;
  module->mapping = CreateFileMapping(
    INVALID_HANDLE_VALUE,
    NULL,
    PAGE_EXECUTE_READWRITE,
    0,
    module->instrumented_code_size,
    NULL);
  if (!module->mapping) {
    FATAL("CreateFileMapping error\n");
  }
  MapViewOfFile2(...); */

  module->instrumented_code_size = module->code_size * CODE_SIZE_MULTIPLIER;
  if ((indirect_instrumentation_mode == II_GLOBAL) || (indirect_instrumentation_mode == II_AUTO)) {
    module->instrumented_code_size += child_ptr_size * JUMPTABLE_SIZE;
  }

  module->instrumented_code_allocated = 0;
  module->instrumented_code_local = (char *)VirtualAlloc(NULL, module->instrumented_code_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!module->instrumented_code_local) {
    FATAL("Error allocating local code buffer\n");
  }

  module->instrumented_code_remote = NULL;
  // find a convenient spot for the module
  // must be <2GB away from the original code
  uint64_t min_code = (uint64_t)module->base + module->size;
  if (min_code < 0x80000000) min_code = 0;
  else min_code -= 0x80000000;
  uint64_t max_code = (uint64_t)module->base;
  if (max_code < module->instrumented_code_size) max_code = 0;
  else max_code -= module->instrumented_code_size;
  // try as close as possible
  uint64_t cur_code = max_code;
  while (cur_code > min_code) {
    // Don't attempt allocating on the null page
    if (cur_code < 0x1000) break;

    size_t step = module->instrumented_code_size;

    size_t ret = VirtualQueryEx(child_handle, (LPCVOID)cur_code, &meminfobuf, sizeof(MEMORY_BASIC_INFORMATION));
    if (!ret) break;

    if (meminfobuf.State == MEM_FREE) {
      if (meminfobuf.RegionSize >= module->instrumented_code_size) {
        size_t address = (size_t)meminfobuf.BaseAddress + (meminfobuf.RegionSize - module->instrumented_code_size);
        module->instrumented_code_remote = (char *)VirtualAllocEx(child_handle, (LPVOID)address, module->instrumented_code_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
        if (module->instrumented_code_remote) {
          if (((size_t)module->instrumented_code_remote >= min_code) &&
            ((size_t)module->instrumented_code_remote <= max_code)) {
            break;
          } else {
            FATAL("Error allocating remote code buffer\n");
          }
        }
      } else {
        step = module->instrumented_code_size - meminfobuf.RegionSize;
      }
    }

    cur_code = (size_t)meminfobuf.BaseAddress;
    if (cur_code < step) break;
    else cur_code -= step;
  }
  if (!module->instrumented_code_remote) {
    // TODO also try allocating after the module
    FATAL("Error allocating remote code buffer\n");
  }

  if ((indirect_instrumentation_mode == II_GLOBAL) || (indirect_instrumentation_mode == II_AUTO)) {
    InitGlobalJumptable(module);
  }

  module->instrumented = true;

  printf("Done instrumenting %s, ranges: %lld\n", module->module_name, module->executable_ranges.size());
}

void LiteInst::InstrumentAllLoadedModules() {
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if (cur_module->base && cur_module->size) {
      InstrumentModule(cur_module);
    }
  }
}

// should we collect coverage for this module
LiteInst::ModuleInfo *LiteInst::IsInstrumentModule(char *module_name) {
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if (_stricmp(module_name, cur_module->module_name) == 0) {
      return cur_module;
    }
  }
  return NULL;
}

void LiteInst::OnInstrumentModuleLoaded(HMODULE module, ModuleInfo *target_module) {
  target_module->base = (void *)module;
  target_module->size = GetImageSize(target_module->base);
  target_module->loaded = true;
}

// called when a potentialy interesting module gets loaded
void LiteInst::OnModuleLoaded(HMODULE module, char *module_name) {
  Debugger::OnModuleLoaded(module, module_name);

  ModuleInfo *coverage_module = IsInstrumentModule(module_name);
  if (coverage_module) {
    OnInstrumentModuleLoaded(module, coverage_module);

    if (persist_target_reached) InstrumentModule(coverage_module);
  }
}

// called when a potentialy interesting module gets loaded
void LiteInst::OnModuleUnloaded(HMODULE module) {
  Debugger::OnModuleUnloaded(module);

  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if (cur_module->base == (void *)module) {
      cur_module->loaded = false;
    }
  }
}

void LiteInst::OnPersistMethodReached(DWORD thread_id) {
  Debugger::OnPersistMethodReached(thread_id);

  InstrumentAllLoadedModules();
}

bool LiteInst::OnException(EXCEPTION_RECORD *exception_record, DWORD thread_id) {
  switch (exception_record->ExceptionCode)
  {
  case EXCEPTION_BREAKPOINT:
  case 0x4000001f: //STATUS_WX86_BREAKPOINT
    if (HandleBreakpoint(exception_record->ExceptionAddress, thread_id)) {
      return true;
    }
  case EXCEPTION_ACCESS_VIOLATION:
    if (exception_record->ExceptionInformation[0] == 8) {
      if (TryExecuteInstrumented((char *)exception_record->ExceptionInformation[1], thread_id)) {
        return true;
      }
    }
  default:
    break;
  }

  return false;
}

void LiteInst::OnProcessCreated(CREATE_PROCESS_DEBUG_INFO *info) {
  if (child_ptr_size == 8) {
    xed_mmode = XED_MACHINE_MODE_LONG_64;
  } else {
    xed_mmode = XED_MACHINE_MODE_LEGACY_32;
  }
}

void LiteInst::Init(int argc, char **argv) {
  // init the debugger first
  Debugger::Init(argc, argv);

  indirect_instrumentation_mode = II_AUTO;
  patch_return_addresses = false;
  instrument_cross_module_calls = true; // TODO: handle this when modules get undloaded

  trace_basic_blocks = false;
  trace_module_entries = false;

  sp_offset = 0;

  xed_tables_init();

  list <char *> module_names;
  GetOptionAll("-coverage_module", argc, argv, &module_names);
  for (auto iter = module_names.begin(); iter != module_names.end(); iter++) {
    ModuleInfo *new_module = new ModuleInfo;
    new_module->base = NULL;
    new_module->size = 0;
    new_module->loaded = false;
    new_module->instrumented = false;
    strncpy(new_module->module_name, *iter, MAX_PATH);
    instrumented_modules.push_back(new_module);
  }

  char *option;

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

  option = GetOption("-stack_offset", argc, argv);
  if (option) sp_offset = strtoul(option, NULL, 0);
}
