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
#include <algorithm>

#include <list>

#include "tinyinst.h"
#include "hook.h"

#ifdef ARM64
  #include "arch/arm64/arm64_assembler.h"
#else
  #include "arch/x86/x86_assembler.h"
#endif
#if defined(__APPLE__) && defined(ARM64)
  #include <set>
  #include "macOS/dyld_cache_map_parser.h"
#endif

ModuleInfo::ModuleInfo() {
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
  unwind_data = NULL;
}

void ModuleInfo::ClearInstrumentation() {
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
  address_map.clear();

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

  assembler_->Breakpoint(module);

  size_t code_size_after = module->instrumented_code_allocated;

  CommitCode(module, code_size_before, (code_size_after - code_size_before));
}

// gets the current code address in the instrumented code
// *in the child process*
size_t TinyInst::GetCurrentInstrumentedAddress(ModuleInfo *module) {
  return (size_t)module->instrumented_code_remote + module->instrumented_code_allocated;
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

// fixes an offset in the jump instruction (at offset jmp_offset in the
// instrumented code) to jump to the given basic block (at offset bb in the
// original code) in case the basic block hasn't been instrumented yet, queues
// it for instrumentation
void TinyInst::FixOffsetOrEnqueue(
    ModuleInfo *module,
    uint32_t bb,
    uint32_t jmp_offset,
    std::set<char *> *queue,
    std::list<std::pair<uint32_t, uint32_t>> *offset_fixes) {
  auto iter = module->basic_blocks.find(bb);
  if (iter == module->basic_blocks.end()) {
    char *address = (char *)module->min_address + bb;
    if (queue->find(address) == queue->end()) {
      queue->insert(address);
    }
    offset_fixes->push_back({bb, jmp_offset});
  } else {
    assembler_->FixOffset(module, jmp_offset, iter->second);
  }
}

// various breakpoints
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

  if(unwind_generator->HandleBreakpoint(module, address)) {
    return true;
  }
  
  for(auto iter = hooks.begin(); iter != hooks.end(); iter++) {
    if((*iter)->HandleBreakpoint(module, address)) return true;
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

  IndirectBreakpoinInfo bp_info = {};
  if ((size_t)address == module->br_indirect_newtarget_global) {
    is_indirect_breakpoint = true;
    global_indirect = true;
  } else {
    auto iter = module->br_indirect_newtarget_list.find((size_t)address);
    if (iter != module->br_indirect_newtarget_list.end()) {
      is_indirect_breakpoint = true;
      global_indirect = false;
      bp_info = iter->second;
      list_head_offset = iter->second.list_head;
    }
  }
  if (!is_indirect_breakpoint) return false;

  size_t original_address = GetRegister(ORIG_ADDR_REG);

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
                                          bp_info,
                                          global_indirect);

  size_t continue_address = (size_t)module->instrumented_code_remote + entry_offset;

  if (target_module) {
    continue_address = unwind_generator->MaybeRedirectExecution(target_module, continue_address);
  }

  // redirect execution to just created entry which should handle it immediately
  SetRegister(ARCH_PC, continue_address);
  return true;
}


// adds another observed original_target -> actual_target pair
// to the golbal jumptable at the appropriate location
size_t TinyInst::AddTranslatedJump(ModuleInfo *module,
                                   ModuleInfo *target_module,
                                   size_t original_target,
                                   size_t actual_target,
                                   size_t list_head_offset,
                                   IndirectBreakpoinInfo& breakpoint_info,
                                   bool global_indirect) {
  size_t entry_offset = module->instrumented_code_allocated;

  size_t previous;
  size_t previous_offset;

  // gets the previous list head
  if (child_ptr_size == 8) {
    previous = (size_t)
      (*(uint64_t *)(module->instrumented_code_local + list_head_offset));
  } else {
    previous =
        *(uint32_t *)(module->instrumented_code_local + list_head_offset);
  }
  previous_offset = previous - (size_t)module->instrumented_code_remote;

  assembler_->TranslateJmp(module,
                           target_module,
                           original_target,
                           breakpoint_info,
                           global_indirect,
                           previous_offset);

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
  CommitCode(module,
             entry_offset,
             module->instrumented_code_allocated - entry_offset);

  return entry_offset;
}

TinyInst::IndirectInstrumentation TinyInst::ShouldInstrumentIndirect(
  ModuleInfo *module,
  Instruction& inst,
  size_t instruction_address) {

  if (inst.iclass == InstructionClass::RET) {
    if (!patch_return_addresses) {
      return II_NONE;
    }
  } else {
    if ((inst.iclass != InstructionClass::IJUMP) &&
        (inst.iclass != InstructionClass::ICALL))
      return II_NONE;
  }

  if (indirect_instrumentation_mode != II_AUTO) {
    return indirect_instrumentation_mode;
  } else {
    // default to the most performant mode which is II_GLOBAL
#ifdef ARM64
    return II_LOCAL;
#else
    return II_GLOBAL;
#endif
  }
}

// when an invalid instruction is encountered
// emit a breakpoint followed by crashing the process
void TinyInst::InvalidInstruction(ModuleInfo *module) {
  size_t breakpoint_address = (size_t)module->instrumented_code_remote +
                              module->instrumented_code_allocated;
  assembler_->Breakpoint(module);
  module->invalid_instructions.insert(breakpoint_address);
  assembler_->Crash(module);
}

void TinyInst::InstrumentIndirect(ModuleInfo *module,
                                  Instruction& inst,
                                  size_t instruction_address,
                                  IndirectInstrumentation mode,
                                  size_t bb_address)
{
  if (mode == II_GLOBAL) {
    assembler_->InstrumentGlobalIndirect(module, inst, instruction_address);
  } else if (mode == II_LOCAL) {
    assembler_->InstrumentLocalIndirect(module, inst, instruction_address, bb_address);
  } else {
    FATAL("Unexpected IndirectInstrumentation value");
  }
}

void TinyInst::TranslateBasicBlock(char *address,
                                   ModuleInfo *module,
                                   std::set<char *> *queue,
                                   std::list<std::pair<uint32_t, uint32_t>> *offset_fixes) {
  uint32_t original_offset = (uint32_t)((size_t)address - (size_t)(module->min_address));
  uint32_t translated_offset = (uint32_t)module->instrumented_code_allocated;

  unwind_generator->OnBasicBlockStart(module,
    (size_t)address,
    GetCurrentInstrumentedAddress(module));

  // printf("Instrumenting bb, original at %p, instrumented at %p\n",
  //        address, module->instrumented_code_remote + translated_offset);

  module->basic_blocks.insert({ original_offset, translated_offset });

  AddressRange *range = GetRegion(module, (size_t)address);
  if (!range) {
    // just insert a jump to address
    assembler_->JmpAddress(module, (size_t)address);
    return;
  }

  uint32_t range_offset = (uint32_t)((size_t)address - (size_t)range->from);
  size_t code_size = (uint32_t)((size_t)range->to - (size_t)address);
  char *code_ptr = range->data + range_offset;

  size_t offset = 0, last_offset = 0;

  if (trace_basic_blocks) {
    size_t breakpoint_address = GetCurrentInstrumentedAddress(module);
    assembler_->Breakpoint(module);
    module->tracepoints[breakpoint_address] = (size_t)address;
  } else if (GetTargetMethodAddress()) {
    // hack, allow 1 or 4 byte of unused space at the beginning
    // of the target method. This is needed because we
    // are setting a brekpoint here. If this breakpoint falls
    // into code inserted by the client, and the client modifies
    // that code later, we loose the breakpoint.
    if(GetTargetMethodAddress() == address) {
      assembler_->Nop(module);
    }
  }

  // write pre-bb instrumentation
  InstrumentBasicBlock(module, (size_t)address);

  Instruction inst;
  while (true) {
    bool success =
      assembler_->DecodeInstruction(
        inst,
        (const unsigned char *)(code_ptr + offset),
        (unsigned int)(code_size - offset));

    if (!success) break;

    unwind_generator->OnInstruction(module,
      (size_t)address + offset,
      GetCurrentInstrumentedAddress(module));

    if(full_address_map) {
      size_t original_address = (size_t)address + offset;
      size_t instrumented_address = GetCurrentInstrumentedAddress(module);
      module->address_map[instrumented_address] = original_address;
    }
    
    // instruction-level-instrumentation
    InstructionResult instrumentation_result =
      InstrumentInstruction(module, inst, (size_t)address, (size_t)address + offset);

    switch (instrumentation_result) {
    case INST_HANDLED:
      offset += inst.length;
      continue;
    case INST_STOPBB:
      unwind_generator->OnBasicBlockEnd(module,
        (size_t)address + offset + inst.length,
        GetCurrentInstrumentedAddress(module));
      return;
    case INST_NOTHANDLED:
    default:
      break;
    }

    last_offset = offset;
    offset += inst.length;

    if (inst.bbend) break;

    assembler_->FixInstructionAndOutput(module, inst, (const unsigned char *)(code_ptr + last_offset), (const unsigned char *)(address + last_offset));
  }

  if (!inst.bbend) {
    // WARN("Could not find end of bb at %p.\n", address);
    InvalidInstruction(module);
    unwind_generator->OnBasicBlockEnd(module,
      (size_t)address + offset,
      GetCurrentInstrumentedAddress(module));
    return;
  }

  assembler_->HandleBasicBlockEnd(address, module, queue, offset_fixes, inst, code_ptr, offset, last_offset);
  unwind_generator->OnBasicBlockEnd(module,
    (size_t)address + offset,
    GetCurrentInstrumentedAddress(module));
}

// starting from address, starts instrumenting code in the module
// any other basic blocks detected during instrumentation
// (e.g. jump, call targets) get added to the queue
// and instrumented as well
void TinyInst::TranslateBasicBlockRecursive(char *address, ModuleInfo *module) {
  std::set<char *> queue;
  std::list<std::pair<uint32_t, uint32_t>> offset_fixes;

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

    assembler_->FixOffset(module, jmp_offset, bb_iter->second);
  }

  size_t code_size_after = module->instrumented_code_allocated;

  // Commit everything in one go here
  CommitCode(module, code_size_before, (code_size_after - code_size_before));
}

// gets ModuleInfo for the module specified by name
ModuleInfo *TinyInst::GetModuleByName(const char *name) {
  for (auto iter = instrumented_modules.begin(); iter != instrumented_modules.end(); iter++) {
    ModuleInfo *cur_module = *iter;
    if (_stricmp(cur_module->module_name.c_str(), name) == 0) {
      return cur_module;
    }
  }

  return NULL;
}

// gets module corresponding to address
ModuleInfo *TinyInst::GetModule(size_t address) {
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
AddressRange *TinyInst::GetRegion(ModuleInfo *module, size_t address) {
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
ModuleInfo *TinyInst::GetModuleFromInstrumented(size_t address) {
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
  // clear known entries on crash
  for (auto module : instrumented_modules) {
    module->entry_offsets.clear();
  }
  
  char *address = (char *)exception_record->ip;

  printf("Exception at address %p\n", static_cast<void*>(address));
  if (exception_record->type == ACCESS_VIOLATION) {
    // printf("Access type: %d\n", (int)exception_record->ExceptionInformation[0]);
    printf("Access address: %p\n", exception_record->access_address);
  }

  ModuleInfo *module = GetModuleFromInstrumented((size_t)address);
  if (!module) return;

  printf("Exception in instrumented module %s %p\n", module->module_name.c_str(), module->module_header);
  size_t offset = (size_t)address - (size_t)module->instrumented_code_remote;

  if(full_address_map && !module->address_map.empty()) {
    auto iter = module->address_map.upper_bound((size_t)address);
    if(iter != module->address_map.begin()) {
      --iter;
      printf("Original exception address (could be incorrect): %p\n", (void *)iter->second);
    }
  }
  
  printf("Code before:\n");
  size_t offset_from;
  if (offset < 10) offset_from = 0;
  else offset_from = offset - 10;
  for (size_t i = offset_from; i < offset; i++) {
    printf("%02x ", (unsigned char)(module->instrumented_code_local[i]));
  }
  printf("\n");
  printf("Code after:\n");
  size_t offset_to = offset + 0x10;
  if (offset_to > module->instrumented_code_size)
    offset_to = module->instrumented_code_size;
  for (size_t i = offset; i < offset_to; i++) {
    printf("%02x ", (unsigned char)(module->instrumented_code_local[i]));
  }
  printf("\n");
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
    printf("TRACE: Entered module %s at address %p, offset %zx\n",
           module->module_name.c_str(), static_cast<void*>(address),
           (size_t)address - (size_t)module->module_header );
  }
  if (patch_module_entries) {
    size_t entry_offset = (size_t)address - module->min_address;
    module->entry_offsets.insert(entry_offset);
  }

  size_t translated_address = GetTranslatedAddress(module, (size_t)address);
  OnModuleEntered(module, (size_t)address);

  translated_address = unwind_generator->MaybeRedirectExecution(module, translated_address);

  SetRegister(ARCH_PC, translated_address);

  return true;
}

void TinyInst::OnReturnAddress(ModuleInfo *module, size_t original_address, size_t translated_address) {
  unwind_generator->OnReturnAddress(module, original_address, translated_address);
}

void TinyInst::OnModuleInstrumented(ModuleInfo* module) {
  unwind_generator->OnModuleInstrumented(module);
  
  for (auto iter = hooks.begin(); iter != hooks.end(); iter++) {
    Hook *hook = *iter;
    if((hook->GetModuleName() == std::string("*")) || (hook->GetModuleName() == module->module_name)) {
      size_t address = 0;
      if(!hook->GetFunctionName().empty()) {
        address = (size_t)GetSymbolAddress(module->module_header, hook->GetFunctionName().c_str());
      } else if(hook->GetFunctionOffset()) {
        address = (size_t)(module->module_header) + hook->GetFunctionOffset();
      } else {
        FATAL("Hook specifies neithr function name nor offset");
      }
      if(address) {
        resolved_hooks[address] = hook;
      }
    }
  }
}

void TinyInst::OnModuleUninstrumented(ModuleInfo* module) {
  unwind_generator->OnModuleUninstrumented(module);
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
#ifdef ARM64
    (char *)RemoteAllocate(module->instrumented_code_size,
                           READEXECUTE);
#else
    (char *)RemoteAllocateNear((uint64_t)module->min_address,
                               (uint64_t)module->max_address,
                               module->instrumented_code_size,
                               READEXECUTE);
#endif

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

  if (patch_module_entries) PatchModuleEntries(module);
}

void TinyInst::PatchPointersLocal(char* buf, size_t size, std::unordered_map<size_t, size_t>& search_replace, bool commit_code, ModuleInfo* module) {
  if (child_ptr_size == 4) {
    PatchPointersLocalT<uint32_t>(buf, size, search_replace, commit_code, module);
  } else {
    PatchPointersLocalT<uint64_t>(buf, size, search_replace, commit_code, module);
  }
}

template<typename T>
void TinyInst::PatchPointersLocalT(char* buf, size_t size, std::unordered_map<size_t, size_t>& search_replace, bool commit_code, ModuleInfo* module) {
  size -= child_ptr_size - 1;
  for (size_t i = 0; i < size; i++) {
    T ptr = *(T*)(buf);
    auto iter = search_replace.find(ptr);
    if (iter != search_replace.end()) {
      // printf("patching entry %zx at address %zx\n", (size_t)ptr, (size_t)buf);
      // if (commit_code) printf("The address is in translated code\n");
      T fixed_ptr = (T)iter->second;
      *(T*)(buf) = fixed_ptr;
      if (commit_code) {
        CommitCode(module, i, child_ptr_size);
      }
    }
    buf += 1;
  }
}

void TinyInst::PatchModuleEntries(ModuleInfo* module) {
  if (!patch_module_entries) return;

  if (module->entry_offsets.empty()) return;

  std::unordered_map<size_t, size_t> search_replace;
  for (size_t offset : module->entry_offsets) {
    size_t original_address = offset + module->min_address;
    size_t translated_address = GetTranslatedAddress(module, original_address);
    search_replace[original_address] = translated_address;
  }

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)

  // patching exception handler addresses on x86 windows
  // interferes with SafeSEH. A simple way around it for now
  // is to simply remove exception handlers from the list
  // of entrypoints
  std::unordered_set<size_t> exception_handlers;
  GetExceptionHandlers(module->min_address, exception_handlers);
  for (size_t handler : exception_handlers) {
    auto iter = search_replace.find(handler);
    if (iter != search_replace.end()) {
      // printf("Removing exception handler %zx from list of entrypoints to patch\n", handler);
      search_replace.erase(iter);
    }
  }

  // since at this point, we already read the code and the target can't
  // execute it anymore, patching the entire library in the remote
  // process is equivalent to patching data only
  if (patch_module_entries & PatchModuleEntriesValue::DATA) {
    PatchPointersRemote(module->min_address, module->max_address, search_replace);
  }

#elif defined(__APPLE__)
  if (patch_module_entries & PatchModuleEntriesValue::DATA) {
    PatchPointersRemote(module->module_header,search_replace);
  }
#endif

  if (patch_module_entries & PatchModuleEntriesValue::CODE) {
    // we need to patch the local copy as the code has been
    // copied to TinyInst process alredy
    for (AddressRange& range : module->executable_ranges) {
      PatchPointersLocal(range.data, (range.to - range.from), search_replace, false, NULL);
    }
    // some of that code could have been translated already
    // while translating entrypoints themselves
    PatchPointersLocal(module->instrumented_code_local, module->instrumented_code_allocated, search_replace, true, module);
  }

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
ModuleInfo *TinyInst::IsInstrumentModule(char *module_name) {
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

  if(instrument_modules_on_load) {
    InstrumentModule(target_module);
  } else if (target_function_defined) {
    if (target_reached) InstrumentModule(target_module);
  } else if (child_entrypoint_reached) {
    InstrumentModule(target_module);
  }
}

// called when a potentialy interesting module gets loaded
void TinyInst::OnModuleLoaded(void *module, char *module_name) {
  Debugger::OnModuleLoaded(module, module_name);

  unwind_generator->OnModuleLoaded(module, module_name);
  
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

  if (target_function_defined && !instrument_modules_on_load) InstrumentAllLoadedModules();
}

void TinyInst::OnEntrypoint() {
  Debugger::OnEntrypoint();

  if(!target_function_defined && !instrument_modules_on_load) InstrumentAllLoadedModules();
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

  if ((child_ptr_size == 4) && unwind_generator->Is64BitOnly()) {
    WARN("generate_unwind used with 32-bit process. Disabling.");
    delete unwind_generator;
    unwind_generator = new UnwindGenerator(*this);
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
    OnModuleUninstrumented(cur_module);
  }
  // clear cross-module links
  ClearCrossModuleLinks();
  
  resolved_hooks.clear();
  for (auto iter = hooks.begin(); iter != hooks.end(); iter++) {
    (*iter)->OnProcessExit();
  }
}

void TinyInst::RegisterHook(Hook *hook) {
  hooks.push_back(hook);
}

InstructionResult TinyInst::InstrumentInstruction(ModuleInfo *module,
                                        Instruction& inst,
                                        size_t bb_address,
                                        size_t instruction_address)
{
  if(!resolved_hooks.empty()) {
    auto iter = resolved_hooks.find(instruction_address);
    if(iter != resolved_hooks.end()) {
      Hook *hook = iter->second;
      printf("Hooking function %s in module %s\n",
             hook->GetFunctionName().c_str(),
             module->module_name.c_str());
      hook->SetTinyInst(this);
      hook->SetAssembler(assembler_);
      return hook->InstrumentFunction(module, instruction_address);
    }
  }
  
  return INST_NOTHANDLED;
}


// initializes instrumentation from command line options
void TinyInst::Init(int argc, char **argv) {
  // init the debugger first
  Debugger::Init(argc, argv);

#ifdef ARM64
  assembler_ = new Arm64Assembler(*this);
#else
  assembler_ = new X86Assembler(*this);
#endif
  assembler_->Init();

  instrumentation_disabled = false;

  instrument_modules_on_load = GetBinaryOption("-instrument_modules_on_load", argc, argv, false);
  patch_return_addresses = GetBinaryOption("-patch_return_addresses", argc, argv, false);
  instrument_cross_module_calls = GetBinaryOption("-instrument_cross_module_calls", argc, argv, true);
  persist_instrumentation_data = GetBinaryOption("-persist_instrumentation_data", argc, argv, true);

  trace_basic_blocks = GetBinaryOption("-trace_basic_blocks", argc, argv, false);
  trace_module_entries = GetBinaryOption("-trace_module_entries", argc, argv, false);
  
  full_address_map = GetBinaryOption("-full_address_map", argc, argv, false);

#if defined(ARM64) && defined(__APPLE__)
  page_extend_modules = GetBinaryOption("-page_extend_modules", argc, argv, true);
#else
  page_extend_modules = false;
#endif

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) || defined(ARM64)
  sp_offset = 0;
#else
  // According to System V AMD64 ABI:
  // "For leaf-node functions a 128-byte space is stored just beneath
  // the stack pointer of the function. The space is called the red zone.
  // This zone will not be clobbered by any signal or interrupt handlers.
  // Compilers can thus utilize this zone to save local variables."
  // We set sp_offset to more than that just to be on the safe side.
  sp_offset = 256;
#endif
  
  sp_offset = GetIntOption("-stack_offset", argc, argv, sp_offset);

  std::list <char *> module_names;
  GetOptionAll("-instrument_module", argc, argv, &module_names);

#if defined(__APPLE__) && defined(ARM64)
  std::set <std::string> orig_uniq_mod_names;
  std::set <std::string> new_uniq_mod_names;
  if(page_extend_modules) {
    std::map<std::string, std::vector<std::string>> mod_grp =
      parse_dyld_map_file(find_dyld_map());

    if (mod_grp.empty()) {
      FATAL("Module group is expected to have entries.");
    }

    // Store modules, specified by user, in set for faster lookup.
    orig_uniq_mod_names.insert(module_names.begin(), module_names.end());

    // Generate list of additionally needed modules.
    for(auto* mod_name: module_names) {
      auto it = mod_grp.find(mod_name);
      if(it != mod_grp.end()) {
        for(const auto &m: it->second) {
          // Only add if not specified by user (to keep track of newly added
          // modules).
          if(orig_uniq_mod_names.count(m) == 0) {
            new_uniq_mod_names.insert(m);
          }
        }
      }
    }

    SAY("Additionally added modules to align to pages:\n");
    for (const auto &m : new_uniq_mod_names) {
      SAY("  %s\n", m.c_str());
      module_names.emplace_back((char*)m.c_str());
    }
  }
#endif

  for (const auto module_name: module_names) {
    ModuleInfo *new_module = new ModuleInfo();
    new_module->module_name = module_name;
    instrumented_modules.push_back(new_module);
    // SAY("--- %s\n", module_name);
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

  patch_module_entries = PatchModuleEntriesValue::OFF;
  option = GetOption("-patch_module_entries", argc, argv);
  if (option) {
    if (strcmp(option, "off") == 0)
      patch_module_entries = PatchModuleEntriesValue::OFF;
    else if (strcmp(option, "data") == 0)
      patch_module_entries = PatchModuleEntriesValue::DATA;
    else if (strcmp(option, "code") == 0)
      patch_module_entries = PatchModuleEntriesValue::CODE;
    else if (strcmp(option, "all") == 0)
      patch_module_entries = PatchModuleEntriesValue::ALL;
    else
      FATAL("Unknown -patch_module_entries value");
  }

  generate_unwind = GetBinaryOption("-generate_unwind", argc, argv, false);

  // if patch_return_addresses is on, disable generate_unwind
  // regardless of the flag
  if (patch_return_addresses) generate_unwind = false;

  if (!generate_unwind) {
    unwind_generator = new UnwindGenerator(*this);
  } else {
#ifdef __APPLE__
    unwind_generator = new UnwindGeneratorMacOS(*this);
#elif defined(_WIN64)
    unwind_generator = new WinUnwindGenerator(*this);
#else
    WARN("Unwind generator not implemented for the current platform");
    unwind_generator = new UnwindGenerator(*this);
#endif
  }
  unwind_generator->Init(argc, argv);
}
