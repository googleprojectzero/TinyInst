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

#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <algorithm>

#include <mach/mach.h>
#include <mach/mach_vm.h>

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>

#include <dlfcn.h>

#include <spawn.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>

#include "macOS/debugger.h"
#include "common.h"

#define BREAKPOINT_UNKNOWN 0x0
#define BREAKPOINT_ENTRYPOINT 0x01
#define BREAKPOINT_TARGET 0x02
#define BREAKPOINT_NOTIFICATION 0x04
#define BREAKPOINT_TARGET_END 0x08

#define PERSIST_END_EXCEPTION 0x0F22

#ifndef _POSIX_SPAWN_DISABLE_ASLR
  #define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

extern char **environ;

std::unordered_map<task_t, class Debugger*> Debugger::task_to_debugger_map;
std::mutex Debugger::map_mutex;

vm_prot_t Debugger::MacOSProtectionFlags(MemoryProtection memory_protection) {
  switch (memory_protection) {
    case READONLY:
      return VM_PROT_READ;

    case READWRITE:
      return VM_PROT_READ | VM_PROT_WRITE;

    case READEXECUTE:
      return VM_PROT_READ | VM_PROT_EXECUTE;

    case READWRITEEXECUTE:
      return VM_PROT_ALL;

    default:
      FATAL("Unimplemented memory protection");
  }
}

void Debugger::ClearSharedMemory() {
  for (auto iter = shared_memory.begin(); iter != shared_memory.end(); ) {
    iter = FreeSharedMemory(iter);
  }

  shared_memory.clear();
}

std::list<SharedMemory>::iterator Debugger::FreeSharedMemory(std::list<SharedMemory>::iterator it) {
  if (it->size == 0) {
    WARN("FreeShare is called with size == 0\n");
    return ++it;
  }

  kern_return_t krt = mach_port_destroy(mach_task_self(), it->port);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) destroy port for local shared memory @ 0x%llx\n", mach_error_string(krt), it->local_address);
  }

  krt = mach_vm_deallocate(mach_task_self(), it->local_address, it->size);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) freeing memory @ 0x%llx\n", mach_error_string(krt), it->remote_address);
  }

  return shared_memory.erase(it);
}

void Debugger::RemoteFree(void *address, size_t size) {
  for (auto iter = shared_memory.begin(); iter != shared_memory.end(); iter++) {
    if (iter->remote_address == (mach_vm_address_t)address) {
      FreeSharedMemory(iter);
      break;
    }
  }
  mach_target->FreeMemory((uint64_t)address, size);
}

void Debugger::RemoteRead(void *address, void *buffer, size_t size) {
  mach_vm_address_t shared_memory_address = 0;
  for (auto iter = shared_memory.begin(); iter != shared_memory.end(); ++iter) {
    if (((mach_vm_address_t)address >= iter->remote_address)  &&
        (((mach_vm_address_t)address + size) <= (iter->remote_address + iter->size)))
    {
      shared_memory_address = iter->local_address + ((mach_vm_address_t)address - iter->remote_address);
      break;
    }
  }

  if (shared_memory_address) {
    memcpy(buffer, (void *)shared_memory_address, size);
  } else {
    mach_target->ReadMemory((uint64_t)address, size, buffer);
  }
}

void Debugger::RemoteWrite(void *address, const void *buffer, size_t size) {
  mach_target->WriteMemory((uint64_t)address, buffer, size);
}

void Debugger::RemoteProtect(void *address, size_t size, MemoryProtection protect) {
  RemoteProtect(address, size, MacOSProtectionFlags(protect));
}

void Debugger::RemoteProtect(void *address, size_t size, vm_prot_t protect) {
  mach_target->ProtectMemory((uint64_t)address, size, protect);
}

void Debugger::CreateException(MachException *mach_exception, Exception *exception) {
  exception->ip = (void*)GetRegister(ARCH_PC);

  switch (mach_exception->exception_type) {
    case EXC_BREAKPOINT:
      exception->type = BREAKPOINT;
#ifdef ARM64
      SetRegister(ARCH_PC, GetRegister(ARCH_PC) + 4);
      exception->ip = (void*)((uint64_t)exception->ip);
#else
      exception->ip = (void*)((uint64_t)exception->ip - 1);
#endif
      break;

    case EXC_BAD_ACCESS:
      exception->type = ACCESS_VIOLATION;
      break;

    case EXC_BAD_INSTRUCTION:
      exception->type = ILLEGAL_INSTRUCTION;
      break;

    default:
      exception->type = OTHER;
      break;
  }

  exception->maybe_execute_violation = false;
  exception->maybe_write_violation = false;
  exception->access_address = 0;

  if (mach_exception->exception_type == EXC_BAD_ACCESS) {
    if (mach_exception->code[0] == KERN_PROTECTION_FAILURE) {
      exception->maybe_write_violation = true;
      exception->maybe_execute_violation = true;
    }

    exception->access_address = (void*)mach_exception->code[1];
  }
}

uint64_t* Debugger::GetPointerToRegister(Register r) {
  ARCH_THREAD_STATE_T *state = (ARCH_THREAD_STATE_T*)(mach_exception->new_state);
#ifdef ARM64
  switch(r) {
    case X0:
    case X1:
    case X2:
    case X3:
    case X4:
    case X5:
    case X6:
    case X7:
    case X8:
    case X9:
    case X10:
    case X11:
    case X12:
    case X13:
    case X14:
    case X15:
    case X16:
    case X17:
    case X18:
    case X19:
    case X20:
    case X21:
    case X22:
    case X23:
    case X24:
    case X25:
    case X26:
    case X27:
    case X28:
    case X29:
      return &state->__x[r];
    case PC:
      return &state->__pc;
    case CPSR:
      return (uint64_t*)&state->__cpsr;
    case LR:
      return &state->__lr;
    case SP:
      return &state->__sp;

    default:
      FATAL("Unimplemented register");
    }
#else
  switch (r) {
    case RAX:
      return &state->__rax;
    case RCX:
      return &state->__rcx;
    case RDX:
      return &state->__rdx;
    case RBX:
      return &state->__rbx;
    case RSP:
      return &state->__rsp;
    case RBP:
      return &state->__rbp;
    case RSI:
      return &state->__rsi;
    case RDI:
      return &state->__rdi;
    case R8:
      return &state->__r8;
    case R9:
      return &state->__r9;
    case R10:
      return &state->__r10;
    case R11:
      return &state->__r11;
    case R12:
      return &state->__r12;
    case R13:
      return &state->__r13;
    case R14:
      return &state->__r14;
    case R15:
      return &state->__r15;
    case RIP:
      return &state->__rip;

    default:
      FATAL("Unimplemented register");
  }
#endif
}

size_t Debugger::GetRegister(Register r) {
#ifdef ARM64
  if (r == CPSR) {
    uint32_t *reg_pointer = (uint32_t *)GetPointerToRegister(r);
    return *reg_pointer;
  }
#endif
  uint64_t *reg_pointer = GetPointerToRegister(r);
  return *reg_pointer;
}

void Debugger::SetRegister(Register r, size_t value) {
#ifdef ARM64
  if (r == CPSR) {
    if(value & 0xFFFFFFFF00000000) FATAL("32 bit value required");
    uint32_t *reg_pointer = (uint32_t *)GetPointerToRegister(r);
    *reg_pointer = (uint32_t)(value & 0xFFFFFFFF);
  }
#endif
  uint64_t *reg_pointer = GetPointerToRegister(r);
  *reg_pointer = value;
}

#ifdef ARM64
Register Debugger::ArgumentToRegister(int arg) {
  switch (arg) {
    case 0:
      return X0;

    case 1:
      return X1;

    case 2:
      return X2;

    case 3:
      return X3;

    case 4:
      return X4;

    case 5:
      return X5;

    case 6:
      return X6;

    case 7:
      return X7;

    default:
      FATAL("Argument %d not valid\n", arg);
      break;
  }
}
#else
Register Debugger::ArgumentToRegister(int arg) {
  switch (arg) {
    case 0:
      return RDI;

    case 1:
      return RSI;

    case 2:
      return RDX;

    case 3:
      return RCX;

    case 4:
      return R8;

    case 5:
      return R9;

    default:
      FATAL("Argument %d not valid\n", arg);
      break;
  }
}
#endif

void Debugger::SetReturnAddress(size_t value) {
#ifdef ARM64 
  SetRegister(LR, value);
#else
  RemoteWrite((void*)GetRegister(RSP), &value, child_ptr_size);
#endif
}
size_t Debugger::GetReturnAddress() {
#ifdef ARM64 
  return GetRegister(LR);
#else
  void *ra;
  RemoteRead((void*)GetRegister(RSP), &ra, child_ptr_size);
  return (size_t)ra;
#endif
}

void Debugger::GetMachHeader(void *mach_header_address, mach_header_64 *mach_header) {
  RemoteRead(mach_header_address, (void*)mach_header, sizeof(mach_header_64));
}

void Debugger::GetLoadCommandsBuffer(void *mach_header_address,
                                     const mach_header_64 *mach_header,
                                     void **load_commands) {
  *load_commands = (void*)malloc(mach_header->sizeofcmds);
  RemoteRead((void*)((uint64_t)mach_header_address + sizeof(mach_header_64)),
             *load_commands,
             mach_header->sizeofcmds);
}

template <class TCMD>
bool Debugger::GetLoadCommand(mach_header_64 mach_header,
                              void *load_commands_buffer,
                              uint32_t load_cmd_type,
                              const char *segname,
                              TCMD **ret_command) {
  uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
  for (uint32_t i = 0; i < mach_header.ncmds; ++i) {
    load_command *load_cmd = (load_command *)load_cmd_addr;
    if (load_cmd->cmd == load_cmd_type) {
      TCMD *t_cmd = (TCMD*)load_cmd;
      if (load_cmd_type != LC_SEGMENT_64
          || !strcmp(((segment_command_64*)t_cmd)->segname, segname)) {
        *ret_command = (TCMD*)load_cmd;
        return true;
      }
    }

    load_cmd_addr += load_cmd->cmdsize;
  }

  return false;
}


bool Debugger::GetSectionAndSlide(void *mach_header_address,
                                 const char *segname,
                                 const char *sectname,
                                 section_64 *ret_section,
                                 size_t *file_vm_slide) {
  mach_header_64 mach_header;
  GetMachHeader(mach_header_address, &mach_header);

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(mach_header_address, &mach_header, &load_commands_buffer);

  segment_command_64 *text_cmd = NULL;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd)) {
    FATAL("Unable to find __TEXT command in GetSectionAndSlide\n");
  }
  *file_vm_slide = (size_t)mach_header_address - text_cmd->vmaddr;

  segment_command_64 *seg_cmd = NULL;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, segname, &seg_cmd)) {
    return false;
  }

  bool found_section = false;
  size_t section_addr = (size_t)seg_cmd + sizeof(segment_command_64);
  for (uint32_t i = 0; i < seg_cmd->nsects && !found_section; ++i) {
    section_64 *section = (section_64*)section_addr;
    if (!strcmp(section->sectname, sectname)) {
      *ret_section = *section;
      found_section = true;
    }

    section_addr += sizeof(section_64);
  }

  free(load_commands_buffer);
  return found_section;
}

void *Debugger::MakeSharedMemory(mach_vm_address_t address, size_t size, MemoryProtection protection) {
  mach_port_t shm_port;
  if (address == 0)
    return NULL;

  memory_object_size_t memoryObjectSize = round_page(size);
  vm_prot_t prot_flags = MacOSProtectionFlags(protection);
  kern_return_t ret = mach_make_memory_entry_64(mach_target->Task(), &memoryObjectSize, address, prot_flags, &shm_port, MACH_PORT_NULL);
  if (ret != KERN_SUCCESS) {
    FATAL("Error (%s) remote allocate share memory\n", mach_error_string(ret));
  }

  mach_vm_address_t map_address = 0;
  ret = mach_vm_map(mach_task_self(), &map_address, memoryObjectSize, 0, VM_FLAGS_ANYWHERE, shm_port, 0, 0, prot_flags, prot_flags, VM_INHERIT_NONE);
  if (ret != KERN_SUCCESS) {
    FATAL("Error (%s) map memory\n", mach_error_string(ret));
  }

  SharedMemory sm(map_address, address, size, shm_port);
  shared_memory.push_back(sm);

  return (void *)map_address;
}

void *Debugger::RemoteAllocateNear(uint64_t region_min,
				    uint64_t region_max,
				    size_t size,
				    MemoryProtection protection,
				    bool use_shared_memory) {
  uint64_t min_address, max_address;

  //try after first
  min_address = region_max;
  max_address = (UINT64_MAX - region_min < 0x80000000) ? UINT64_MAX : region_min + 0x80000000;
  void *ret_address = RemoteAllocateAfter(min_address, max_address, size, protection);
  if (ret_address != NULL) {
    if (use_shared_memory)
      MakeSharedMemory((mach_vm_address_t)ret_address, size, protection);
    return ret_address;
  }

  //try before second
  min_address = (region_max < 0x80000000) ? 0 : region_max - 0x80000000;
  max_address = (region_min < size) ? 0 : region_min - size;
  ret_address = RemoteAllocateBefore(min_address, max_address, size, protection);
  if (ret_address != NULL) {
    if (use_shared_memory)
      MakeSharedMemory((mach_vm_address_t)ret_address, size, protection);
    return ret_address;
  }

  // if all else fails, try within
  ret_address = RemoteAllocateAfter(region_min, region_max, size, protection);
  if (use_shared_memory)
    MakeSharedMemory((mach_vm_address_t)ret_address, size, protection);
  return ret_address;
}

void *Debugger::RemoteAllocateBefore(uint64_t min_address,
                                          uint64_t max_address,
                                          size_t size,
                                          MemoryProtection protection) {
  vm_prot_t protection_flags = MacOSProtectionFlags(protection);

  mach_vm_address_t cur_address = max_address;
  while (cur_address > min_address) {
    size_t step = size;

    mach_vm_address_t region_address = cur_address;
    mach_vm_size_t region_size = 0;
    vm_region_submap_info_data_64_t info;
    mach_target->GetRegionSubmapInfo(&region_address, &region_size, &info);

    if (region_address <= cur_address) { /* cur_address references allocated memory */
      cur_address = region_address;
    } else { /* cur_address references unallocated memory */
      uint64_t free_region_size = region_address - cur_address;
      if (free_region_size >= size) {
        void *ret_address = (void*)(cur_address + (free_region_size - size));
        kern_return_t krt = RemoteAllocateAt(ret_address, size);

        if (krt == KERN_SUCCESS) {
          if (!(min_address <= (uint64_t)ret_address && (uint64_t)ret_address <= max_address)) {
            return NULL;
          }

          RemoteProtect(ret_address, size, protection_flags);
          return ret_address;
        }
      } else {
        step = size - free_region_size;
      }
    }

    if (cur_address < step) break;
    cur_address -= step;
  }

  return NULL;
}

void *Debugger::RemoteAllocateAfter(uint64_t min_address,
                                         uint64_t max_address,
                                         size_t size,
                                         MemoryProtection protection) {
  vm_prot_t protection_flags = MacOSProtectionFlags(protection);

  mach_vm_address_t cur_address = min_address;
  while (cur_address < max_address) {
    mach_vm_address_t region_address = cur_address;
    mach_vm_size_t region_size = 0;
    vm_region_submap_info_data_64_t info;
    mach_target->GetRegionSubmapInfo(&region_address, &region_size, &info);

    if (region_address <= cur_address) { /* cur_address references allocated memory */
      cur_address = region_address + region_size;
      continue;
    }

    /* cur_address references unallocated memory */
    if (region_address > max_address) {
      region_address = max_address;
    }

    uint64_t free_region_size = region_address - cur_address;
    if (free_region_size >= size) {
      void *ret_address = (void*)cur_address;
      kern_return_t krt = RemoteAllocateAt(ret_address, size);

      if (krt == KERN_SUCCESS) {
        if (!(min_address <= (uint64_t)ret_address && (uint64_t)ret_address <= max_address)) {
          return NULL;
        }

        RemoteProtect(ret_address, size, protection_flags);
        return ret_address;
      }
    }

    cur_address = region_address;
  }

  return NULL;
}

kern_return_t Debugger::RemoteAllocateAt(void *ret_address, int size) {
  kern_return_t krt;
  bool retried = false;

retry_label:
  void *alloc_address = ret_address;
  krt = mach_vm_allocate(mach_target->Task(),
                        (mach_vm_address_t*)&alloc_address,
                        size,
                        VM_FLAGS_FIXED);

  if (krt == KERN_NO_SPACE && !retried) {
    krt = mach_vm_deallocate(mach_target->Task(),
                             (mach_vm_address_t)ret_address,
                             size);
    if (krt != KERN_SUCCESS) {
      FATAL("Unable to deallocate memory region starting @ %p, size 0x%x\n",
            ret_address, size);
    }

    retried = true;
    goto retry_label;
  }

  return krt;
}


void Debugger::DeleteBreakpoints() {
  for (auto iter = breakpoints.begin(); iter != breakpoints.end(); iter++) {
    delete *iter;
  }
  breakpoints.clear();
}


void Debugger::AddBreakpoint(void *address, int type) {
  for (auto it = breakpoints.rbegin(); it != breakpoints.rend(); ++it) {
    if ((*it)->address == address) {
      (*it)->type |= type;
      if (((*it)->type & BREAKPOINT_NOTIFICATION) && ((*it)->type & BREAKPOINT_TARGET)) {
        FATAL("Target method must not be the same as _dyld_debugger_notification");
      }

      return;
    }
  }

  Breakpoint *new_breakpoint = new Breakpoint;
#ifdef ARM64
  uint32_t breakpoint_bytes = 0xd4200020;
#else
  unsigned char breakpoint_bytes = 0xcc;
#endif
  RemoteRead(address, &(new_breakpoint->original_opcode), sizeof(new_breakpoint->original_opcode));
  RemoteWrite(address, (void*)&breakpoint_bytes, sizeof(breakpoint_bytes));

  new_breakpoint->address = address;
  new_breakpoint->type = type;
  breakpoints.push_back(new_breakpoint);
}


void Debugger::HandleTargetReachedInternal() {
  saved_sp = (void*)GetRegister(ARCH_SP);
  saved_return_address = (void*)GetReturnAddress();

  if (loop_mode) {
    for (int arg_index = 0; arg_index < MAX_NUM_REG_ARGS && arg_index < target_num_args; ++arg_index) {
      saved_args[arg_index] = (void*)GetRegister(ArgumentToRegister(arg_index));
    }

    if (target_num_args > MAX_NUM_REG_ARGS) {
      RemoteRead((void*)((uint64_t)saved_sp + child_ptr_size),
                 saved_args + MAX_NUM_REG_ARGS,
                 child_ptr_size * (target_num_args - MAX_NUM_REG_ARGS));
    }
  }

  if (target_end_detection == RETADDR_STACK_OVERWRITE) {
    size_t return_address = PERSIST_END_EXCEPTION;
    RemoteWrite(saved_sp, &return_address, child_ptr_size);
  } else if (target_end_detection == RETADDR_BREAKPOINT) {
    AddBreakpoint((void*)GetTranslatedAddress((size_t)saved_return_address), BREAKPOINT_TARGET_END);
  }

  if (!target_reached) {
    target_reached = true;
    OnTargetMethodReached();
  }
}


void Debugger::HandleTargetEnded() {
  target_return_value = (uint64_t)GetRegister(ARCH_RETURN_VALUE_REGISTER);

  if (loop_mode) {
    SetRegister(ARCH_PC, (size_t)target_address);
    SetRegister(ARCH_SP, (size_t)saved_sp);

    if (target_end_detection == RETADDR_STACK_OVERWRITE) {
      size_t return_address = PERSIST_END_EXCEPTION;
      SetReturnAddress(return_address);
    } else if (target_end_detection == RETADDR_BREAKPOINT) {
      SetReturnAddress((size_t)saved_return_address);
      AddBreakpoint((void*)GetTranslatedAddress((size_t)saved_return_address), BREAKPOINT_TARGET_END);
    }

    for (int arg_index = 0; arg_index < MAX_NUM_REG_ARGS && arg_index < target_num_args; ++arg_index) {
      SetRegister(ArgumentToRegister(arg_index), (size_t)saved_args[arg_index]);
    }

    if (target_num_args > MAX_NUM_REG_ARGS) {
      RemoteWrite((void*)((uint64_t)saved_sp + child_ptr_size),
                  saved_args + MAX_NUM_REG_ARGS,
                  child_ptr_size * (target_num_args - MAX_NUM_REG_ARGS));
    }
  } else {
    SetRegister(ARCH_PC, (size_t)saved_return_address);
    AddBreakpoint((void*)GetTranslatedAddress((size_t)target_address), BREAKPOINT_TARGET);
  }
}

void Debugger::OnEntrypoint() {
  child_entrypoint_reached = true;
  if (trace_debug_events) {
    SAY("Debugger: Process entrypoint reached\n");
  }
}


void Debugger::ExtractCodeRanges(void *base_address,
                                 size_t min_address,
                                 size_t max_address,
                                 std::list<AddressRange> *executable_ranges,
                                 size_t *code_size) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(base_address, &mach_header, &load_commands_buffer);

  segment_command_64 *text_cmd = NULL;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd)) {
    FATAL("Unable to find __TEXT command in ExtractCodeRanges\n");
  }
  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;

  *code_size = 0;
  for (auto &it: *executable_ranges) {
    free(it.data);
  }
  executable_ranges->clear();

  uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
  for (uint32_t i = 0; i < mach_header.ncmds; ++i) {
    load_command *load_cmd = (load_command *)load_cmd_addr;
    if (load_cmd->cmd == LC_SEGMENT_64) {
      segment_command_64 *segment_cmd = (segment_command_64*)load_cmd;

      if (!strcmp(segment_cmd->segname, "__PAGEZERO")
          || !strcmp(segment_cmd->segname, "__LINKEDIT")) {
        load_cmd_addr += load_cmd->cmdsize;
        continue;
      }

      mach_vm_address_t segment_start_addr = (mach_vm_address_t)segment_cmd->vmaddr + file_vm_slide;
      mach_vm_address_t segment_end_addr = (mach_vm_address_t)segment_cmd->vmaddr + file_vm_slide + segment_cmd->vmsize;

      ExtractSegmentCodeRanges(segment_start_addr, segment_end_addr, executable_ranges, code_size);
    }

    load_cmd_addr += load_cmd->cmdsize;
  }

  free(load_commands_buffer);
}

void Debugger::ExtractSegmentCodeRanges(mach_vm_address_t segment_start_addr,
                                        mach_vm_address_t segment_end_addr,
                                        std::list<AddressRange> *executable_ranges,
                                        size_t *code_size) {
  mach_vm_address_t cur_address = segment_start_addr;
  while (cur_address < segment_end_addr) {
    mach_vm_size_t region_size = 0;
    vm_region_submap_info_data_64_t info;
    mach_target->GetRegionSubmapInfo(&cur_address, &region_size, &info);
    if (segment_end_addr <= cur_address) {
      break;
    }

    AddressRange new_range;
    new_range.from = cur_address;
    new_range.to = cur_address + region_size;
    if (new_range.from < segment_start_addr) {
      new_range.from = segment_start_addr;
    }
    if (segment_end_addr < new_range.to) {
      new_range.to = segment_end_addr;
    }

    if (info.protection & VM_PROT_EXECUTE) {
      int retried = false;

      size_t range_size = new_range.to - new_range.from;
      new_range.data = (char *)malloc(range_size);
      RemoteRead((void*)new_range.from, new_range.data, range_size);

    retry_label:
      RemoteProtect((void*)new_range.from, range_size, info.protection ^ VM_PROT_EXECUTE);
      mach_vm_address_t region_addr = new_range.from;
      mach_vm_size_t region_sz = range_size;
      vm_region_submap_info_data_64_t region_info;
      mach_target->GetRegionSubmapInfo(&region_addr, (mach_vm_size_t*)&region_sz, &region_info);
      if (region_info.protection & VM_PROT_EXECUTE) {
        if (retried) {
          FATAL("Failed to mark the original code NON-EXECUTABLE\n");
        }

        kern_return_t krt;
        krt = mach_vm_deallocate(mach_target->Task(),
                                 (mach_vm_address_t)new_range.from,
                                 range_size);

        if (krt == KERN_SUCCESS) {
          mach_vm_address_t alloc_address = new_range.from;
          krt = mach_vm_allocate(mach_target->Task(),
                                 (mach_vm_address_t*)&alloc_address,
                                 range_size,
                                 VM_FLAGS_FIXED);

          if (krt == KERN_SUCCESS && alloc_address && new_range.from) {
            RemoteWrite((void*)new_range.from, new_range.data, range_size);
          } else {
            FATAL("Unable to re-allocate memory after deallocate in ExtractSegmentCodeRanges\n");
          }
        }

        retried = true;
        goto retry_label;
      }

      AddressRange *last_range = NULL;
      if(!executable_ranges->empty()) {
        last_range = &executable_ranges->back();
      }
      if(last_range && (last_range->to == new_range.from)) {
        // merge ranges instead of creating new one
        size_t last_range_size = last_range->to - last_range->from;
        size_t merged_size = last_range_size + range_size;
        last_range->data = (char *)realloc(last_range->data, merged_size);
        memcpy(last_range->data + last_range_size, new_range.data, range_size);
        last_range->to = new_range.to;
        free(new_range.data);
      } else {
        executable_ranges->push_back(new_range);
      }
      *code_size += range_size;
    }

    cur_address += region_size;
  }
}


void Debugger::ProtectCodeRanges(std::list<AddressRange> *executable_ranges) {
  WARN("persist_instrumentation_data functionality was not tested on macOS."
       "ProtectCodeRanges might fail");

  for (auto &range: *executable_ranges) {
    mach_vm_address_t region_address = range.from;
    mach_vm_size_t region_size = 0;
    vm_region_submap_info_data_64_t info;
    mach_target->GetRegionSubmapInfo(&region_address, &region_size, &info);

    if (region_address != range.from
        || region_address + region_size != range.to
        || !(info.protection & VM_PROT_EXECUTE)) {
      FATAL("Error in ProtectCodeRanges. Target incompatible with persist_instrumentation_data");
    }

    RemoteProtect((void*)region_address, region_size, info.protection ^ VM_PROT_EXECUTE);
  }
}

void Debugger::GetImageSize(void *base_address, size_t *min_address, size_t *max_address) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(base_address, &mach_header, &load_commands_buffer);

  *min_address = SIZE_MAX;
  *max_address = 0;

  uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
  for (uint32_t i = 0; i < mach_header.ncmds; ++i) {
    load_command *load_cmd = (load_command *)load_cmd_addr;
    if (load_cmd->cmd == LC_SEGMENT_64) {
      segment_command_64 *segment_cmd = (segment_command_64*)load_cmd;

      if (!strcmp(segment_cmd->segname, "__PAGEZERO")
          || !strcmp(segment_cmd->segname, "__LINKEDIT")) {
        load_cmd_addr += load_cmd->cmdsize;
        continue;
      }

      if (segment_cmd->vmaddr < *min_address) {
        *min_address = segment_cmd->vmaddr;
      }

      if (segment_cmd->vmaddr + segment_cmd->vmsize > *max_address) {
        *max_address = segment_cmd->vmaddr + segment_cmd->vmsize;
      }
    }

    load_cmd_addr += load_cmd->cmdsize;
  }

  segment_command_64 *text_cmd = NULL;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd)) {
    FATAL("Unable to find __TEXT command in GetImageSize\n");
  }

  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;
  *min_address += file_vm_slide;
  *max_address += file_vm_slide;

  free(load_commands_buffer);
}


void *Debugger::GetModuleEntrypoint(void *base_address) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);
  if (mach_header.filetype != MH_EXECUTE) {
    return NULL;
  }

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(base_address, &mach_header, &load_commands_buffer);

  entry_point_command *entry_point_cmd = NULL;
  if (GetLoadCommand(mach_header, load_commands_buffer, LC_MAIN, NULL, &entry_point_cmd)) {
    uint64_t entryoff = entry_point_cmd->entryoff;

    free(load_commands_buffer);
    return (void*)((uint64_t)base_address + entryoff);
  }

  // no LC_MAIN command, probably an older binary.
  // Look up LC_UNIXTHREAD instead

  thread_command *tc;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_UNIXTHREAD, NULL, &tc)) {
    FATAL("Unable to find entry point in the executable module");
  }

  uint32_t flavor = *(uint32_t *)((char *)tc + 2 * sizeof(uint32_t));
  if(flavor != ARCH_THREAD_STATE) {
    FATAL("Unexpected thread state flavor");
  }
  ARCH_THREAD_STATE_T *state = (ARCH_THREAD_STATE_T *)((char *)tc + 4 * sizeof(uint32_t));

  segment_command_64 *text_cmd = NULL;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd)) {
    FATAL("Unable to find __TEXT command in GetModuleEntrypoint\n");
  }
  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;

  free(load_commands_buffer);
#ifdef ARM64
  return (void*)(state->__pc + file_vm_slide);
#else
  return (void*)(state->__rip + file_vm_slide);
#endif
}

bool Debugger::IsDyld(void *base_address) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);

  return (mach_header.filetype == MH_DYLINKER);
}


void *Debugger::GetSymbolAddress(void *base_address, char *symbol_name) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(base_address, &mach_header, &load_commands_buffer);

  symtab_command *symtab_cmd = NULL;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_SYMTAB, NULL, &symtab_cmd)) {
    FATAL("Unable to find SYMTAB command in GetSymbolAddress\n");
  }

  segment_command_64 *linkedit_cmd = NULL;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__LINKEDIT", &linkedit_cmd)) {
    FATAL("Unable to find __LINKEDIT command in GetSymbolAddress\n");
  }

  segment_command_64 *text_cmd = NULL;
  if (!GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd)) {
    FATAL("Unable to find __TEXT command in GetSymbolAddress\n");
  }

  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;

  char *strtab = (char*)malloc(symtab_cmd->strsize);
  uint64_t strtab_addr = linkedit_cmd->vmaddr + file_vm_slide
                         + symtab_cmd->stroff - linkedit_cmd->fileoff;
  RemoteRead((void*)strtab_addr, strtab, symtab_cmd->strsize);

  void *symbol_address = NULL;
  for (uint32_t i = 0; i < symtab_cmd->nsyms && !symbol_address; ++i) {
    uint64_t nlist_addr = linkedit_cmd->vmaddr + file_vm_slide
                          + symtab_cmd->symoff - linkedit_cmd->fileoff + i * sizeof(nlist_64);

    nlist_64 symbol = {};
    RemoteRead((void*)nlist_addr, &symbol, sizeof(nlist_64));

    if ((symbol.n_type & N_TYPE) == N_SECT) {
      char *sym_name_start = strtab + symbol.n_un.n_strx;
      // printf("%s\n", sym_name_start);
      if (!strcmp(sym_name_start, symbol_name)) {
        symbol_address = (void*)((uint64_t)base_address - text_cmd->vmaddr + symbol.n_value);
        break;
      }
    }
  }

  free(strtab);
  free(load_commands_buffer);
  return symbol_address;
}

void *Debugger::GetTargetAddress(void *base_address) {
  if (!target_offset) {
    void *method_address = GetSymbolAddress(base_address, target_method);
    if (method_address == NULL) {
      FATAL("Unable to find address of target method\n");
    }

    target_offset = (uint64_t)method_address - (uint64_t)base_address;
  }

  return (void*)((uint64_t)base_address + target_offset);
}

void Debugger::OnModuleLoaded(void *module, char *module_name) {
  if (trace_debug_events) {
    SAY("Debugger: Loaded module %s at %p\n", module_name, module);
  }

  if (!attach_mode) {
    void *entrypoint = GetModuleEntrypoint(module);
    if (entrypoint) {
      AddBreakpoint(entrypoint, BREAKPOINT_ENTRYPOINT);
    }
  }

  if (IsDyld(module)) {
    m_dyld_debugger_notification = GetSymbolAddress(module, (char*)"__dyld_debugger_notification");
    AddBreakpoint(m_dyld_debugger_notification, BREAKPOINT_NOTIFICATION);

#ifdef ARM64
    // For arm we just mov pc, lr on BREAKPOINT_NOTIFICATION
#else
    // This save us the recurring TRAP FLAG breakpoint on BREAKPOINT_NOTIFICATION.
    unsigned char ret = 0xC3;
    RemoteWrite((void*)((uint64_t)m_dyld_debugger_notification+1), (void*)&ret, 1);
#endif
  }

  if (target_function_defined && !strcasecmp(module_name, target_module)) {
    target_address = GetTargetAddress(module);
    if (!target_address) {
      FATAL("Error determing target method address\n");
    }

    AddBreakpoint(target_address, BREAKPOINT_TARGET);
  }
}


void Debugger::OnDyldImageNotifier(size_t mode, unsigned long infoCount, uint64_t machHeaders[]) {
  uint64_t *image_info_array = new uint64_t[infoCount];
  size_t image_info_array_size = sizeof(uint64_t) * infoCount;
  RemoteRead(machHeaders, (void*)image_info_array, image_info_array_size);

  if (mode == 1) { /* dyld_image_removing */
    for (unsigned long i = 0; i < infoCount; ++i) {
      OnModuleUnloaded((void*)image_info_array[i]);
    }
  } else {
    dyld_all_image_infos all_image_infos = mach_target->GetAllImageInfos();
    dyld_image_info *all_image_info_array = new dyld_image_info[all_image_infos.infoArrayCount];
    size_t all_image_info_array_size = sizeof(dyld_image_info) * all_image_infos.infoArrayCount;
    RemoteRead((void*)all_image_infos.infoArray, (void*)all_image_info_array, all_image_info_array_size);

    char path[PATH_MAX];
    for (uint32_t i = 0; i < all_image_infos.infoArrayCount; ++i) {
      void *mach_header_addr = (void*)all_image_info_array[i].imageLoadAddress;
      if (mode == 2) { /* dyld_notify_remove_all */
        OnModuleUnloaded(mach_header_addr);
      } else if (std::find(image_info_array, image_info_array + infoCount, (uint64_t)mach_header_addr)
                 != image_info_array + infoCount) {
        /* dyld_image_adding */
        mach_target->ReadCString((uint64_t)all_image_info_array[i].imageFilePath, PATH_MAX, path);
        char *base_name = strrchr((char*)path, '/');
        base_name = (base_name) ? base_name + 1 : (char*)path;
        OnModuleLoaded(mach_header_addr, base_name);
      }
    }

    delete [] all_image_info_array;
  }

  delete [] image_info_array;
}

void Debugger::OnProcessCreated() {
  if (trace_debug_events) {
    SAY("Debugger: Process created or attached\n");
  }

  kern_return_t krt;
  dyld_process_info info = m_dyld_process_info_create(mach_target->Task(), 0, &krt);
  if (krt != KERN_SUCCESS) {
    FATAL("Unable to retrieve dyld_process_info_create information\n");
  }

  if (info) {
    m_dyld_process_info_for_each_image(
      info,
      ^(uint64_t mach_header_addr, const uuid_t uuid, const char *path) {
        if (attach_mode || IsDyld((void*)mach_header_addr)) {
          char *base_name = strrchr((char*)path, '/');
          base_name = (base_name) ? base_name + 1 : (char*)path;
          OnModuleLoaded((void*)mach_header_addr, (char*)path);
        }
      });

    m_dyld_process_info_release(info);
  }
}


int Debugger::HandleDebuggerBreakpoint() {
  int ret = BREAKPOINT_UNKNOWN;

  Breakpoint *breakpoint = NULL, *tmp_breakpoint;
  for (auto iter = breakpoints.begin(); iter != breakpoints.end(); iter++) {
    tmp_breakpoint = *iter;
    if (tmp_breakpoint->address == (void*)((uint64_t)last_exception.ip)) {
      breakpoint = tmp_breakpoint;
      if (breakpoint->type & BREAKPOINT_NOTIFICATION) {
        OnDyldImageNotifier(GetRegister(ArgumentToRegister(0)),
                            (unsigned long)GetRegister(ArgumentToRegister(1)),
                            (uint64_t*)GetRegister(ArgumentToRegister(2)));

        return BREAKPOINT_NOTIFICATION;
      }

      breakpoints.erase(iter);
      break;
    }
  }

  if (!breakpoint) {
    return ret;
  }

  RemoteWrite(breakpoint->address, &breakpoint->original_opcode, sizeof(breakpoint->original_opcode));
#ifdef ARM64
  SetRegister(ARCH_PC, GetRegister(ARCH_PC) - 4); // ARM
#else
  SetRegister(ARCH_PC, GetRegister(ARCH_PC) - 1); // INTEL
#endif

  if (breakpoint->type & BREAKPOINT_ENTRYPOINT) {
      OnEntrypoint();
  }

  if (breakpoint->type & BREAKPOINT_TARGET) {
      if (trace_debug_events) {
        SAY("Target method reached\n");
      }
      HandleTargetReachedInternal();
  }
  
  if (breakpoint->type & BREAKPOINT_TARGET_END) {
      if (trace_debug_events) {
        SAY("Target method ended\n");
      }
      HandleTargetEnded();
  }

  ret = breakpoint->type;
  free(breakpoint);

  return ret;
}

bool Debugger::IsTargetAlive() {
  return (mach_target != NULL && mach_target->IsTaskValid() && mach_target->IsExceptionPortValid());
}


void Debugger::HandleExceptionInternal(MachException *raised_mach_exception) {
  mach_exception = raised_mach_exception;
  CreateException(mach_exception, &last_exception);

  dbg_continue_status = KERN_SUCCESS;
  handle_exception_status = DEBUGGER_CONTINUE;

  if (mach_exception->exception_type == EXC_BREAKPOINT) {
    int breakpoint_type = HandleDebuggerBreakpoint();
    if (breakpoint_type & BREAKPOINT_TARGET) {
      handle_exception_status = DEBUGGER_TARGET_START;
    }
    if (breakpoint_type & BREAKPOINT_TARGET_END) {
      handle_exception_status = DEBUGGER_TARGET_END;
    }
#ifdef ARM64
    if (breakpoint_type & BREAKPOINT_NOTIFICATION) {
        SetRegister(ARCH_PC, GetRegister(LR));
        return;
    }
#endif

    if (breakpoint_type != BREAKPOINT_UNKNOWN) {
      return;
    }
  }

  if (OnException(&last_exception)) {
    return;
  }

  if (trace_debug_events) {
    SAY("Debugger: Mach exception (%d) @ address %p\n",
        mach_exception->exception_type, last_exception.ip);
  }

  switch(mach_exception->exception_type) {
    case EXC_SYSCALL:
      handle_exception_status = DEBUGGER_CONTINUE;
      dbg_continue_status = KERN_SUCCESS;
      break;
    case EXC_RESOURCE:
      handle_exception_status = DEBUGGER_HANGED;
      break;

    case EXC_BAD_ACCESS:
    bad_access_label:
      if (target_function_defined && last_exception.ip == (void*)PERSIST_END_EXCEPTION) {
        if (trace_debug_events) {
          SAY("Debugger: Persistence method ended\n");
        }

        HandleTargetEnded();
        handle_exception_status = DEBUGGER_TARGET_END;
      } else {
        dbg_continue_status = KERN_FAILURE;
        handle_exception_status = DEBUGGER_CRASHED;
      }
      break;

    case EXC_BAD_INSTRUCTION:
    case EXC_ARITHMETIC:
    case EXC_CRASH:
    case EXC_GUARD:
    crash_label:
      dbg_continue_status = KERN_FAILURE;
      handle_exception_status = DEBUGGER_CRASHED;
      break;

    case EXC_BREAKPOINT:
      dbg_continue_status = KERN_FAILURE;
      break;

    //Unix signals
    case EXC_SOFTWARE:
      if (mach_exception->code_cnt < 2 || mach_exception->code[0] != EXC_SOFT_SIGNAL) {
        goto default_label;
      }

      switch (mach_exception->code[1]) {
        case SIGSEGV:
        case SIGBUS:
          goto bad_access_label;

        case SIGILL:
        case SIGFPE:
        case SIGABRT:
        case SIGSYS:
        case SIGPIPE:
          goto crash_label;

        /* Handling the Unix soft signal produced by attaching via ptrace
          PT_ATTACHEXC suspends the process by using a SIGSTOP signal */
        case SIGSTOP:
          OnProcessCreated();

          mach_exception->code[1] = 0;
          ptrace(PT_THUPDATE,
                 mach_target->Pid(),
                (caddr_t)(uintptr_t)mach_exception->thread_port,
                (int)mach_exception->code[1]);

          break;

        case SIGCHLD:
          if (!IsTargetAlive()) {
            handle_exception_status = DEBUGGER_PROCESS_EXIT;
          }
          break;

        default:
          goto default_label;
      }

      break;

    default:
    default_label:
      if (trace_debug_events) {
        WARN("Debugger: Unhandled exception, mach exception_type %x at address %p\n",
             mach_exception->exception_type, last_exception.ip);
      }
      dbg_continue_status = KERN_FAILURE;
  }
}

void Debugger::SaveRegisters(SavedRegisters *registers) {
  if((*(mach_exception->new_state_cnt)) * sizeof(mach_exception->new_state[0]) > sizeof(ARCH_THREAD_STATE_T)) {
    FATAL("Unexpected thread state size");
  }
  
  registers->gpr_count = *(mach_exception->new_state_cnt);
  
  memcpy(&registers->gpr_registers,
         mach_exception->new_state,
         registers->gpr_count * sizeof(natural_t));
  
  kern_return_t ret = thread_get_state(mach_exception->thread_port,
                                       ARCH_FPU_STATE,
                                       (thread_state_t)&registers->fpu_registers,
                                       &registers->fpu_count);
  
  if(ret != KERN_SUCCESS) {
    FATAL("Error getting FPU registers");
  }
}

void Debugger::RestoreRegisters(SavedRegisters *registers) {
  if(*mach_exception->new_state_cnt != registers->gpr_count) {
    FATAL("Unexpected thread state size");
  }

  memcpy(mach_exception->new_state,
         &registers->gpr_registers,
         registers->gpr_count * sizeof(natural_t));
  
  kern_return_t ret = thread_set_state(mach_exception->thread_port,
                                       ARCH_FPU_STATE,
                                       (thread_state_t)&registers->fpu_registers,
                                       registers->fpu_count);
  
  if(ret != KERN_SUCCESS) {
    FATAL("Error setting FPU registers");
  }

}

void Debugger::PrintContext() {
  thread_act_t *threads = NULL;
  mach_msg_type_number_t num_threads = 0;
  kern_return_t ret = task_threads(mach_target->Task(), &threads, &num_threads);
  if(ret != KERN_SUCCESS) return;
  for(unsigned i=0;i<num_threads;i++) {
    ARCH_THREAD_STATE_T state;
    unsigned int count = ARCH_THREAD_STATE_COUNT;
    ret = thread_get_state(threads[i], ARCH_THREAD_STATE, (thread_state_t)&state, &count);
    if(ret != KERN_SUCCESS) continue;
#ifdef ARM64
    printf("thread %d\n", i);
    printf("pc: %llx\n", state.__pc);
    printf(" x0: %16llx  x1: %16llx  x2: %16llx  x3: %16llx\n", state.__x[0], state.__x[1], state.__x[2], state.__x[3]);
    printf(" x4: %16llx  x5: %16llx  x6: %16llx  x7: %16llx\n", state.__x[4], state.__x[5], state.__x[6], state.__x[7]);
    printf(" x8: %16llx  x9: %16llx x10: %16llx x11: %16llx\n", state.__x[8], state.__x[9], state.__x[10], state.__x[11]);
    printf("x12: %16llx x13: %16llx x14: %16llx x15: %16llx\n", state.__x[12], state.__x[13], state.__x[14], state.__x[15]);
    printf("x16: %16llx x17: %16llx x18: %16llx x19: %16llx\n", state.__x[16], state.__x[17], state.__x[18], state.__x[19]);
    printf("x20: %16llx x21: %16llx x22: %16llx x23: %16llx\n", state.__x[20], state.__x[21], state.__x[22], state.__x[23]);
    printf("x24: %16llx x25: %16llx x26: %16llx x27: %16llx\n", state.__x[24], state.__x[25], state.__x[26], state.__x[27]);
    printf("x28: %16llx\n", state.__x[28]);
    printf(" sp: %16llx  fp: %16llx  lr: %16llx cpsr: %8x\n", state.__sp, state.__fp, state.__lr, state.__cpsr);
    printf("stack:\n");
    uint64_t stack[100];
    mach_target->ReadMemory(state.__sp, sizeof(stack), stack);
#else
    printf("thread %d\n", i);
    printf("rip:%llx\n", state.__rip);
    printf("rax:%llx rbx:%llx rcx:%llx rdx:%llx\n", state.__rax, state.__rbx, state.__rcx, state.__rdx);
    printf("rsi:%llx rdi:%llx rbp:%llx rsp:%llx\n", state.__rsi, state.__rdi, state.__rbp, state.__rsp);
    printf("r8:%llx r9:%llx r10:%llx r11:%llx\n", state.__r8, state.__r9, state.__r10, state.__r11);
    printf("r12:%llx r13:%llx r14:%llx r15:%llx\n", state.__r12, state.__r13, state.__r14, state.__r15);
    printf("stack:\n");
    uint64_t stack[100];
    mach_target->ReadMemory(state.__rsp, sizeof(stack), stack);
#endif
    for(size_t j=0; j<(sizeof(stack)/sizeof(stack[0])); j++) {
      printf("%16llx\n", stack[j]);
    }
  }
  for(unsigned i=0;i<num_threads;i++) {
    mach_port_deallocate(mach_task_self(), threads[i]);
  }
  vm_deallocate(mach_task_self(), (vm_address_t)threads, num_threads * sizeof(thread_act_t));
}

DebuggerStatus Debugger::DebugLoop(uint32_t timeout) {
  if (!IsTargetAlive()) {
    OnProcessExit();
    return DEBUGGER_PROCESS_EXIT;
  }

  if (dbg_continue_needed) {
    task_resume(mach_target->Task());
  }

  if (dbg_reply_needed) {
    mach_target->ReplyToException(reply_buffer);
  }

  bool alive = true;
  while (alive) {
    dbg_continue_needed = false;
    dbg_reply_needed = false;

    uint64_t begin_time = GetCurTime();
    kern_return_t krt = mach_target->WaitForException(std::min(timeout, (uint32_t)100),
                                                      request_buffer,
                                                      sizeof(union __RequestUnion__catch_mach_exc_subsystem));
    uint64_t end_time = GetCurTime();

    uint64_t time_elapsed = end_time - begin_time;
    timeout = ((uint64_t)timeout >= time_elapsed) ? timeout - (uint32_t)time_elapsed : 0;

    switch (krt) {
      case MACH_RCV_TIMED_OUT:
        if (timeout == 0) {
          task_suspend(mach_target->Task());
          dbg_continue_needed = true;
          return DEBUGGER_HANGED;
        }
        //go down into the MACH_RCV_INTERRUPTED case otherwise

      case MACH_RCV_INTERRUPTED:
        if (!IsTargetAlive()) {
          alive = false;
        }

        continue;

      default:
        if (krt != MACH_MSG_SUCCESS) {
          FATAL("Error (%s) returned by mach_msg (%x)\n", mach_error_string(krt), krt);
        }
    }

    task_suspend(mach_target->Task());
    dbg_continue_needed = true;

    /* mach_exc_server calls catch_mach_exception_raise
       HandleExceptionInternal returns in ret_HandleExceptionInternal */
    boolean_t message_parsed_correctly = mach_exc_server(request_buffer, reply_buffer);
    if (!message_parsed_correctly) {
      krt = ((mig_reply_error_t *)reply_buffer)->RetCode;
      FATAL("Error (%s) returned in reply buffer by mach_exc_server\n", mach_error_string(krt));
    }

    dbg_reply_needed = true;

    if (handle_exception_status == DEBUGGER_CRASHED) {
      OnCrashed(&last_exception);
    }

    if (handle_exception_status == DEBUGGER_PROCESS_EXIT) {
      alive = false;
      continue;
    }

    if (handle_exception_status != DEBUGGER_CONTINUE) {
      return handle_exception_status;
    }

    task_resume(mach_target->Task());
    mach_target->ReplyToException(reply_buffer);
  }

  OnProcessExit();
  return DEBUGGER_PROCESS_EXIT;
}

/**
 * Method not used, implementation is needed by the mach_exc_server method.
*/
kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port,
    mach_port_t thread_port,
    mach_port_t task_port,
    exception_type_t exception_type,
    mach_exception_data_t code,
    mach_msg_type_number_t code_cnt) {
  return MACH_RCV_INVALID_TYPE;
}


/**
 * Method not used, implementation is needed by the mach_exc_server method.
 */
kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port,
    exception_type_t exception_type,
    const mach_exception_data_t code,
    mach_msg_type_number_t code_cnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_state_cnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_state_cnt) {
  return MACH_RCV_INVALID_TYPE;
}

/**
 * Called by mach_exc_server
 *
 * @param exception_port the exception_port registered in AttachToProcess() method
 * @param task_port the target_task
*/
kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread_port,
    mach_port_t task_port,
    exception_type_t exception_type,
    mach_exception_data_t code,
    mach_msg_type_number_t code_cnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_cnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_state_cnt) {

  memcpy(new_state, old_state, old_state_cnt * sizeof(old_state[0]));
  *new_state_cnt = old_state_cnt;

  Debugger::MachException *mach_exception = new Debugger::MachException(exception_port,
                                                                        thread_port,
                                                                        task_port,
                                                                        exception_type,
                                                                        code,
                                                                        code_cnt,
                                                                        flavor,
                                                                        new_state,
                                                                        new_state_cnt);


  class Debugger *dbg = NULL;
  Debugger::map_mutex.lock();
  auto it = Debugger::task_to_debugger_map.find(task_port);
  if (it == Debugger::task_to_debugger_map.end() || it->second == NULL) {
    FATAL("Debugger object could not be found in the map, task port = (%d)\n", task_port);
  }
  dbg = it->second;
  Debugger::map_mutex.unlock();

  if (!dbg->killing_target) {
    dbg->HandleExceptionInternal(mach_exception);
  } else {
    dbg->dbg_continue_status = KERN_FAILURE;
    dbg->handle_exception_status = DEBUGGER_CONTINUE;
  }

  kern_return_t krt;
  krt = mach_port_deallocate(mach_task_self(), task_port);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) deallocating the task port\n", mach_error_string(krt));
  }

  krt = mach_port_deallocate(mach_task_self(), thread_port);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) deallocating the thread port\n", mach_error_string(krt));
  }

  delete mach_exception;
  mach_exception = NULL;
  return dbg->dbg_continue_status;
}

void Debugger::OnProcessExit() {
  if (trace_debug_events) {
    SAY("Debugger: Process exit\n");
  }

  if (mach_target != NULL) {
    map_mutex.lock();
    int removed = task_to_debugger_map.erase(mach_target->Task());
    if (removed == 0) {
      WARN("There is no task port (%u) in task_to_debugger_map to be erased", mach_target->Task());
    }
    map_mutex.unlock();

    mach_target->CleanUp();
    delete mach_target;
    mach_target = NULL;

    ClearSharedMemory();
  }

  // collect any zombie processes at this point
  int status;
  while(wait3(&status, WNOHANG, 0) > 0);
}


DebuggerStatus Debugger::Kill() {
  if (mach_target == NULL) {
    return DEBUGGER_PROCESS_EXIT;
  }

  killing_target = true;
  int target_pid = mach_target->Pid();
  kill(target_pid, SIGKILL);

  //SIGKILL is not handled, so DebugLoop must return DEBUGGER_PROCESS_EXIT
  dbg_last_status = DebugLoop(0xffffffff);
  if (dbg_last_status != DEBUGGER_PROCESS_EXIT || IsTargetAlive()) {
    FATAL("Unable to kill the process\n");
  }

  DeleteBreakpoints();
  killing_target = false;

  return dbg_last_status;
}

char **Debugger::GetEnvp() {
  int environ_size = 0;
  char **p = environ;
  while (*p) {
    environ_size += 1;
    p++;
  }

  additional_env.push_back("DYLD_SHARED_REGION=private");

  int envp_size = environ_size + additional_env.size();
  char **envp = (char**)malloc(sizeof(char*)*(envp_size+1));
  int i;
  for (i = 0; i < environ_size; ++i) {
    envp[i] = (char*)malloc(strlen(environ[i])+1);
    strcpy(envp[i], environ[i]);
  }

  for(auto iter = additional_env.begin(); iter != additional_env.end(); iter++) {
    envp[i] = (char*)malloc(iter->size() + 1);
    strcpy(envp[i], iter->c_str());
    i++;
  }

  envp[envp_size] = NULL;

  return envp;
}


void Debugger::StartProcess(int argc, char **argv) {
  if (argc <= 0) {
    FATAL("Number of arguments is not strictly positive");
  }

  pid_t pid;
  int status;
  posix_spawnattr_t attr;

  status = posix_spawnattr_init(&attr);
  if (status != 0) {
    FATAL("Unable to init spawnattr");
  }
  
  short posix_flags = POSIX_SPAWN_START_SUSPENDED;
  if(disable_aslr) {
    posix_flags |= _POSIX_SPAWN_DISABLE_ASLR;
  }
  status = posix_spawnattr_setflags(&attr, posix_flags);
  if (status != 0) {
    FATAL("Unable to set flags in posix_spawnattr_setflags");
  }

  char **envp = GetEnvp();
  status = posix_spawn(&pid, argv[0], NULL, &attr, argv, envp);
  if (status != 0) {
    FATAL("Error (%s) spawning the process\n", strerror(status));
  }

  for (char **p = envp; *p; p++) {
    free(*p);
  }
  free(envp);

  mach_target = new MachTarget(pid);
}


void Debugger::AttachToProcess() {
  killing_target = false;
  dbg_continue_needed = false;
  dbg_reply_needed = false;
  child_entrypoint_reached = false;
  target_reached = false;

  DeleteBreakpoints();

  int ptrace_ret;
  ptrace_ret = ptrace(PT_ATTACHEXC, mach_target->Pid(), 0, 0);
  if (ptrace_ret == -1) {
    FATAL("Unable to ptrace PT_ATTACHEXC to the target process\n");
  }

  map_mutex.lock();
  task_to_debugger_map[mach_target->Task()] = this;
  map_mutex.unlock();

  dbg_last_status = DEBUGGER_ATTACHED;
}


DebuggerStatus Debugger::Attach(unsigned int pid, uint32_t timeout) {
  attach_mode = true;
  mach_target = new MachTarget(pid);

  AttachToProcess();
  return Continue(timeout);
}


DebuggerStatus Debugger::Run(char *cmd, uint32_t timeout) {
  FATAL("Deprecated Run interface on macOS - use Run(int argc, char **argv, uint32_t timeout) instead");
}


DebuggerStatus Debugger::Run(int argc, char **argv, uint32_t timeout) {
  attach_mode = false;

  StartProcess(argc, argv);
  AttachToProcess();
  return Continue(timeout);
}

DebuggerStatus Debugger::Continue(uint32_t timeout) {
  if (loop_mode && (dbg_last_status == DEBUGGER_TARGET_END)) {
    dbg_last_status = DEBUGGER_TARGET_START;
    return dbg_last_status;
  }

  dbg_last_status = DebugLoop(timeout);
  return dbg_last_status;
}


void Debugger::Init(int argc, char **argv) {
  mach_target = NULL;
  killing_target = false;

  attach_mode = false;
  trace_debug_events = false;
  loop_mode = false;
  disable_aslr = false;
  target_function_defined = false;
  
  target_return_value = 0;

  target_module[0] = 0;
  target_method[0] = 0;
  target_offset = 0;
  saved_args = NULL;
  target_num_args = 0;
  target_address = NULL;
  
#ifdef ARM64
  target_end_detection = RETADDR_BREAKPOINT;
#else
  target_end_detection = RETADDR_STACK_OVERWRITE;
#endif

  dbg_last_status = DEBUGGER_NONE;
  shared_memory.clear();

  dbg_continue_needed = false;
  dbg_reply_needed = false;
  request_buffer = (mach_msg_header_t *)malloc(sizeof(union __RequestUnion__catch_mach_exc_subsystem));
  reply_buffer = (mach_msg_header_t *)malloc(sizeof(union __ReplyUnion__catch_mach_exc_subsystem));

  std::list<char *> env_options;
  GetOptionAll("-target_env", argc, argv, &env_options);
  for (auto iter = env_options.begin(); iter != env_options.end(); iter++) {
    additional_env.push_back(*iter);
  }
  
  char *option;
  trace_debug_events = GetBinaryOption("-trace_debug_events",
                                       argc, argv,
                                       trace_debug_events);

  option = GetOption("-target_module", argc, argv);
  if (option) strncpy(target_module, option, PATH_MAX);

  option = GetOption("-target_method", argc, argv);
  if (option) strncpy(target_method, option, PATH_MAX);

  loop_mode = GetBinaryOption("-loop", argc, argv, loop_mode);
  disable_aslr = GetBinaryOption("-disable_aslr", argc, argv, disable_aslr);

  option = GetOption("-nargs", argc, argv);
  if (option) target_num_args = atoi(option);

  option = GetOption("-target_offset", argc, argv);
  if (option) target_offset = strtoul(option, NULL, 0);

  // check if we are running in persistence mode
  if (target_module[0] || target_offset || target_method[0]) {
    target_function_defined = true;
    if ((target_module[0] == 0) || ((target_offset == 0) && (target_method[0] == 0))) {
      FATAL("target_module and either target_offset or target_method must be specified together\n");
    }
  }

  if (loop_mode && !target_function_defined) {
    FATAL("Target function needs to be defined to use the loop mode\n");
  }
  
  // avoid overwriting return address in case we have libgmalloc in env
  for (auto iter = additional_env.begin(); iter != additional_env.end(); iter++) {
    if (iter->find("libgmalloc") != std::string::npos) {
      target_end_detection = RETADDR_BREAKPOINT;
    }
  }

  if (target_num_args) {
    saved_args = (void **)malloc(target_num_args * sizeof(void *));
  }

  m_dyld_process_info_create =
      (void *(*)(task_t task, uint64_t timestamp, kern_return_t * kernelError))
          dlsym(RTLD_DEFAULT, "_dyld_process_info_create");
  m_dyld_process_info_for_each_image =
      (void (*)(void *info, void (^)(uint64_t machHeaderAddress,
                                     const uuid_t uuid, const char *path)))
          dlsym(RTLD_DEFAULT, "_dyld_process_info_for_each_image");
  m_dyld_process_info_release =
      (void (*)(void *info))dlsym(RTLD_DEFAULT, "_dyld_process_info_release");
}
