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

#include "debugger.h"
#include "../common.h"

#define BREAKPOINT_UNKNOWN 0x0
#define BREAKPOINT_ENTRYPOINT 0x01
#define BREAKPOINT_TARGET 0x02
#define BREAKPOINT_NOTIFICATION 0x04

#define PERSIST_END_EXCEPTION 0x0F22

extern char **environ;
#define GMALLOC_ENV_CONFIG "DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib"

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

void Debugger::FreeShare(void *address, size_t size) {
  if (size == 0) {
    WARN("FreeShare is called with size == 0\n");
    return;
  }

  mach_port_t shm_port = mach_target->ShmPorts()[(mach_vm_address_t)address];
  kern_return_t krt = mach_port_destroy(mach_target->Task(), shm_port);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) destroy port for shared memory @ 0x%llx\n", mach_error_string(krt), (mach_vm_address_t)address);
  }

  krt = mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)address, (mach_vm_size_t)size);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) freeing memory @ 0x%llx\n", mach_error_string(krt), (mach_vm_address_t)address);
  }
}

void Debugger::RemoteFree(void *address, size_t size) {
  mach_target->FreeMemory((uint64_t)address, size);
}

void Debugger::RemoteRead(void *address, void *buffer, size_t size) {
  mach_target->ReadMemory((uint64_t)address, size, buffer);
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
  exception->ip = (void*)GetRegister(RIP);

  switch (mach_exception->exception_type) {
    case EXC_BREAKPOINT:
      exception->type = BREAKPOINT;
      exception->ip = (void*)((uint64_t)exception->ip - 1);
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
  x86_thread_state64_t *state = (x86_thread_state64_t*)(mach_exception->new_state);
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
}

size_t Debugger::GetRegister(Register r) {
  uint64_t *reg_pointer = GetPointerToRegister(r);
  return *reg_pointer;
}

void Debugger::SetRegister(Register r, size_t value) {
  uint64_t *reg_pointer = GetPointerToRegister(r);
  *reg_pointer = value;
}

Debugger::Register Debugger::ArgumentToRegister(int arg) {
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
void Debugger::GetLoadCommand(mach_header_64 mach_header,
                              void *load_commands_buffer,
                              uint32_t load_cmd_type,
                              const char segname[16],
                              TCMD **ret_command) {
  uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
  for (int i = 0; i < mach_header.ncmds; ++i) {
    load_command *load_cmd = (load_command *)load_cmd_addr;
    if (load_cmd->cmd == load_cmd_type) {
      TCMD *t_cmd = (TCMD*)load_cmd;
      if (load_cmd_type != LC_SEGMENT_64
          || !strcmp(((segment_command_64*)t_cmd)->segname, segname)) {
        *ret_command = (TCMD*)load_cmd;
        return;
      }
    }

    load_cmd_addr += load_cmd->cmdsize;
  }
}

void *Debugger::MakeEntryRemoteAddress(mach_vm_address_t address, size_t size) {
  mach_port_t shm_port;

  memory_object_size_t memoryObjectSize = round_page(size);
  kern_return_t ret = mach_make_memory_entry_64(mach_target->Task(), &memoryObjectSize, address, VM_PROT_READ, &shm_port, MACH_PORT_NULL);
  if (ret != KERN_SUCCESS) {
    FATAL("Error (%s) remote allocate share memory\n", mach_error_string(ret));
  }

  mach_vm_address_t map_address;
  ret = mach_vm_map(mach_task_self(), &map_address, memoryObjectSize, 0, VM_FLAGS_ANYWHERE, shm_port, 0, 0, VM_PROT_READ, VM_PROT_READ, VM_INHERIT_NONE);
  if (ret != KERN_SUCCESS) {
    FATAL("Error (%s) map memory\n", mach_error_string(ret));
  }
  mach_target->ShmPorts()[map_address] = shm_port;

  return (void *)map_address;
}

void *Debugger::RemoteAllocateNear(uint64_t region_min,
                                        uint64_t region_max,
                                        size_t size,
                                        MemoryProtection protection) {
  uint64_t min_address, max_address;

  //try after first
  min_address = region_max;
  max_address = (UINT64_MAX - region_min < 0x80000000) ? UINT64_MAX : region_min + 0x80000000;
  void *ret_address = RemoteAllocateAfter(min_address, max_address, size, protection);
  if (ret_address != NULL) {
    return ret_address;
  }

  //try before second
  min_address = (region_max < 0x80000000) ? 0 : region_max - 0x80000000;
  max_address = (region_min < size) ? 0 : region_min - size;
  ret_address = RemoteAllocateBefore(min_address, max_address, size, protection);
  if (ret_address != NULL) {
    return ret_address;
  }

  // if all else fails, try within
  return RemoteAllocateAfter(region_min, region_max, size, protection);
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
  RemoteRead(address, &(new_breakpoint->original_opcode), 1);

  unsigned char cc = 0xCC;
  RemoteWrite(address, (void*)&cc, 1);

  new_breakpoint->address = address;
  new_breakpoint->type = type;
  breakpoints.push_back(new_breakpoint);
}


void Debugger::HandleTargetReachedInternal() {
  saved_sp = (void*)GetRegister(RSP);
  RemoteRead(saved_sp, &saved_return_address, child_ptr_size);

  if (loop_mode) {
    for (int arg_index = 0; arg_index < 6 && arg_index < target_num_args; ++arg_index) {
      saved_args[arg_index] = (void*)GetRegister(ArgumentToRegister(arg_index));
    }

    if (target_num_args > 6) {
      RemoteRead((void*)((uint64_t)saved_sp + child_ptr_size),
                 saved_args + 6,
                 child_ptr_size * (target_num_args - 6));
    }
  }

  size_t return_address = PERSIST_END_EXCEPTION;
  RemoteWrite(saved_sp, &return_address, child_ptr_size);

  if (!target_reached) {
    target_reached = true;
    OnTargetMethodReached();
  }
}


void Debugger::HandleTargetEnded() {
  if (loop_mode) {
    SetRegister(RIP, (size_t)target_address);
    SetRegister(RSP, (size_t)saved_sp);

    size_t return_address = PERSIST_END_EXCEPTION;
    RemoteWrite(saved_sp, &return_address, child_ptr_size);

    for (int arg_index = 0; arg_index < 6 && arg_index < target_num_args; ++arg_index) {
      SetRegister(ArgumentToRegister(arg_index), (size_t)saved_args[arg_index]);
    }

    if (target_num_args > 6) {
      RemoteWrite((void*)((uint64_t)saved_sp + child_ptr_size),
                  saved_args + 6,
                  child_ptr_size * (target_num_args - 6));
    }
  } else {
    SetRegister(RIP, (size_t)saved_return_address);
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
  GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd);
  if (text_cmd == NULL) {
    FATAL("Unable to find __TEXT command in ExtractCodeRanges\n");
  }
  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;

  *code_size = 0;
  for (auto &it: *executable_ranges) {
    free(it.data);
  }
  executable_ranges->clear();

  uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
  for (int i = 0; i < mach_header.ncmds; ++i) {
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
            FATAL("Unable to re-allocate memory after deallocate in ExtractCodeRanges\n");
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
  for (int i = 0; i < mach_header.ncmds; ++i) {
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
  GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd);
  if (text_cmd == NULL) {
    FATAL("Unable to find __TEXT command in ExtractCodeRanges\n");
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
  GetLoadCommand(mach_header, load_commands_buffer, LC_MAIN, NULL, &entry_point_cmd);
  if (entry_point_cmd == NULL) {
    FATAL("Unable to find ENTRY POINT command in GetModuleEntrypoint\n");
  }

  uint64_t entryoff = entry_point_cmd->entryoff;

  free(load_commands_buffer);
  return (void*)((uint64_t)base_address + entryoff);
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
  GetLoadCommand(mach_header, load_commands_buffer, LC_SYMTAB, NULL, &symtab_cmd);
  if (symtab_cmd == NULL) {
    FATAL("Unable to find SYMTAB command in GetSymbolAddress\n");
  }

  segment_command_64 *linkedit_cmd = NULL;
  GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__LINKEDIT", &linkedit_cmd);
  if (linkedit_cmd == NULL) {
    FATAL("Unable to find __LINKEDIT command in GetSymbolAddress\n");
  }

  segment_command_64 *text_cmd = NULL;
  GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd);
  if (text_cmd == NULL) {
    FATAL("Unable to find __TEXT command in GetSymbolAddress\n");
  }

  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;

  char *strtab = (char*)malloc(symtab_cmd->strsize);
  uint64_t strtab_addr = linkedit_cmd->vmaddr + file_vm_slide
                         + symtab_cmd->stroff - linkedit_cmd->fileoff;
  RemoteRead((void*)strtab_addr, strtab, symtab_cmd->strsize);

  void *symbol_address = NULL;
  for (int i = 0; i < symtab_cmd->nsyms && !symbol_address; ++i) {
    uint64_t nlist_addr = linkedit_cmd->vmaddr + file_vm_slide
                          + symtab_cmd->symoff - linkedit_cmd->fileoff + i * sizeof(nlist_64);

    nlist_64 symbol = {0};
    RemoteRead((void*)nlist_addr, &symbol, sizeof(nlist_64));

    if ((symbol.n_type & N_TYPE) == N_SECT) {
      char *sym_name_start = strtab + symbol.n_un.n_strx;
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

    // This save us the recurring TRAP FLAG breakpoint on BREAKPOINT_NOTIFICATION.
    unsigned char ret = 0xC3;
    RemoteWrite((void*)((uint64_t)m_dyld_debugger_notification+1), (void*)&ret, 1);
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
    for (int i = 0; i < all_image_infos.infoArrayCount; ++i) {
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

  RemoteWrite(breakpoint->address, &breakpoint->original_opcode, 1);
  SetRegister(RIP, GetRegister(RIP) - 1); //INTEL

  if (breakpoint->type & BREAKPOINT_ENTRYPOINT) {
      OnEntrypoint();
  }

  if (breakpoint->type & BREAKPOINT_TARGET) {
      if (trace_debug_events) {
        SAY("Target method reached\n");
      }
      HandleTargetReachedInternal();
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
          FATAL("Error (%s) returned by mach_msg\n", mach_error_string(krt));
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

    int target_pid = mach_target->Pid();

    mach_target->CleanUp();
    delete mach_target;
    mach_target = NULL;

    int status;
    while(waitpid(target_pid, &status, WNOHANG) == target_pid);
  }
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

  int envp_size = environ_size + ((gmalloc_mode)?1:0);
  char **envp = (char**)malloc(sizeof(char*)*(envp_size+1));
  for (int i = 0; i < environ_size; ++i) {
    envp[i] = (char*)malloc(strlen(environ[i])+1);
    strcpy(envp[i], environ[i]);
  }

  if (gmalloc_mode) {
    envp[envp_size-1] = (char*)malloc(strlen(GMALLOC_ENV_CONFIG)+1);
    strcpy(envp[envp_size-1], GMALLOC_ENV_CONFIG);
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

  status = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
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
  target_function_defined = false;
  gmalloc_mode = false;

  target_module[0] = 0;
  target_method[0] = 0;
  target_offset = 0;
  saved_args = NULL;
  target_num_args = 0;
  target_address = NULL;

  dbg_last_status = DEBUGGER_NONE;

  dbg_continue_needed = false;
  dbg_reply_needed = false;
  request_buffer = (mach_msg_header_t *)malloc(sizeof(union __RequestUnion__catch_mach_exc_subsystem));
  reply_buffer = (mach_msg_header_t *)malloc(sizeof(union __ReplyUnion__catch_mach_exc_subsystem));

  char *option;
  trace_debug_events = GetBinaryOption("-trace_debug_events",
                                       argc, argv,
                                       trace_debug_events);

  option = GetOption("-target_module", argc, argv);
  if (option) strncpy(target_module, option, PATH_MAX);

  option = GetOption("-target_method", argc, argv);
  if (option) strncpy(target_method, option, PATH_MAX);

  loop_mode = GetBinaryOption("-loop", argc, argv, loop_mode);
  gmalloc_mode = GetBinaryOption("-gmalloc", argc, argv, gmalloc_mode);

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
