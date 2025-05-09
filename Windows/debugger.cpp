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

#include "windows.h"
#include "psapi.h"
#include "dbghelp.h"

#include "../common.h"
#include "debugger.h"

#define BREAKPOINT_UNKNOWN 0
#define BREAKPOINT_ENTRYPOINT 1
#define BREAKPOINT_TARGET 2

#define PERSIST_END_EXCEPTION 0x0F22

// cleans up all breakpoint structures
// does not actually remove breakpoints in target process 
void Debugger::DeleteBreakpoints() {
  for (auto iter = breakpoints.begin(); iter != breakpoints.end(); ++iter) {
    delete *iter;
  }
  breakpoints.clear();
}

void Debugger::CreateException(EXCEPTION_RECORD *win_exception_record,
                               Exception *exception)
{
  switch (win_exception_record->ExceptionCode) {
  case EXCEPTION_BREAKPOINT:
  case 0x4000001f:
    exception->type = BREAKPOINT;
    break;
  case EXCEPTION_ACCESS_VIOLATION:
    exception->type = ACCESS_VIOLATION;
    break;
  case EXCEPTION_ILLEGAL_INSTRUCTION:
    exception->type = ILLEGAL_INSTRUCTION;
    break;
  case EXCEPTION_STACK_OVERFLOW:
    exception->type = STACK_OVERFLOW;
    break;
  default:
    exception->type = OTHER;
    break;
  }

  exception->ip = win_exception_record->ExceptionAddress;

  exception->maybe_execute_violation = false;
  exception->maybe_write_violation = false;
  exception->access_address = 0;
  if (win_exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    if (win_exception_record->ExceptionInformation[0] == 8) {
      exception->maybe_execute_violation = true;
    }
    if (win_exception_record->ExceptionInformation[0] == 1) {
      exception->maybe_write_violation = true;
    }

    exception->access_address = (void *)(win_exception_record->ExceptionInformation[1]);
  }
}

void Debugger::RetrieveThreadContext() {
  if (have_thread_context) return; // already done
  lcContext.ContextFlags = CONTEXT_ALL;
  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  GetThreadContext(thread_handle, &lcContext);
  CloseHandle(thread_handle);
  have_thread_context = true;
}

void Debugger::SaveRegisters(SavedRegisters* registers) {
  RetrieveThreadContext();
  memcpy(&registers->saved_context, &lcContext, sizeof(registers->saved_context));
}

void Debugger::RestoreRegisters(SavedRegisters* registers) {
  have_thread_context = false;
  memcpy(&lcContext, &registers->saved_context, sizeof(registers->saved_context));

  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  if (!SetThreadContext(thread_handle, &lcContext)) {
    FATAL("Error restoring registers");
  }
  CloseHandle(thread_handle);
}

size_t Debugger::GetRegister(Register r) {
  RetrieveThreadContext();

#ifdef _WIN64

  switch (r) {
  case RAX:
    return lcContext.Rax;
  case RCX:
    return lcContext.Rcx;
  case RDX:
    return lcContext.Rdx;
  case RBX:
    return lcContext.Rbx;
  case RSP:
    return lcContext.Rsp;
  case RBP:
    return lcContext.Rbp;
  case RSI:
    return lcContext.Rsi;
  case RDI:
    return lcContext.Rdi;
  case R8:
    return lcContext.R8;
  case R9:
    return lcContext.R9;
  case R10:
    return lcContext.R10;
  case R11:
    return lcContext.R11;
  case R12:
    return lcContext.R12;
  case R13:
    return lcContext.R13;
  case R14:
    return lcContext.R14;
  case R15:
    return lcContext.R15;
  case RIP:
    return lcContext.Rip;
  default:
    FATAL("Unimplemented");
  }

#else

  switch (r) {
  case RAX:
    return lcContext.Eax;
  case RCX:
    return lcContext.Ecx;
  case RDX:
    return lcContext.Edx;
  case RBX:
    return lcContext.Ebx;
  case RSP:
    return lcContext.Esp;
  case RBP:
    return lcContext.Ebp;
  case RSI:
    return lcContext.Esi;
  case RDI:
    return lcContext.Edi;
  case RIP:
    return lcContext.Eip;
  default:
    FATAL("Unimplemented");
}

#endif

}

void Debugger::SetRegister(Register r, size_t value) {
  RetrieveThreadContext();

#ifdef _WIN64

  switch (r) {
  case RAX:
    lcContext.Rax = value;
    break;
  case RCX:
    lcContext.Rcx = value;
    break;
  case RDX:
    lcContext.Rdx = value;
    break;
  case RBX:
    lcContext.Rbx = value;
    break;
  case RSP:
    lcContext.Rsp = value;
    break;
  case RBP:
    lcContext.Rbp = value;
    break;
  case RSI:
    lcContext.Rsi = value;
    break;
  case RDI:
    lcContext.Rdi = value;
    break;
  case R8:
    lcContext.R8 = value;
    break;
  case R9:
    lcContext.R9 = value;
    break;
  case R10:
    lcContext.R10 = value;
    break;
  case R11:
    lcContext.R11 = value;
    break;
  case R12:
    lcContext.R12 = value;
    break;
  case R13:
    lcContext.R13 = value;
    break;
  case R14:
    lcContext.R14 = value;
    break;
  case R15:
    lcContext.R15 = value;
    break;
  case RIP:
    lcContext.Rip = value;
    break;
  default:
    FATAL("Unimplemented");
  }

#else

  switch (r) {
  case RAX:
    lcContext.Eax = value;
    break;
  case RCX:
    lcContext.Ecx = value;
    break;
  case RDX:
    lcContext.Edx = value;
    break;
  case RBX:
    lcContext.Ebx = value;
    break;
  case RSP:
    lcContext.Esp = value;
    break;
  case RBP:
    lcContext.Ebp = value;
    break;
  case RSI:
    lcContext.Esi = value;
    break;
  case RDI:
    lcContext.Edi = value;
    break;
  case RIP:
    lcContext.Eip = value;
    break;
  default:
    FATAL("Unimplemented");
  }

#endif

  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  SetThreadContext(thread_handle, &lcContext);
  CloseHandle(thread_handle);
}


// converts between MemoryProtection and Windows protection flags
DWORD Debugger::WindowsProtectionFlags(MemoryProtection protection) {
  switch (protection) {
  case READONLY:
    return PAGE_READONLY;
  case READWRITE:
    return PAGE_READWRITE;
  case READEXECUTE:
    return PAGE_EXECUTE_READ;
  case READWRITEEXECUTE:
    return PAGE_EXECUTE_READWRITE;
  default:
    FATAL("Unumplemented memory protection");
  }
}

// allocates memory within 2GB of memory region
// between region_min and region_max
void *Debugger::RemoteAllocateNear(uint64_t region_min,
  uint64_t region_max,
  size_t size,
  MemoryProtection protection,
  bool use_shared_memory)
{
  void *ret = NULL;

  // try before first
  uint64_t min_address = region_max;
  if (min_address < 0x80000000) min_address = 0;
  else min_address -= 0x80000000;
  uint64_t max_address = region_min;
  if (max_address < size) max_address = 0;
  else max_address -= size;

  ret = RemoteAllocateBefore(min_address,
    max_address,
    size,
    protection);

  if (ret) return ret;

  min_address = region_max;
  uint64_t address_range_max = 0xFFFFFFFFFFFFFFFFULL;
  if (child_ptr_size == 4) {
    address_range_max = 0xFFFFFFFFULL;
  }
  if ((address_range_max - 0x80000000) < region_min) {
    max_address = address_range_max - size;
  } else {
    max_address = region_min + 0x80000000 - size;
  }

  ret = RemoteAllocateAfter(min_address,
    max_address,
    size,
    protection);

  return ret;
}

// allocates memory in target process
void* Debugger::RemoteAllocate(size_t size, MemoryProtection protection) {
  DWORD protection_flags = WindowsProtectionFlags(protection);

  void* ret_address = VirtualAllocEx(child_handle,
    0,
    size,
    MEM_COMMIT | MEM_RESERVE,
    protection_flags);

  return ret_address;
}

// allocates memory in target process as close as possible
// to max_address, but at address larger than min_address
void *Debugger::RemoteAllocateBefore(uint64_t min_address,
  uint64_t max_address,
  size_t size,
  MemoryProtection protection)
{
  DWORD protection_flags = WindowsProtectionFlags(protection);

  MEMORY_BASIC_INFORMATION meminfobuf;
  void *ret_address = NULL;

  uint64_t cur_code = max_address;
  while (cur_code > min_address) {
    // Don't attempt allocating on the null page
    if (cur_code < 0x1000) break;

    size_t step = size;

    size_t query_ret = VirtualQueryEx(child_handle,
      (LPCVOID)cur_code,
      &meminfobuf,
      sizeof(MEMORY_BASIC_INFORMATION));
    if (!query_ret) break;

    if (meminfobuf.State == MEM_FREE) {
      if (meminfobuf.RegionSize >= size) {
        size_t address = (size_t)meminfobuf.BaseAddress +
          (meminfobuf.RegionSize - size);
        ret_address = VirtualAllocEx(child_handle,
          (LPVOID)address,
          size,
          MEM_COMMIT | MEM_RESERVE,
          protection_flags);
        if (ret_address) {
          if (((size_t)ret_address >= min_address) &&
            ((size_t)ret_address <= max_address)) {
            return ret_address;
          } else {
            return NULL;
          }
        }
      } else {
        step = size - meminfobuf.RegionSize;
      }
    }

    cur_code = (size_t)meminfobuf.BaseAddress;
    if (cur_code < step) break;
    else cur_code -= step;
  }

  return ret_address;
}

// allocates memory in target process as close as possible
// to min_address, but not higher than max_address
void *Debugger::RemoteAllocateAfter(uint64_t min_address,
  uint64_t max_address,
  size_t size,
  MemoryProtection protection)
{
  DWORD protection_flags = WindowsProtectionFlags(protection);

  MEMORY_BASIC_INFORMATION meminfobuf;
  void *ret_address = NULL;

  uint64_t cur_code = min_address;
  while (cur_code < max_address) {
    size_t query_ret = VirtualQueryEx(child_handle,
      (LPCVOID)cur_code,
      &meminfobuf,
      sizeof(MEMORY_BASIC_INFORMATION));
    if (!query_ret) break;

    if (meminfobuf.State == MEM_FREE) {
      size_t region_address = (size_t)meminfobuf.BaseAddress;
      size_t region_size = meminfobuf.RegionSize;
      // make sure we are allocating on an address that
      // is aligned according to allocation_granularity
      size_t alignment = region_address & (allocation_granularity - 1);
      if (alignment) {
        size_t offset = (allocation_granularity - alignment);
        region_address += offset;
        if (region_size > offset) {
          region_size -= offset;
        } else {
          region_size = 0;
        }
      }
      if (region_size >= size) {
        ret_address = VirtualAllocEx(child_handle,
          (LPVOID)region_address,
          size,
          MEM_COMMIT | MEM_RESERVE,
          protection_flags);
        if (ret_address) {
          if (((size_t)ret_address >= min_address) &&
            ((size_t)ret_address <= max_address)) {
            return ret_address;
          } else {
            return NULL;
          }
        }
      }
    }

    cur_code = (size_t)meminfobuf.BaseAddress + meminfobuf.RegionSize;
  }

  return ret_address;
}

void Debugger::RemoteFree(void *address, size_t size) {
  if (!child_handle) return;
  VirtualFreeEx(child_handle, address, 0, MEM_RELEASE);
}

void Debugger::RemoteWrite(void *address, const void *buffer, size_t size) {
  SIZE_T size_written;
  if (WriteProcessMemory(
    child_handle,
    address,
    buffer,
    size,
    &size_written))
  {
    return;
  }

  // we need to (a) read page permissions
  // (b) make it writable, and (c) restore permissions
  DWORD oldProtect;
  if (!VirtualProtectEx(child_handle,
    address,
    size,
    PAGE_READWRITE,
    &oldProtect))
  {
    FATAL("Error in VirtualProtectEx");
  }

  if (!WriteProcessMemory(
    child_handle,
    address,
    buffer,
    size,
    &size_written))
  {
    FATAL("Error writing target memory\n");
  }

  DWORD ignore;
  if (!VirtualProtectEx(child_handle,
    address,
    size,
    oldProtect,
    &ignore))
  {
    FATAL("Error in VirtualProtectEx");
  }
}

void Debugger::RemoteRead(void *address, void *buffer, size_t size) {
  SIZE_T size_read;
  if (!ReadProcessMemory(
    child_handle,
    address,
    buffer,
    size,
    &size_read))
  {
    FATAL("Error reading target memory\n");
  }
}

void Debugger::RemoteProtect(void *address, size_t size, MemoryProtection protect) {
  DWORD protection_flags = WindowsProtectionFlags(protect);
  DWORD old_protect;

  if (!VirtualProtectEx(child_handle,
    address,
    size,
    protection_flags,
    &old_protect))
  {
    FATAL("Could not apply memory protection");
  }
}


// detects executable memory regions in the module
// makes them non-executable
// and copies code out into this process
void Debugger::ExtractCodeRanges(void *module_base,
                                 size_t min_address,
                                 size_t max_address,
                                 std::list<AddressRange> *executable_ranges,
                                 size_t *code_size,
                                 bool do_protect)
{
  LPCVOID end_address = (void *)max_address;
  LPCVOID cur_address = (void *)min_address;
  MEMORY_BASIC_INFORMATION meminfobuf;

  AddressRange newRange;

  for (auto iter = executable_ranges->begin();
    iter != executable_ranges->end(); iter++)
  {
    free(iter->data);
  }
  executable_ranges->clear();
  *code_size = 0;

  while (cur_address < end_address) {
    size_t ret = VirtualQueryEx(child_handle,
      cur_address,
      &meminfobuf,
      sizeof(MEMORY_BASIC_INFORMATION));
    if (!ret) break;

    if (meminfobuf.Protect & 0xF0) {
      // printf("%p, %llx, %lx\n", meminfobuf.BaseAddress, meminfobuf.RegionSize, meminfobuf.Protect);

      SIZE_T size_read;
      newRange.data = (char *)malloc(meminfobuf.RegionSize);
      if (!ReadProcessMemory(child_handle,
        meminfobuf.BaseAddress,
        newRange.data,
        meminfobuf.RegionSize,
        &size_read))
      {
        FATAL("Error in ReadProcessMemory");
      }
      if (size_read != meminfobuf.RegionSize) {
        FATAL("Error in ReadProcessMemory");
      }

      if(do_protect) {
        uint8_t low = meminfobuf.Protect & 0xFF;
        low = low >> 4;
        DWORD newProtect = (meminfobuf.Protect & 0xFFFFFF00) + low;
        DWORD oldProtect;
        if (!VirtualProtectEx(child_handle,
                              meminfobuf.BaseAddress,
                              meminfobuf.RegionSize,
                              newProtect,
                              &oldProtect))
        {
          FATAL("Error in VirtualProtectEx");
        }
      }

      newRange.from = (size_t)meminfobuf.BaseAddress;
      newRange.to = (size_t)meminfobuf.BaseAddress + meminfobuf.RegionSize;
      executable_ranges->push_back(newRange);

      *code_size += newRange.to - newRange.from;
    }

    cur_address = (char *)meminfobuf.BaseAddress + meminfobuf.RegionSize;
  }
}

// sets all pages containing (previously detected)
// code to non-executable
void Debugger::ProtectCodeRanges(std::list<AddressRange> *executable_ranges) {
  MEMORY_BASIC_INFORMATION meminfobuf;

  for (auto iter = executable_ranges->begin();
    iter != executable_ranges->end(); iter++)
  {
    size_t ret = VirtualQueryEx(child_handle,
      (void *)iter->from,
      &meminfobuf,
      sizeof(MEMORY_BASIC_INFORMATION));

    // if the module was already instrumented, everything must be the same as before
    if (!ret) {
      FATAL("Error in ProtectCodeRanges."
        "Target incompatible with persist_instrumentation_data");
    }
    if (iter->from != (size_t)meminfobuf.BaseAddress) {
      FATAL("Error in ProtectCodeRanges."
        "Target incompatible with persist_instrumentation_data");
    }
    if (iter->to != (size_t)meminfobuf.BaseAddress + meminfobuf.RegionSize) {
      FATAL("Error in ProtectCodeRanges."
        "Target incompatible with persist_instrumentation_data");
    }
    if (!(meminfobuf.Protect & 0xF0)) {
      FATAL("Error in ProtectCodeRanges."
        "Target incompatible with persist_instrumentation_data");
    }

    uint8_t low = meminfobuf.Protect & 0xFF;
    low = low >> 4;
    DWORD newProtect = (meminfobuf.Protect & 0xFFFFFF00) + low;
    DWORD oldProtect;
    if (!VirtualProtectEx(child_handle,
      meminfobuf.BaseAddress,
      meminfobuf.RegionSize,
      newProtect,
      &oldProtect))
    {
      FATAL("Error in VirtualProtectEx");
    }
  }
}

void Debugger::PatchPointersRemote(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace) {
  if (child_ptr_size == 4) {
    PatchPointersRemoteT<uint32_t>(min_address, max_address, search_replace);
  } else {
    PatchPointersRemoteT<uint64_t>(min_address, max_address, search_replace);
  }
}

template<typename T>
void Debugger::PatchPointersRemoteT(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace) {
  size_t module_size = max_address - min_address;
  char* buf = (char *)malloc(module_size);
  RemoteRead((void *)min_address, buf, module_size);

  size_t remote_address = min_address;
  for (size_t i = 0; i < (module_size - child_ptr_size + 1); i++) {
    T ptr = *(T *)(buf + i);
    auto iter = search_replace.find(ptr);
    if (iter != search_replace.end()) {
      // printf("patching entry %zx at address %zx\n", (size_t)ptr, remote_address);
      T fixed_ptr = (T)iter->second;
      RemoteWrite((void *)remote_address, &fixed_ptr, child_ptr_size);
    }
    remote_address += 1;
  }

  free(buf);
}

// returns an array of handles for all modules loaded in the target process
DWORD Debugger::GetLoadedModules(HMODULE **modules) {
  DWORD module_handle_storage_size = 1024 * sizeof(HMODULE);
  HMODULE *module_handles = (HMODULE *)malloc(module_handle_storage_size);
  DWORD hmodules_size;
  while (true) {
    if (!EnumProcessModulesEx(child_handle,
                              module_handles,
                              module_handle_storage_size,
                              &hmodules_size,
                              LIST_MODULES_ALL))
    {
      FATAL("EnumProcessModules failed, %x\n", GetLastError());
    }
    if (hmodules_size <= module_handle_storage_size) break;
    module_handle_storage_size *= 2;
    module_handles = (HMODULE *)realloc(module_handles, module_handle_storage_size);
  }
  *modules = module_handles;
  return hmodules_size / sizeof(HMODULE);
}

// parses PE headers and gets the module entypoint
void *Debugger::GetModuleEntrypoint(void *base_address) {
  unsigned char headers[4096];
  SIZE_T num_read = 0;
  if (!ReadProcessMemory(child_handle, base_address, headers, 4096, &num_read) ||
     (num_read != 4096))
  {
    FATAL("Error reading target memory\n");
  }
  DWORD pe_offset;
  pe_offset = *((DWORD *)(headers + 0x3C));
  unsigned char *pe = headers + pe_offset;
  DWORD signature = *((DWORD *)pe);
  if (signature != 0x00004550) {
    FATAL("PE signature error\n");
  }
  pe = pe + 0x18;
  WORD magic = *((WORD *)pe);
  if ((magic != 0x10b) && (magic != 0x20b)) {
    FATAL("Unknown PE magic value\n");
  }
  DWORD entrypoint_offset = *((DWORD *)(pe + 16));
  if (entrypoint_offset == 0) return NULL;
  return (char *)base_address + entrypoint_offset;
}

// parses PE headers and gets the image size
DWORD Debugger::GetImageSize(void *base_address) {
  unsigned char headers[4096];
  SIZE_T num_read = 0;
  if (!ReadProcessMemory(child_handle, base_address, headers, 4096, &num_read) ||
    (num_read != 4096))
  {
    FATAL("Error reading target memory\n");
  }
  DWORD pe_offset;
  pe_offset = *((DWORD *)(headers + 0x3C));
  unsigned char *pe = headers + pe_offset;
  DWORD signature = *((DWORD *)pe);
  if (signature != 0x00004550) {
    FATAL("PE signature error\n");
  }
  pe = pe + 0x18;
  WORD magic = *((WORD *)pe);
  if ((magic != 0x10b) && (magic != 0x20b)) {
    FATAL("Unknown PE magic value\n");
  }
  DWORD SizeOfImage = *((DWORD *)(pe + 56));
  return SizeOfImage;
}


// parses PE headers and gets the image size
void Debugger::GetImageSize(void *base_address, size_t *min_address, size_t *max_address) {
  *min_address = (size_t)base_address;
  DWORD SizeOfImage = GetImageSize(base_address);
  *max_address = *min_address + SizeOfImage;
}

// adds a one-time breakpoint at a specified address
// type, is an arbitrary int
// that can be accessed later when the breakpoint gets hit
void Debugger::AddBreakpoint(void *address, int type) {
  Breakpoint *new_breakpoint = new Breakpoint;
  SIZE_T rwsize = 0;
  if (!ReadProcessMemory(child_handle, address, &(new_breakpoint->original_opcode), 1, &rwsize) ||
     (rwsize != 1)) {
    FATAL("Error reading target memory\n");
  }
  rwsize = 0;
  unsigned char cc = 0xCC;
  if (!WriteProcessMemory(child_handle, address, &cc, 1, &rwsize) || (rwsize != 1)) {
    FATAL("Error writing target memory\n");
  }
  FlushInstructionCache(child_handle, address, 1);
  new_breakpoint->address = address;
  new_breakpoint->type = type;
  breakpoints.push_back(new_breakpoint);
}

// damn it Windows, why don't you have a GetProcAddress
// that works on another process
DWORD Debugger::GetProcOffset(HMODULE module, const char *name) {
  char* base_of_dll = (char*)module;

  char* headers = (char*)malloc(4096);

  SIZE_T num_read;
  if (!ReadProcessMemory(child_handle, base_of_dll, headers, 4096, &num_read) ||
    (num_read != 4096))
  {
    FATAL("Error reading target memory\n");
  }

  DWORD pe_offset;
  pe_offset = *((DWORD *)(headers + 0x3C));
  char *pe = headers + pe_offset;
  DWORD signature = *((DWORD *)pe);
  if (signature != 0x00004550) {
    free(headers);
    return 0;
  }
  pe = pe + 0x18;
  WORD magic = *((WORD *)pe);
  DWORD exporttableoffset;
  DWORD exporttablesize;
  if (magic == 0x10b) {
    exporttableoffset = *(DWORD*)(pe + 96);
    exporttablesize = *(DWORD*)(pe + 100);
  } else if (magic == 0x20b) {
    exporttableoffset = *(DWORD *)(pe + 112);
    exporttablesize = *(DWORD*)(pe + 116);
  } else {
    free(headers);
    return 0;
  }

  if (!exporttableoffset) {
    free(headers);
    return 0;
  }

  char* exporttable = (char*)malloc(exporttablesize);
  if (!ReadProcessMemory(child_handle, base_of_dll + exporttableoffset, exporttable, exporttablesize, &num_read) ||
    (num_read != exporttablesize))
  {
    FATAL("Error reading target memory\n");
  }  

  DWORD numentries = *(DWORD *)(exporttable + 24);
  DWORD addresstableoffset = *(DWORD *)(exporttable + 28);
  DWORD nameptrtableoffset = *(DWORD *)(exporttable + 32);
  DWORD ordinaltableoffset = *(DWORD *)(exporttable + 36);

  addresstableoffset -= exporttableoffset;
  nameptrtableoffset -= exporttableoffset;
  ordinaltableoffset -= exporttableoffset;

  if ((addresstableoffset >= exporttablesize) ||
    (nameptrtableoffset >= exporttablesize) ||
    (ordinaltableoffset >= exporttablesize))
  {
    WARN("Didn't read all export information");
    free(headers);
    free(exporttable);
    return 0;
  }

  DWORD *nameptrtable = (DWORD *)(exporttable + nameptrtableoffset);
  WORD *ordinaltable = (WORD *)(exporttable + ordinaltableoffset);
  DWORD *addresstable = (DWORD *)(exporttable + addresstableoffset);

  DWORD i;
  DWORD found = 0;
  for (i = 0; i < numentries; i++) {
    DWORD nameoffset = nameptrtable[i] - exporttableoffset;
    if (nameoffset >= exporttablesize)
    {
      WARN("Didn't read all export information");
      break;
    }
    char *nameptr = exporttable + nameoffset;
    // printf("Name: %s\n", nameptr);
    if (strcmp(name, nameptr) == 0) {
      found = 1;
      break;
    }
  }

  if (!found) {
    free(headers);
    free(exporttable);
    return 0;
  }

  WORD oridnal = ordinaltable[i];
  DWORD offset = addresstable[oridnal];

  free(headers);
  free(exporttable);

  return offset;
}

void* Debugger::GetSymbolAddress(void* base_address, const char* symbol_name) {
  DWORD offset = GetProcOffset((HMODULE)base_address, symbol_name);
  if (!offset) return NULL;
  return (void*)((size_t)base_address + offset);
}

// Gets the registered safe exception handlers for the module
void Debugger::GetExceptionHandlers(size_t module_haeder, std::unordered_set <size_t>& handlers) {
  // only present on x86
  if (child_ptr_size != 4) return;

  DWORD size_of_image = GetImageSize((void *)module_haeder);

  char* modulebuf = (char*)malloc(size_of_image);
  SIZE_T num_read;
  if (!ReadProcessMemory(child_handle, (void *)module_haeder, modulebuf, size_of_image, &num_read) ||
    (num_read != size_of_image))
  {
    FATAL("Error reading target memory\n");
  }

  DWORD pe_offset;
  pe_offset = *((DWORD*)(modulebuf + 0x3C));
  char* pe = modulebuf + pe_offset;
  DWORD signature = *((DWORD*)pe);
  if (signature != 0x00004550) {
    free(modulebuf);
    return;
  }
  pe = pe + 0x18;
  WORD magic = *((WORD*)pe);
  DWORD lc_offset;
  DWORD lc_size;
  if (magic == 0x10b) {
    lc_offset = *(DWORD*)(pe + 176);
    lc_size = *(DWORD*)(pe + 180);
  } else if (magic == 0x20b) {
    lc_offset = *(DWORD*)(pe + 192);
    lc_size = *(DWORD*)(pe + 196);
  } else {
    free(modulebuf);
    return;
  }

  if (!lc_offset || (lc_size != 64)) {
    free(modulebuf);
    return;
  }

  char* lc = modulebuf + lc_offset;

  size_t seh_table_address;
  DWORD seh_count;
  if (magic == 0x10b) {
    seh_table_address = *(DWORD*)(lc + 64);
    seh_count = *(DWORD*)(lc + 68);
  } else if (magic == 0x20b) {
    seh_table_address = *(uint64_t*)(lc + 96);
    seh_count = *(DWORD*)(lc + 104);
  } else {
    free(modulebuf);
    return;
  }

  size_t seh_table_offset = seh_table_address - module_haeder;

  DWORD* seh_table = (DWORD *)(modulebuf + seh_table_offset);
  for (DWORD i = 0; i < seh_count; i++) {
    handlers.insert(module_haeder + seh_table[i]);
  }

  free(modulebuf);
}

// attempt to obtain the address of target function
// in various ways
char *Debugger::GetTargetAddress(HMODULE module) {
  char* base_of_dll = (char *)module;

  // if persist_offset is defined, use that
  if (target_offset) {
    return base_of_dll + target_offset;
  }

  DWORD offset = GetProcOffset(module, target_method.c_str());
  if (offset) {
    return (char *)module + offset;
  }

  // finally, try the debug symbols
  char *method_address = NULL;
  char base_name[MAX_PATH];
  GetModuleBaseNameA(child_handle,
                     module,
                     (LPSTR)(&base_name),
                     sizeof(base_name));

  char module_path[MAX_PATH];
  if (!GetModuleFileNameExA(child_handle,
                            module,
                            module_path,
                            sizeof(module_path)))
    return NULL;

  ULONG64 buffer[(sizeof(SYMBOL_INFO) +
    MAX_SYM_NAME * sizeof(TCHAR) +
    sizeof(ULONG64) - 1) /
    sizeof(ULONG64)];
  PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
  pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
  pSymbol->MaxNameLen = MAX_SYM_NAME;
  SymInitialize(child_handle, NULL, false);
  DWORD64 sym_base_address = SymLoadModuleEx(child_handle,
                                             NULL,
                                             module_path,
                                             NULL,
                                             0,
                                             0,
                                             NULL,
                                             0);
  if (SymFromName(child_handle, target_method.c_str(), pSymbol)) {
    target_offset = (unsigned long)(pSymbol->Address - sym_base_address);
    method_address = base_of_dll + target_offset;
  }
  SymCleanup(child_handle);

  return method_address;
}

// called when a module gets loaded
void Debugger::OnModuleLoaded(void *module, char *module_name) {
  // printf("In on_module_loaded, name: %s, base: %p\n", module_name, module_info.lpBaseOfDll);

  if (target_function_defined && _stricmp(module_name, target_module.c_str()) == 0) {
    target_address = GetTargetAddress((HMODULE)module);
    if (!target_address) {
      FATAL("Error determining target method address\n");
    }

    AddBreakpoint(target_address, BREAKPOINT_TARGET);
  }
}

// called when a module gets unloaded
void Debugger::OnModuleUnloaded(void *module) { }

// reads numitems entries from stack in remote process
// from stack_addr
// into buffer
void Debugger::ReadStack(void *stack_addr, uint64_t *buffer, size_t numitems) {
  SIZE_T numrw = 0;
  if (child_ptr_size == 4) {
    uint32_t* buf32 = (uint32_t*)malloc(numitems * child_ptr_size);
    ReadProcessMemory(child_handle, stack_addr, buf32, numitems * child_ptr_size, &numrw);
    for (size_t i = 0; i < numitems; i++) {
      buffer[i] = ((uint64_t)buf32[i]);
    }
    free(buf32);
    return;
  }
  ReadProcessMemory(child_handle, stack_addr, buffer, numitems * child_ptr_size, &numrw);
}

// writes numitems entries to stack in remote process
// from buffer
// into stack_addr
void Debugger::WriteStack(void *stack_addr, uint64_t *buffer, size_t numitems) {
  SIZE_T numrw = 0;
  if (child_ptr_size == 4) {
    uint32_t *buf32 = (uint32_t *)malloc(numitems * child_ptr_size);
    for (size_t i = 0; i < numitems; i++) {
      buf32[i] = (uint32_t)(buffer[i]);
    }
    WriteProcessMemory(child_handle, stack_addr, buf32, numitems * child_ptr_size, &numrw);
    free(buf32);
    return;
  }
  WriteProcessMemory(child_handle, stack_addr, buffer, numitems * child_ptr_size, &numrw);
}

void Debugger::SetReturnAddress(size_t value) {
  RemoteWrite((void*)GetRegister(RSP), &value, child_ptr_size);
}

size_t Debugger::GetReturnAddress() {
  size_t ra;
  RemoteRead((void*)GetRegister(RSP), &ra, child_ptr_size);
  return ra;
}

void Debugger::GetFunctionArguments(uint64_t* arguments, size_t num_args, uint64_t sp, CallingConvention callconv) {
  RetrieveThreadContext();

  switch (callconv) {
#ifdef _WIN64
  case CALLCONV_DEFAULT:
  case CALLCONV_MICROSOFT_X64:
    if (num_args > 0) arguments[0] = lcContext.Rcx;
    if (num_args > 1) arguments[1] = lcContext.Rdx;
    if (num_args > 2) arguments[2] = lcContext.R8;
    if (num_args > 3) arguments[3] = lcContext.R9;
    if (num_args > 4) {
      ReadStack((void*)(sp + 5 * child_ptr_size), arguments + 4, num_args - 4);
    }
    break;
  case CALLCONV_CDECL:
    if (num_args > 0) {
      ReadStack((void*)(sp + child_ptr_size), arguments, num_args);
    }
    break;
  case CALLCONV_FASTCALL:
    if (num_args > 0) arguments[0] = lcContext.Rcx;
    if (num_args > 1) arguments[1] = lcContext.Rdx;
    if (num_args > 2) {
      ReadStack((void*)(sp + child_ptr_size), arguments + 2, num_args - 2);
    }
    break;
  case CALLCONV_THISCALL:
    if (num_args > 0) arguments[0] = lcContext.Rcx;
    if (num_args > 1) {
      ReadStack((void*)(sp + child_ptr_size), arguments + 1, num_args - 1);
    }
    break;
#else
  case CALLCONV_MICROSOFT_X64:
    FATAL("X64 callong convention not supported for 32-bit targets");
    break;
  case CALLCONV_DEFAULT:
  case CALLCONV_CDECL:
    if (num_args > 0) {
      ReadStack((void*)(sp + child_ptr_size), arguments, num_args);
    }
    break;
  case CALLCONV_FASTCALL:
    if (num_args > 0) arguments[0] = (uint64_t)lcContext.Ecx;
    if (num_args > 1) arguments[1] = (uint64_t)lcContext.Edx;
    if (num_args > 2) {
      ReadStack((void*)(sp + child_ptr_size), arguments + 2, num_args - 2);
    }
    break;
  case CALLCONV_THISCALL:
    if (num_args > 0) arguments[0] = (uint64_t)lcContext.Ecx;
    if (num_args > 1) {
      ReadStack((void*)(sp + child_ptr_size), arguments + 1, num_args - 1);
    }
    break;
#endif
  default:
    FATAL("Unknown calling convention");
  }
}

void Debugger::SetFunctionArguments(uint64_t* arguments, size_t num_args, uint64_t sp, CallingConvention callconv) {
  RetrieveThreadContext();

  switch (callconv) {
#ifdef _WIN64
  case CALLCONV_DEFAULT:
  case CALLCONV_MICROSOFT_X64:
    if (num_args > 0) lcContext.Rcx = (size_t)arguments[0];
    if (num_args > 1) lcContext.Rdx = (size_t)arguments[1];
    if (num_args > 2) lcContext.R8 = (size_t)arguments[2];
    if (num_args > 3) lcContext.R9 = (size_t)arguments[3];
    if (num_args > 4) {
      WriteStack((void*)(sp + 5 * child_ptr_size), arguments + 4, num_args - 4);
    }
    break;
  case CALLCONV_CDECL:
    if (num_args > 0) {
      WriteStack((void*)(sp + child_ptr_size), arguments, num_args);
    }
    break;
  case CALLCONV_FASTCALL:
    if (num_args > 0) lcContext.Rcx = (size_t)arguments[0];
    if (num_args > 1) lcContext.Rdx = (size_t)arguments[1];
    if (num_args > 3) {
      WriteStack((void*)(sp + child_ptr_size), arguments + 2, num_args - 2);
    }
    break;
  case CALLCONV_THISCALL:
    if (num_args > 0) lcContext.Rcx = (size_t)arguments[0];
    if (num_args > 3) {
      WriteStack((void*)(sp + child_ptr_size), arguments + 1, num_args - 1);
    }
    break;
#else
  case CALLCONV_MICROSOFT_X64:
    FATAL("X64 callong convention not supported for 32-bit targets");
    break;
  case CALLCONV_DEFAULT:
  case CALLCONV_CDECL:
    if (num_args > 0) {
      WriteStack((void*)(sp + child_ptr_size), arguments, num_args);
    }
    break;
  case CALLCONV_FASTCALL:
    if (num_args > 0) lcContext.Ecx = (size_t)arguments[0];
    if (num_args > 1) lcContext.Edx = (size_t)arguments[1];
    if (num_args > 3) {
      WriteStack((void*)(sp + child_ptr_size), arguments + 2, num_args - 2);
    }
    break;
  case CALLCONV_THISCALL:
    if (num_args > 0) lcContext.Ecx = (size_t)arguments[0];
    if (num_args > 3) {
      WriteStack((void*)(sp + child_ptr_size), arguments + 1, num_args - 1);
    }
    break;
#endif
  default:
    FATAL("Unknown calling convention");
  }

  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  SetThreadContext(thread_handle, &lcContext);
  CloseHandle(thread_handle);
}

// called when the target method is reached
void Debugger::HandleTargetReachedInternal() {
  // printf("in OnTargetMethod\n");

  SIZE_T numrw = 0;

  saved_sp = (void *)GetRegister(RSP);

  saved_return_address = 0;
  ReadProcessMemory(child_handle, saved_sp, &saved_return_address, child_ptr_size, &numrw);

  if (loop_mode) {
    GetFunctionArguments(saved_args, target_num_args, (uint64_t)saved_sp, calling_convention);

    // todo store any target-specific additional context here
  }

  // modify the return address on the stack so that an exception is triggered
  // when the target function finishes executing
  // another option would be to allocate a block of executable memory
  // and point return address over there, but this is quicker
  size_t return_address = PERSIST_END_EXCEPTION;
  WriteProcessMemory(child_handle, saved_sp, &return_address, child_ptr_size, &numrw);

  if (!target_reached) {
    target_reached = true;
    OnTargetMethodReached();
  }
}

// called every time the target method returns
void Debugger::HandleTargetEnded() {
  // printf("in OnTargetMethodEnded\n");

  target_return_value = GetRegister(RAX);

  if (loop_mode) {
    // restore params

    // Writing to lcContext directly to avoid calling 
    // SetThreadContext multiple times.
    // We don't need to RetrieveThreadContext() as it was done in 
    // GetRegister() above and we don't need to SetThreadContext
    // as it will be called by SetFunctionArguments below
#ifdef _WIN64
    lcContext.Rip = (size_t)target_address;
    lcContext.Rsp = (size_t)saved_sp;
#else
    lcContext.Eip = (size_t)target_address;
    lcContext.Esp = (size_t)saved_sp;
#endif

    // restore return address as it might have been overwritten by instrumentation
    SIZE_T numrw = 0;
    size_t return_address = PERSIST_END_EXCEPTION;
    WriteProcessMemory(child_handle, saved_sp, &return_address, child_ptr_size, &numrw);

    SetFunctionArguments(saved_args, target_num_args, (uint64_t)saved_sp, calling_convention);

    // todo restore any target-specific additional context here

  } else { /*  loop_mode == false */

    SetRegister(RIP, (size_t)saved_return_address);

    // restore target entry breakpoint
    // note that this time, the breakpoint address might be
    // in instrumented code
    // so we need to use translated address
    AddBreakpoint((void *)GetTranslatedAddress((size_t)target_address),
                  BREAKPOINT_TARGET);
  }
}

// called when process entrypoint gets reached
void Debugger::OnEntrypoint() {
  // printf("Entrypoint\n");

  HMODULE *module_handles = NULL;
  DWORD num_modules = GetLoadedModules(&module_handles);
  for (DWORD i = 0; i < num_modules; i++) {
    char base_name[MAX_PATH];
    GetModuleBaseNameA(child_handle, module_handles[i], (LPSTR)(&base_name), sizeof(base_name));
    if(trace_debug_events)
      printf("Debugger: Loaded module %s at %p\n", base_name, (void *)module_handles[i]);
    OnModuleLoaded((void *)module_handles[i], base_name);
  }
  if (module_handles) free(module_handles);

  child_entrypoint_reached = true;

  if (trace_debug_events) printf("Debugger: Process entrypoint reached\n");
}

// called when the debugger hits a breakpoint
int Debugger::HandleDebuggerBreakpoint(void *address) {
  int ret = BREAKPOINT_UNKNOWN;
  SIZE_T rwsize = 0;

  Breakpoint *breakpoint = NULL, *tmp_breakpoint;
  for (auto iter = breakpoints.begin(); iter != breakpoints.end(); iter++) {
    tmp_breakpoint = *iter;
    if (tmp_breakpoint->address == address) {
      breakpoint = tmp_breakpoint;
      breakpoints.erase(iter);
      break;
    }
  }

  if (!breakpoint) return ret;

  // restore address
  if (!WriteProcessMemory(child_handle, address, &breakpoint->original_opcode, 1, &rwsize) ||
     (rwsize != 1))
  {
    FATAL("Error writing child memory\n");
  }
  FlushInstructionCache(child_handle, address, 1);
  // restore context
  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_ALL;
  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  GetThreadContext(thread_handle, &lcContext);
#ifdef _WIN64
  lcContext.Rip--;
#else
  lcContext.Eip--;
#endif
  SetThreadContext(thread_handle, &lcContext);
  CloseHandle(thread_handle);
  // handle breakpoint
  switch (breakpoint->type) {
  case BREAKPOINT_ENTRYPOINT:
    OnEntrypoint();
    break;
  case BREAKPOINT_TARGET:
    if (trace_debug_events) printf("Target method reached\n");
    HandleTargetReachedInternal();
    break;
  default:
    break;
  }

  // return the brekpoint type
  ret = breakpoint->type;

  // delete the breakpoint object
  free(breakpoint);

  return ret;
}

// called when a dll gets loaded
void Debugger::HandleDllLoadInternal(LOAD_DLL_DEBUG_INFO *LoadDll) {
  // Don't do anything until the processentrypoint is reached.
  // Before that time we can't do much anyway, a lot of calls are going to fail
  // Modules loaded before entrypoint is reached are going to be enumerated at that time
  if (child_entrypoint_reached) {
    char filename[MAX_PATH];
    GetFinalPathNameByHandleA(LoadDll->hFile, (LPSTR)(&filename), sizeof(filename), 0);
    char *base_name = strrchr(filename, '\\');
    if (base_name) base_name += 1;
    else base_name = filename;
    if (trace_debug_events)
      printf("Debugger: Loaded module %s at %p\n",
        base_name,
        (void *)LoadDll->lpBaseOfDll);
    OnModuleLoaded(LoadDll->lpBaseOfDll, base_name);
  }
}

// called when a process gets created
// or attached to
void Debugger::OnProcessCreated() {
  CREATE_PROCESS_DEBUG_INFO *info = &dbg_debug_event.u.CreateProcessInfo;

  if (attach_mode) {
    // assume entrypoint has been reached already
    child_handle = info->hProcess;
    child_thread_handle = info->hThread;
    child_entrypoint_reached = true;
    GetProcessPlatform();

    // In case of attaching to an existing process
    // the dll load event for the main module
    // will *not* be generated.
    // Handle the main module load below
    char filename[MAX_PATH];
    GetFinalPathNameByHandleA(info->hFile, (LPSTR)(&filename), sizeof(filename), 0);
    char* base_name = strrchr(filename, '\\');
    if (base_name) base_name += 1;
    else base_name = filename;
    if (trace_debug_events)
      printf("Debugger: Loaded module %s at %p\n",
        base_name,
        (void*)info->lpBaseOfImage);
    OnModuleLoaded(info->lpBaseOfImage, base_name);

  } else {
    // add a brekpoint to the process entrypoint
    void *entrypoint = GetModuleEntrypoint(info->lpBaseOfImage);
    AddBreakpoint(entrypoint, BREAKPOINT_ENTRYPOINT);
  }
}

// called when an exception in the target occurs
DebuggerStatus Debugger::HandleExceptionInternal(EXCEPTION_RECORD *exception_record)
{
  CreateException(exception_record, &last_exception);

  // note: instrumentation could have placed breakpoints
  // on the same addresses as debugger
  // handle one-time debugger breakpoints first
  if ((exception_record->ExceptionCode == EXCEPTION_BREAKPOINT) ||
      (exception_record->ExceptionCode == 0x4000001f))
  {
    void *address = exception_record->ExceptionAddress;
    // printf("Breakpoint at address %p\n", address);
    int breakpoint_type = HandleDebuggerBreakpoint(address);
    if (breakpoint_type == BREAKPOINT_TARGET) {
      return DEBUGGER_TARGET_START;
    } else if (breakpoint_type != BREAKPOINT_UNKNOWN) {
      return DEBUGGER_CONTINUE;
    }
  }

  // check if cleient can handle it
  if (OnException(&last_exception)) {
    return DEBUGGER_CONTINUE;
  }

  // don't print exceptions handled by clients
  if (trace_debug_events)
    printf("Debugger: Exception %x at address %p\n",
      exception_record->ExceptionCode,
      exception_record->ExceptionAddress);

  switch (exception_record->ExceptionCode)
  {
  case EXCEPTION_BREAKPOINT:
  case 0x4000001f: //STATUS_WX86_BREAKPOINT
    // not handled above
    dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
    return DEBUGGER_CONTINUE;

  case EXCEPTION_ACCESS_VIOLATION: {
    if (target_function_defined && 
       ((size_t)exception_record->ExceptionAddress == PERSIST_END_EXCEPTION))
    {
      if (trace_debug_events) printf("Debugger: Persistence method ended\n");
      HandleTargetEnded();
      return DEBUGGER_TARGET_END;
    } else {
      // Debug(&DebugEv->u.Exception.ExceptionRecord);
      dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
      return DEBUGGER_CRASHED;
    }
    break;
  }

  case EXCEPTION_ILLEGAL_INSTRUCTION:
  case EXCEPTION_PRIV_INSTRUCTION:
  case EXCEPTION_INT_DIVIDE_BY_ZERO:
  case EXCEPTION_STACK_OVERFLOW:
  case STATUS_HEAP_CORRUPTION:
  case STATUS_STACK_BUFFER_OVERRUN:
  case STATUS_FATAL_APP_EXIT:
    dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
    return DEBUGGER_CRASHED;
    break;

  default:
    if (trace_debug_events)
      printf("Unhandled exception %x\n", exception_record->ExceptionCode);
    dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
    return DEBUGGER_CONTINUE;
  }
}

// standard debugger loop that listens to events in the target process
DebuggerStatus Debugger::DebugLoop(uint32_t timeout, bool killing)
{
  DebuggerStatus ret;
  bool alive = true;

  if (dbg_continue_needed) {
    ContinueDebugEvent(dbg_debug_event.dwProcessId,
      dbg_debug_event.dwThreadId,
      dbg_continue_status);
  }

  LPDEBUG_EVENT DebugEv = &dbg_debug_event;

  while (alive)
  {
    have_thread_context = false;

    uint64_t begin_time = GetCurTime();
    BOOL wait_ret = WaitForDebugEvent(DebugEv, 100);
    uint64_t end_time = GetCurTime();

    uint64_t time_elapsed = end_time - begin_time;
    timeout = ((uint64_t)timeout >= time_elapsed) ? timeout - (uint32_t)time_elapsed : 0;

    // printf("timeout: %u\n", timeout);
    // printf("time: %lld\n", get_cur_time_us());

    if (wait_ret) {
      dbg_continue_needed = true;
    } else {
      dbg_continue_needed = false;
    }

    if (timeout == 0) return DEBUGGER_HANGED;

    if (!wait_ret) {
      //printf("WaitForDebugEvent returned 0\n");
      continue;
    }

    dbg_continue_status = DBG_CONTINUE;

    thread_id = DebugEv->dwThreadId;

    // printf("eventCode: %x\n", DebugEv->dwDebugEventCode);

    switch (DebugEv->dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:
      if (!killing) {
        ret = HandleExceptionInternal(&DebugEv->u.Exception.ExceptionRecord);
        if (ret == DEBUGGER_CRASHED) OnCrashed(&last_exception);
        if (ret != DEBUGGER_CONTINUE) return ret;
      } else {
        dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
      }
      break;

    case CREATE_THREAD_DEBUG_EVENT:
      break;

    case CREATE_PROCESS_DEBUG_EVENT: {
      if (trace_debug_events) printf("Debugger: Process created or attached\n");
      OnProcessCreated();
      CloseHandle(DebugEv->u.CreateProcessInfo.hFile);
      break;
    }

    case EXIT_THREAD_DEBUG_EVENT:
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
      if (trace_debug_events) printf("Debugger: Process exit\n");
      OnProcessExit();
      alive = false;
      break;

    case LOAD_DLL_DEBUG_EVENT: {
      if(!killing) HandleDllLoadInternal(&DebugEv->u.LoadDll);
      CloseHandle(DebugEv->u.LoadDll.hFile);
      break;
    }

    case UNLOAD_DLL_DEBUG_EVENT:
      if (trace_debug_events)
        printf("Debugger: Unloaded module from %p\n", DebugEv->u.UnloadDll.lpBaseOfDll);
      OnModuleUnloaded(DebugEv->u.UnloadDll.lpBaseOfDll);
      break;

   default:
      break;
    }

    ContinueDebugEvent(DebugEv->dwProcessId,
      DebugEv->dwThreadId,
      dbg_continue_status);
  }

  return DEBUGGER_PROCESS_EXIT;
}

// starts the target process
void Debugger::StartProcess(char *cmd) {
  dbg_continue_needed = false;

  STARTUPINFOA si;
  STARTUPINFOEXA si_ex;
  LPSTARTUPINFOA si_ptr;
  LPSTARTUPINFOA si_basic_ptr;
  LPPROC_THREAD_ATTRIBUTE_LIST attr_list_buf = NULL;

  DWORD creation_flags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;

  PROCESS_INFORMATION pi;
  HANDLE hJob = NULL;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limit;

  DeleteBreakpoints();

  if (sinkhole_stds && devnul_handle == INVALID_HANDLE_VALUE) {
    devnul_handle = CreateFile(
      "nul",
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      0,
      NULL);

    if (devnul_handle == INVALID_HANDLE_VALUE) {
      FATAL("Unable to open the nul device.");
    }
  }
  BOOL inherit_handles = TRUE;

  if (force_dep) {
    ZeroMemory(&si_ex, sizeof(si_ex));
    si_ex.StartupInfo.cb = sizeof(si_ex);

    creation_flags |= EXTENDED_STARTUPINFO_PRESENT;

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    if (attr_size == 0) {
      FATAL("Error getting attribute list size");
    }

    attr_list_buf = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_size);
    if (!InitializeProcThreadAttributeList(attr_list_buf, 1, 0, &attr_size)) {
      FATAL("Error in InitializeProcThreadAttributeList");
    }

    DWORD flags = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
    size_t flags_size = sizeof(flags);

    if (!UpdateProcThreadAttribute(attr_list_buf,
      0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
      &flags, flags_size, NULL, NULL))
    {
      FATAL("Error in UpdateProcThreadAttribute");
    }

    si_ex.lpAttributeList = attr_list_buf;

    si_ptr = (LPSTARTUPINFOA)&si_ex;
    si_basic_ptr = &si_ex.StartupInfo;
  } else {
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si_ptr = &si;
    si_basic_ptr = &si;
  }

  if (sinkhole_stds) {
    si_basic_ptr->hStdOutput = si_basic_ptr->hStdError = devnul_handle;
    si_basic_ptr->dwFlags |= STARTF_USESTDHANDLES;
  } else {
    inherit_handles = FALSE;
  }

  ZeroMemory(&pi, sizeof(pi));

  if (mem_limit || cpu_aff) {
    hJob = CreateJobObject(NULL, NULL);
    if (hJob == NULL) {
      FATAL("CreateJobObject failed, GLE=%d.\n", GetLastError());
    }

    ZeroMemory(&job_limit, sizeof(job_limit));
    if (mem_limit) {
      job_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
      job_limit.ProcessMemoryLimit = (size_t)(mem_limit * 1024 * 1024);
    }

    if (cpu_aff) {
      job_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY;
      job_limit.BasicLimitInformation.Affinity = (DWORD_PTR)cpu_aff;
    }

    if (!SetInformationJobObject(
      hJob,
      JobObjectExtendedLimitInformation,
      &job_limit,
      sizeof(job_limit)
    )) {
      FATAL("SetInformationJobObject failed, GLE=%d.\n", GetLastError());
    }
  }

  if (!CreateProcessA(NULL,
                      cmd,
                      NULL,
                      NULL,
                      inherit_handles,
                      creation_flags,
                      NULL,
                      NULL,
                      si_ptr,
                      &pi))
  {
    FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
  }

  if (attr_list_buf) {
    DeleteProcThreadAttributeList(attr_list_buf);
    free(attr_list_buf);
  }

  child_handle = pi.hProcess;
  child_thread_handle = pi.hThread;
  child_entrypoint_reached = false;
  target_reached = false;
  have_thread_context = false;

  if (mem_limit || cpu_aff) {
    if (!AssignProcessToJobObject(hJob, child_handle)) {
      FATAL("AssignProcessToJobObject failed, GLE=%d.\n", GetLastError());
    }
  }

  GetProcessPlatform();
}

void Debugger::GetProcessPlatform() {
  BOOL wow64current, wow64remote;
  if (!IsWow64Process(child_handle, &wow64remote)) {
    FATAL("IsWow64Process failed");
  }
  if (wow64remote) {
    wow64_target = 1;
    child_ptr_size = 4;
    if (calling_convention == CALLCONV_DEFAULT) {
      calling_convention = CALLCONV_CDECL;
    }
  }
  if (!IsWow64Process(GetCurrentProcess(), &wow64current)) {
    FATAL("IsWow64Process failed");
  }
  // Will probably fail before we reach this, but oh well
  if (sizeof(void*) < child_ptr_size) {
    FATAL("64-bit build is needed to run 64-bit targets\n");
  }
}

// kills the target process
// (if not dead already)
DebuggerStatus Debugger::Kill() {
  if (!child_handle) return DEBUGGER_PROCESS_EXIT;

  TerminateProcess(child_handle, 0);
  
  dbg_last_status = DebugLoop(0xFFFFFFFFUL, true);
  if (dbg_last_status != DEBUGGER_PROCESS_EXIT) {
    FATAL("Error killing target process\n");
  }

  CloseHandle(child_handle);
  CloseHandle(child_thread_handle);

  child_handle = NULL;
  child_thread_handle = NULL;
  have_thread_context = false;

  // delete any breakpoints that weren't hit
  DeleteBreakpoints();

  return dbg_last_status;
}

// attaches to an active process
DebuggerStatus Debugger::Attach(unsigned int pid, uint32_t timeout) {
  attach_mode = true;

  if (!DebugActiveProcess(pid)) {
    DWORD error_code = GetLastError();
    

    if(error_code == 5) {
      HANDLE hToken = NULL;
      LUID luid;
      TOKEN_PRIVILEGES tp;
      
      if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        FATAL("OpenProcessToken() failed, error code = %d\n", GetLastError());
      }
      
      if(!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        FATAL("LookupPrivilegeValueA() failed, error code = %d\n", GetLastError());
      }
      
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      tp.Privileges[0].Luid = luid;
      tp.PrivilegeCount = 1;
      
      if(!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        FATAL("AdjustTokenPrivileges() failed, error code = %d\n", GetLastError());
      }
      
      if(!DebugActiveProcess(pid)) {
        FATAL("Could not attach to the process.\n"
              "Make sure the process exists and you have permissions to debug it.\n");
      }
      
    } else {
      FATAL("DebugActiveProcess() failed, error code = %d\n", error_code);
    }
  }

  dbg_last_status = DEBUGGER_ATTACHED;

  return Continue(timeout);
}

// starts the process and waits for the next event
DebuggerStatus Debugger::Run(char *cmd, uint32_t timeout) {
  attach_mode = false;

  StartProcess(cmd);

  return Continue(timeout);
}

DebuggerStatus Debugger::Run(int argc, char **argv, uint32_t timeout) {
    char* cmd = NULL;
    cmd = ArgvToCmd(argc, argv);

    DebuggerStatus ret_dbg_status = Run(cmd, timeout);
    free(cmd);

    return ret_dbg_status;
}

// continues after Run() or previous Continue()
// return with a non-terminal status
DebuggerStatus Debugger::Continue(uint32_t timeout) {
  if (!child_handle && (dbg_last_status != DEBUGGER_ATTACHED))
    return DEBUGGER_PROCESS_EXIT;

  if (loop_mode && (dbg_last_status == DEBUGGER_TARGET_END)) {
    // saves us a breakpoint
    dbg_last_status = DEBUGGER_TARGET_START;
    return dbg_last_status;
  }

  dbg_last_status = DebugLoop(timeout);

  if (dbg_last_status == DEBUGGER_PROCESS_EXIT) {
    CloseHandle(child_handle);
    CloseHandle(child_thread_handle);
    child_handle = NULL;
    child_thread_handle = NULL;
  }

  return dbg_last_status;
}

// initializes options from command line
void Debugger::Init(int argc, char **argv) {
  have_thread_context = false;
  sinkhole_stds = false;
  mem_limit = 0;
  cpu_aff = 0;

  attach_mode = false;
  trace_debug_events = false;
  loop_mode = false;
  target_function_defined = false;

  target_return_value = 0;

  child_handle = NULL;
  child_thread_handle = NULL;

  target_module[0] = 0;
  target_method[0] = 0;
  target_offset = 0;
  saved_args = NULL;
  target_num_args = 0;
  calling_convention = CALLCONV_DEFAULT;
  target_address = NULL;

  char *option;

  trace_debug_events = GetBinaryOption("-trace_debug_events",
                                       argc, argv,
                                       trace_debug_events);

  option = GetOption("-target_module", argc, argv);
  if (option) target_module = option;

  option = GetOption("-target_method", argc, argv);
  if (option) target_method = option;

  loop_mode = GetBinaryOption("-loop", argc, argv, loop_mode);

  option = GetOption("-nargs", argc, argv);
  if (option) target_num_args = atoi(option);

  option = GetOption("-target_offset", argc, argv);
  if (option) target_offset = strtoul(option, NULL, 0);

  option = GetOption("-callconv", argc, argv);
  if (option) {
    if (strcmp(option, "stdcall") == 0)
      calling_convention = CALLCONV_CDECL;
    else if (strcmp(option, "fastcall") == 0)
      calling_convention = CALLCONV_FASTCALL;
    else if (strcmp(option, "thiscall") == 0)
      calling_convention = CALLCONV_THISCALL;
    else if (strcmp(option, "ms64") == 0)
      calling_convention = CALLCONV_MICROSOFT_X64;
    else
      FATAL("Unknown calling convention");
  }

  force_dep = GetBinaryOption("-force_dep", argc, argv, false);

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
    saved_args = (uint64_t *)malloc(target_num_args * sizeof(uint64_t));
  }

  // get allocation granularity
  SYSTEM_INFO system_info;
  GetSystemInfo(&system_info);
  allocation_granularity = system_info.dwAllocationGranularity;
}
