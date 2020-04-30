#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include "windows.h"
#include "psapi.h"
#include "dbghelp.h"

#include "common.h"
#include "debugger.h"


#define CALLCONV_MICROSOFT_X64 0
#define CALLCONV_THISCALL 1
#define CALLCONV_FASTCALL 2
#define CALLCONV_CDECL 3
#define CALLCONV_DEFAULT 4

#define BREAKPOINT_UNKNOWN 0
#define BREAKPOINT_ENTRYPOINT 1
#define BREAKPOINT_PERSIST 2

#define PERSIST_END_EXCEPTION 0x0F22

#define DEBUGGER_PROCESS_EXIT 0
#define DEBUGGER_PERSIST_REACHED 1
#define DEBUGGER_PERSIST_END 2
#define DEBUGGER_CRASHED 3
#define DEBUGGER_HANGED 4


extern uint8_t sinkhole_stds;
extern uint64_t mem_limit;
extern uint64_t cpu_aff;



void Debugger::DeleteBreakpoints() {
  for (auto iter = breakpoints.begin(); iter != breakpoints.end(); iter++) {
    delete *iter;
  }
  breakpoints.clear();
}

// returns an array of handles for all modules loaded in the target process
DWORD Debugger::GetLoadedModules(HMODULE **modules) {
  DWORD module_handle_storage_size = 1024 * sizeof(HMODULE);
  HMODULE *module_handles = (HMODULE *)malloc(module_handle_storage_size);
  DWORD hmodules_size;
  while (true) {
    if (!EnumProcessModulesEx(child_handle, module_handles, module_handle_storage_size, &hmodules_size, LIST_MODULES_ALL)) {
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
  size_t num_read = 0;
  if (!ReadProcessMemory(child_handle, base_address, headers, 4096, &num_read) || (num_read != 4096)) {
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

// parses PE headers and gets the module entypoint
DWORD Debugger::GetImageSize(void *base_address) {
  unsigned char headers[4096];
  size_t num_read = 0;
  if (!ReadProcessMemory(child_handle, base_address, headers, 4096, &num_read) || (num_read != 4096)) {
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

// adds a breakpoint at a specified address
// type, module_name and module_base are all additional information
// that can be accessed later when the breakpoint gets hit
void Debugger::AddBreakpoint(void *address, int type, char *module_name, void *module_base) {
  Breakpoint *new_breakpoint = new Breakpoint;
  size_t rwsize = 0;
  if (!ReadProcessMemory(child_handle, address, &(new_breakpoint->original_opcode), 1, &rwsize) || (rwsize != 1)) {
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
  if (module_name) {
    strcpy(new_breakpoint->module_name, module_name);
  } else {
    new_breakpoint->module_name[0] = 0;
  }
  new_breakpoint->module_base = module_base;
  breakpoints.push_back(new_breakpoint);
}


// damn it Windows, why don't you have a GetProcAddress
// that works on another process
DWORD Debugger::GetProcOffset(char *data, char *name) {
  DWORD pe_offset;
  pe_offset = *((DWORD *)(data + 0x3C));
  char *pe = data + pe_offset;
  DWORD signature = *((DWORD *)pe);
  if (signature != 0x00004550) {
    return 0;
  }
  pe = pe + 0x18;
  WORD magic = *((WORD *)pe);
  DWORD exporttableoffset;
  if (magic == 0x10b) {
    exporttableoffset = *(DWORD *)(pe + 96);
  } else if (magic == 0x20b) {
    exporttableoffset = *(DWORD *)(pe + 112);
  } else {
    return 0;
  }

  if (!exporttableoffset) return 0;
  char *exporttable = data + exporttableoffset;

  DWORD numentries = *(DWORD *)(exporttable + 24);
  DWORD addresstableoffset = *(DWORD *)(exporttable + 28);
  DWORD nameptrtableoffset = *(DWORD *)(exporttable + 32);
  DWORD ordinaltableoffset = *(DWORD *)(exporttable + 36);
  DWORD *nameptrtable = (DWORD *)(data + nameptrtableoffset);
  WORD *ordinaltable = (WORD *)(data + ordinaltableoffset);
  DWORD *addresstable = (DWORD *)(data + addresstableoffset);

  DWORD i;
  for (i = 0; i < numentries; i++) {
    char *nameptr = data + nameptrtable[i];
    if (strcmp(name, nameptr) == 0) break;
  }

  if (i == numentries) return 0;

  WORD oridnal = ordinaltable[i];
  DWORD offset = addresstable[oridnal];

  return offset;
}

// attempt to obtain the persist_offset in various ways
char *Debugger::GetPersistenceOffset(HMODULE module) {
  char* base_of_dll = (char *)module;
  DWORD size_of_image = GetImageSize(base_of_dll);

  // if persist_offset is defined, use that
  if (persist_offset) {
    return base_of_dll + persist_offset;
  }

  // try the exported symbols next
  BYTE *modulebuf = (BYTE *)malloc(size_of_image);
  size_t num_read;
  if (!ReadProcessMemory(child_handle, base_of_dll, modulebuf, size_of_image, &num_read) || (num_read != size_of_image)) {
    FATAL("Error reading target memory\n");
  }
  DWORD offset = GetProcOffset((char *)modulebuf, persist_method);
  free(modulebuf);
  if (offset) {
    return (char *)module + offset;
  }

  // finally, try the debug symbols
  char *method_address = NULL;
  char base_name[MAX_PATH];
  GetModuleBaseNameA(child_handle, module, (LPSTR)(&base_name), sizeof(base_name));

  char module_path[MAX_PATH];
  if (!GetModuleFileNameExA(child_handle, module, module_path, sizeof(module_path))) return NULL;

  ULONG64 buffer[(sizeof(SYMBOL_INFO) +
    MAX_SYM_NAME * sizeof(TCHAR) +
    sizeof(ULONG64) - 1) /
    sizeof(ULONG64)];
  PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
  pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
  pSymbol->MaxNameLen = MAX_SYM_NAME;
  SymInitialize(child_handle, NULL, false);
  DWORD64 sym_base_address = SymLoadModuleEx(child_handle, NULL, module_path, NULL, 0, 0, NULL, 0);
  if (SymFromName(child_handle, persist_method, pSymbol)) {
    persist_offset = (unsigned long)(pSymbol->Address - sym_base_address);
    method_address = base_of_dll + persist_offset;
  }
  SymCleanup(child_handle);

  return method_address;
}

// called when a potentialy interesting module gets loaded
void Debugger::OnModuleLoaded(HMODULE module, char *module_name) {
  // printf("In on_module_loaded, name: %s, base: %p\n", module_name, module_info.lpBaseOfDll);

  if (_stricmp(module_name, persist_module) == 0) {
    persistence_address = GetPersistenceOffset(module);
    if (!persistence_address) {
      FATAL("Error determining target method address\n");
    }

    AddBreakpoint(persistence_address, BREAKPOINT_PERSIST, NULL, 0);
  }
}

// called when a potentialy interesting module gets loaded
void Debugger::OnModuleUnloaded(HMODULE module) {
}

void Debugger::ReadStack(void *stack_addr, void **buffer, size_t numitems) {
  size_t numrw = 0;
#ifdef _WIN64
  if (wow64_target) {
    uint32_t *buf32 = (uint32_t *)malloc(numitems * child_ptr_size);
    ReadProcessMemory(child_handle, stack_addr, buf32, numitems * child_ptr_size, &numrw);
    for (size_t i = 0; i < numitems; i++) {
      buffer[i] = (void *)((size_t)buf32[i]);
    }
    free(buf32);
    return;
  }
#endif
  ReadProcessMemory(child_handle, stack_addr, buffer, numitems * child_ptr_size, &numrw);
}

void Debugger::WriteStack(void *stack_addr, void **buffer, size_t numitems) {
  size_t numrw = 0;
#ifdef _WIN64
  if (wow64_target) {
    uint32_t *buf32 = (uint32_t *)malloc(numitems * child_ptr_size);
    for (size_t i = 0; i < numitems; i++) {
      buf32[i] = (uint32_t)((size_t)buffer[i]);
    }
    WriteProcessMemory(child_handle, stack_addr, buf32, numitems * child_ptr_size, &numrw);
    free(buf32);
    return;
  }
#endif
  WriteProcessMemory(child_handle, stack_addr, buffer, numitems * child_ptr_size, &numrw);
}

// called when the target method is called *for the first time only*
void Debugger::OnPersistMethodReached(DWORD thread_id) {
  // printf("in OnTargetMethod\n");

  persist_target_reached = true;

  size_t numrw = 0;

  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_ALL;
  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  GetThreadContext(thread_handle, &lcContext);

  // read out and save the params
#ifdef _WIN64
  saved_sp = (void *)lcContext.Rsp;
#else
  saved_sp = (void *)lcContext.Esp;
#endif

  switch (calling_convention) {
#ifdef _WIN64
  case CALLCONV_DEFAULT:
  case CALLCONV_MICROSOFT_X64:
    if (persist_num_args > 0) saved_args[0] = (void *)lcContext.Rcx;
    if (persist_num_args > 1) saved_args[1] = (void *)lcContext.Rdx;
    if (persist_num_args > 2) saved_args[2] = (void *)lcContext.R8;
    if (persist_num_args > 3) saved_args[3] = (void *)lcContext.R9;
    if (persist_num_args > 4) {
      ReadStack((void *)(lcContext.Rsp + 5 * child_ptr_size), saved_args + 4, persist_num_args - 4);
    }
    break;
  case CALLCONV_CDECL:
    if (persist_num_args > 0) {
      ReadStack((void *)(lcContext.Rsp + child_ptr_size), saved_args, persist_num_args);
    }
    break;
  case CALLCONV_FASTCALL:
    if (persist_num_args > 0) saved_args[0] = (void *)lcContext.Rcx;
    if (persist_num_args > 1) saved_args[1] = (void *)lcContext.Rdx;
    if (persist_num_args > 3) {
      ReadStack((void *)(lcContext.Rsp + child_ptr_size), saved_args + 2, persist_num_args - 2);
    }
    break;
  case CALLCONV_THISCALL:
    if (persist_num_args > 0) saved_args[0] = (void *)lcContext.Rcx;
    if (persist_num_args > 3) {
      ReadStack((void *)(lcContext.Rsp + child_ptr_size), saved_args + 1, persist_num_args - 1);
    }
    break;
#else
  case CALLCONV_MICROSOFT_X64:
    FATAL("X64 callong convention not supported for 32-bit targets");
    break;
  case CALLCONV_DEFAULT:
  case CALLCONV_CDECL:
    if (persist_num_args > 0) {
      ReadStack((void *)(lcContext.Esp + child_ptr_size), saved_args, persist_num_args);
    }
    break;
  case CALLCONV_FASTCALL:
    if (persist_num_args > 0) saved_args[0] = (void *)lcContext.Ecx;
    if (persist_num_args > 1) saved_args[1] = (void *)lcContext.Edx;
    if (persist_num_args > 3) {
      ReadStack((void *)(lcContext.Esp + child_ptr_size), saved_args + 2, persist_num_args - 2);
    }
    break;
  case CALLCONV_THISCALL:
    if (persist_num_args > 0) saved_args[0] = (void *)lcContext.Ecx;
    if (persist_num_args > 3) {
      ReadStack((void *)(lcContext.Esp + child_ptr_size), saved_args + 1, persist_num_args - 1);
    }
    break;
#endif
  default:
    break;
  }

  // todo store any target-specific additional context here

  // modify the return address on the stack so that an exception is triggered
  // when the target function finishes executing
  // another option would be to allocate a block of executable memory
  // and point return address over there, but this is quicker
  size_t return_address = PERSIST_END_EXCEPTION;
  WriteProcessMemory(child_handle, saved_sp, &return_address, child_ptr_size, &numrw);

  CloseHandle(thread_handle);
}

// called every time the target method returns
void Debugger::OnPersistMethodEnded(DWORD thread_id) {
  // printf("in OnTargetMethodEnded\n");

  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_ALL;
  HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
  GetThreadContext(thread_handle, &lcContext);

  // restore params
#ifdef _WIN64
  lcContext.Rip = (size_t)persistence_address;
  lcContext.Rsp = (size_t)saved_sp;
#else
  lcContext.Eip = (size_t)persistence_address;
  lcContext.Esp = (size_t)saved_sp;
#endif

  switch (calling_convention) {
#ifdef _WIN64
  case CALLCONV_DEFAULT:
  case CALLCONV_MICROSOFT_X64:
    if (persist_num_args > 0) lcContext.Rcx = (size_t)saved_args[0];
    if (persist_num_args > 1) lcContext.Rdx = (size_t)saved_args[1];
    if (persist_num_args > 2) lcContext.R8 = (size_t)saved_args[2];
    if (persist_num_args > 3) lcContext.R9 = (size_t)saved_args[3];
    if (persist_num_args > 4) {
      WriteStack((void *)(lcContext.Rsp + 5 * child_ptr_size), saved_args + 4, persist_num_args - 4);
    }
    break;
  case CALLCONV_CDECL:
    if (persist_num_args > 0) {
      WriteStack((void *)(lcContext.Rsp + child_ptr_size), saved_args, persist_num_args);
    }
    break;
  case CALLCONV_FASTCALL:
    if (persist_num_args > 0) lcContext.Rcx = (size_t)saved_args[0];
    if (persist_num_args > 1) lcContext.Rdx = (size_t)saved_args[1];
    if (persist_num_args > 3) {
      WriteStack((void *)(lcContext.Rsp + child_ptr_size), saved_args + 2, persist_num_args - 2);
    }
    break;
  case CALLCONV_THISCALL:
    if (persist_num_args > 0) lcContext.Rcx = (size_t)saved_args[0];
    if (persist_num_args > 3) {
      WriteStack((void *)(lcContext.Rsp + child_ptr_size), saved_args + 1, persist_num_args - 1);
    }
    break;
#else
  case CALLCONV_MICROSOFT_X64:
    FATAL("X64 callong convention not supported for 32-bit targets");
    break;
  case CALLCONV_DEFAULT:
  case CALLCONV_CDECL:
    if (persist_num_args > 0) {
      WriteStack((void *)(lcContext.Esp + child_ptr_size), saved_args, persist_num_args);
    }
    break;
  case CALLCONV_FASTCALL:
    if (persist_num_args > 0) lcContext.Ecx = (size_t)saved_args[0];
    if (persist_num_args > 1) lcContext.Edx = (size_t)saved_args[1];
    if (persist_num_args > 3) {
      WriteStack((void *)(lcContext.Esp + child_ptr_size), saved_args + 2, persist_num_args - 2);
    }
    break;
  case CALLCONV_THISCALL:
    if (persist_num_args > 0) lcContext.Ecx = (size_t)saved_args[0];
    if (persist_num_args > 3) {
      WriteStack((void *)(lcContext.Esp + child_ptr_size), saved_args + 1, persist_num_args - 1);
    }
    break;
#endif
  default:
    break;
  }

  // todo restore any target-specific additional context here

  SetThreadContext(thread_handle, &lcContext);
  CloseHandle(thread_handle);
}

// called when process entrypoint gets reached
void Debugger::OnEntrypoint() {
  // printf("Entrypoint\n");

  HMODULE *module_handles = NULL;
  DWORD num_modules = GetLoadedModules(&module_handles);
  for (DWORD i = 0; i < num_modules; i++) {
    char base_name[MAX_PATH];
    GetModuleBaseNameA(child_handle, module_handles[i], (LPSTR)(&base_name), sizeof(base_name));
    printf("Module loaded: %s\n", base_name);
    OnModuleLoaded(module_handles[i], base_name);
  }
  if (module_handles) free(module_handles);

  child_entrypoint_reached = true;
}

// called when the debugger hits a breakpoint
int Debugger::HandleDebuggerBreakpoint(void *address, DWORD thread_id) {
  int ret = BREAKPOINT_UNKNOWN;
  size_t rwsize = 0;

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
  if (!WriteProcessMemory(child_handle, address, &breakpoint->original_opcode, 1, &rwsize) || (rwsize != 1)) {
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
  case BREAKPOINT_PERSIST:
    OnPersistMethodReached(thread_id);
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

// standard debugger loop that listens to relevant events in the target process
int Debugger::DebugLoop()
{
  bool alive = true;

  LPDEBUG_EVENT DebugEv = &dbg_debug_event;

  while (alive)
  {

    BOOL wait_ret = WaitForDebugEvent(DebugEv, 100);

    // printf("time: %lld\n", get_cur_time_us());

    if (wait_ret) {
      dbg_continue_needed = true;
    } else {
      dbg_continue_needed = false;
    }

    if (GetCurTime() > dbg_timeout_time) return DEBUGGER_HANGED;

    if (!wait_ret) {
      //printf("WaitForDebugEvent returned 0\n");
      continue;
    }

    dbg_continue_status = DBG_CONTINUE;

    // printf("eventCode: %x\n", DebugEv->dwDebugEventCode);

    switch (DebugEv->dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:
      // printf("exception code: %x\n", DebugEv->u.Exception.ExceptionRecord.ExceptionCode);
      // printf("exception address: %p\n", DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);
      if (OnException(&DebugEv->u.Exception.ExceptionRecord, DebugEv->dwThreadId)) {
        dbg_continue_status = DBG_CONTINUE;
      } else {
        switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case EXCEPTION_BREAKPOINT:
        case 0x4000001f: //STATUS_WX86_BREAKPOINT
        {
          void *address = DebugEv->u.Exception.ExceptionRecord.ExceptionAddress;
          // printf("Breakpoint at address %p\n", address);
          int breakpoint_type = HandleDebuggerBreakpoint(address, DebugEv->dwThreadId);
          if (breakpoint_type == BREAKPOINT_UNKNOWN) {
            dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
          } else if (breakpoint_type == BREAKPOINT_PERSIST) {
            dbg_continue_status = DBG_CONTINUE;
            return DEBUGGER_PERSIST_REACHED;
          } else {
            dbg_continue_status = DBG_CONTINUE;
          }
          break;
        }

        case EXCEPTION_ACCESS_VIOLATION: {
          if ((size_t)DebugEv->u.Exception.ExceptionRecord.ExceptionAddress == PERSIST_END_EXCEPTION) {
            OnPersistMethodEnded(DebugEv->dwThreadId);
            dbg_continue_status = DBG_CONTINUE;
            return DEBUGGER_PERSIST_END;
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
          printf("Unhandled exception %x\n", DebugEv->u.Exception.ExceptionRecord.ExceptionCode);
          dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
          break;
        }
      }

      break;

    case CREATE_THREAD_DEBUG_EVENT:
      break;

    case CREATE_PROCESS_DEBUG_EVENT: {
      OnProcessCreated(&DebugEv->u.CreateProcessInfo);
      // add a brekpoint to the process entrypoint
      void *entrypoint = GetModuleEntrypoint(DebugEv->u.CreateProcessInfo.lpBaseOfImage);
      AddBreakpoint(entrypoint, BREAKPOINT_ENTRYPOINT, NULL, 0);
      CloseHandle(DebugEv->u.CreateProcessInfo.hFile);
      break;
    }

    case EXIT_THREAD_DEBUG_EVENT:
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
      alive = false;
      break;

    case LOAD_DLL_DEBUG_EVENT: {
      // Don't do anything until the processentrypoint is reached.
      // Before that time we can't do much anyway, a lot of calls are going to fail
      // Modules loaded before entrypoint is reached are going to be enumerated at that time
      if (child_entrypoint_reached) {
        char filename[MAX_PATH];
        GetFinalPathNameByHandleA(DebugEv->u.LoadDll.hFile, (LPSTR)(&filename), sizeof(filename), 0);
        char *base_name = strrchr(filename, '\\');
        if (base_name) base_name += 1;
        else base_name = filename;
        // printf("Module loaded: %s %p\n", base_name, DebugEv->u.LoadDll.lpBaseOfDll);
        printf("Module loaded: %s\n", base_name);
        OnModuleLoaded((HMODULE)DebugEv->u.LoadDll.lpBaseOfDll, base_name);
      }
      CloseHandle(DebugEv->u.LoadDll.hFile);
      break;
    }

    case UNLOAD_DLL_DEBUG_EVENT:
      OnModuleUnloaded((HMODULE)DebugEv->u.UnloadDll.lpBaseOfDll);
      break;

    case OUTPUT_DEBUG_STRING_EVENT:
      break;

    case RIP_EVENT:
      break;
    }

    ContinueDebugEvent(DebugEv->dwProcessId,
      DebugEv->dwThreadId,
      dbg_continue_status);
  }

  return DEBUGGER_PROCESS_EXIT;
}

// a simpler debugger loop that just waits for the process to exit
void Debugger::WaitProcessExit()
{
  bool alive = true;

  LPDEBUG_EVENT DebugEv = &dbg_debug_event;

  while (alive)
  {
    dbg_continue_status = DBG_CONTINUE;

    if (!WaitForDebugEvent(DebugEv, 100)) {
      continue;
    }

    //printf("eventCode: %x\n", DebugEv->dwDebugEventCode);

    switch (DebugEv->dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:
      dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      CloseHandle(DebugEv->u.CreateProcessInfo.hFile);
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
      alive = false;
      break;

    case LOAD_DLL_DEBUG_EVENT:
      CloseHandle(DebugEv->u.LoadDll.hFile);
      break;

    default:
      break;
    }

    ContinueDebugEvent(DebugEv->dwProcessId,
      DebugEv->dwThreadId,
      dbg_continue_status);
  }
}

// starts the target process
void Debugger::StartProcess(char *cmd) {
  STARTUPINFOA si;
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

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  if (sinkhole_stds) {
    si.hStdOutput = si.hStdError = devnul_handle;
    si.dwFlags |= STARTF_USESTDHANDLES;
  } else {
    inherit_handles = FALSE;
  }

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

  if (!CreateProcessA(NULL, cmd, NULL, NULL, inherit_handles, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
    FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
  }

  child_handle = pi.hProcess;
  child_thread_handle = pi.hThread;
  child_entrypoint_reached = false;
  persist_target_reached = false;

  if (mem_limit || cpu_aff) {
    if (!AssignProcessToJobObject(hJob, child_handle)) {
      FATAL("AssignProcessToJobObject failed, GLE=%d.\n", GetLastError());
    }
  }

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
  if (wow64current != wow64remote) {
    FATAL("Please use 64-bit build on 64-bit targets and 32-bit build on 32-bit targets\n");
  }
}

// called to resume the target process if it is waiting on a debug event
void Debugger::ResumeProcess() {
  ContinueDebugEvent(dbg_debug_event.dwProcessId,
    dbg_debug_event.dwThreadId,
    dbg_continue_status);
}

void Debugger::KillProcess() {
  TerminateProcess(child_handle, 0);

  if (dbg_continue_needed) ResumeProcess();

  WaitProcessExit();

  CloseHandle(child_handle);
  CloseHandle(child_thread_handle);

  child_handle = NULL;
  child_thread_handle = NULL;

  // delete any breakpoints that weren't hit
  DeleteBreakpoints();
}

int Debugger::Run(char *cmd, uint32_t timeout) {
  int debugger_status;
  int ret;

  if (!child_handle) {

    StartProcess(cmd);

    // wait until the target method is reached
    dbg_timeout_time = GetCurTime() + timeout;
    debugger_status = DebugLoop();

    if (debugger_status != DEBUGGER_PERSIST_REACHED) {
      switch (debugger_status) {
      case DEBUGGER_CRASHED:
        FATAL("Process crashed before reaching the target method\n");
        break;
      case DEBUGGER_HANGED:
        FATAL("Process hanged before reaching the target method\n");
        break;
      case DEBUGGER_PROCESS_EXIT:
        FATAL("Process exited before reaching the target method\n");
        break;
      default:
        FATAL("An unknown problem occured before reaching the target method\n");
        break;
      }
    }

    persist_iterations_current = 0;
  }

  printf("iteration %d\n", persist_iterations_current);

  dbg_timeout_time = GetCurTime() + timeout;

  // printf("iteration start\n");

  ResumeProcess();
  debugger_status = DebugLoop();

  // printf("iteration end\n");

  if (debugger_status == DEBUGGER_PROCESS_EXIT) {
    CloseHandle(child_handle);
    CloseHandle(child_thread_handle);
    child_handle = NULL;
    child_thread_handle = NULL;
    ret = FAULT_TMOUT; //treat it as a hang
  } else if (debugger_status == DEBUGGER_HANGED) {
    KillProcess();
    ret = FAULT_TMOUT;
  } else if (debugger_status == DEBUGGER_CRASHED) {
    KillProcess();
    ret = FAULT_CRASH;
  } else if (debugger_status == DEBUGGER_PERSIST_END) {
    ret = FAULT_NONE;
  }

  // TODO: examine coverage

  persist_iterations_current++;
  if (persist_iterations_current == persist_iterations && child_handle != NULL) {
    KillProcess();
  }

  return ret;
}


void Debugger::Init(int argc, char **argv) {
  child_handle = NULL;
  child_thread_handle = NULL;

  persist_module[0] = 0;
  persist_method[0] = 0;
  persist_offset = 0;
  persist_iterations = 1000;
  saved_args = NULL;
  persist_num_args = 0;
  calling_convention = CALLCONV_DEFAULT;

  char *option;

  option = GetOption("-target_module", argc, argv);
  if (option) strncpy(persist_module, option, MAX_PATH);

  option = GetOption("-target_method", argc, argv);
  if (option) strncpy(persist_method, option, MAX_PATH);

  option = GetOption("-iterations", argc, argv);
  if (option) persist_iterations = atoi(option);

  option = GetOption("-nargs", argc, argv);
  if (option) persist_num_args = atoi(option);

  option = GetOption("-target_offset", argc, argv);
  if (option) persist_offset = strtoul(option, NULL, 0);

  option = GetOption("-call_convention", argc, argv);
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

  if (persist_module[0] && (persist_offset == 0) && (persist_method[0] == 0)) {
    FATAL("If persist_module is specified, then either persist_offset or persist_method must be as well");
  }

  if (persist_num_args) {
    saved_args = (void **)malloc(persist_num_args * sizeof(void *));
  }
}
