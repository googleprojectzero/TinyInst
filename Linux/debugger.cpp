/*
Copyright 2023 Google LLC

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

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <dirent.h>
#include <pthread.h>

#include <algorithm>
#include <tuple>

#include "elffile.h"
#include "debugger.h"

#define BREAKPOINT_UNKNOWN 0x0
#define BREAKPOINT_ENTRYPOINT 0x01
#define BREAKPOINT_TARGET 0x02
#define BREAKPOINT_NOTIFICATION 0x04
#define BREAKPOINT_TARGET_END 0x08

#define PERSIST_END_EXCEPTION 0x0F22


// 32-bit link structute definitions
struct r_debug32
  {
    int r_version;
    uint32_t r_map;	/* Head of the chain of loaded objects.  */
    uint32_t r_brk;
    enum
      {
	RT_CONSISTENT,		/* Mapping change is complete.  */
	RT_ADD,			/* Beginning to add a new object.  */
	RT_DELETE		/* Beginning to remove an object mapping.  */
      } r_state;
    uint32_t r_ldbase;	/* Base address the linker is loaded at.  */
  };
  
struct link_map32
  {
    uint32_t l_addr;		/* Difference between the address in the ELF
				   file and the addresses in memory.  */
    uint32_t l_name;		/* Absolute file name object was found in.  */
    uint32_t l_ld;		/* Dynamic section of the shared object.  */
    uint32_t l_next, l_prev; /* Chain of loaded objects.  */
  };

void *debugger_watchdog_thread(void *arg)
{
  Debugger *debugger = (Debugger *)arg;
  debugger->Watchdog();
  return NULL;
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

bool operator< (LoadedModule const& lhs, LoadedModule const& rhs) {
  return std::tie(lhs.path, lhs.address) < std::tie(rhs.path, rhs.address);
}

#define ptrace_check(request, pid, addr, data) ({  \
    long ret = ptrace(request, pid, addr, data); \
    if(ret == -1) { \
      WARN("ptrace error %d", errno); \
      if(errno == ESRCH) SAY("thread doesn't exist anymore?\n"); \
      SAY(" Location : %s(), %s:%u\n\n", \
      __FUNCTION__, __FILE__, __LINE__); \
    } ret; })


char **Debugger::GetEnvp() {
  int environ_size = 0;
  char **p = environ;
  while (*p) {
    environ_size += 1;
    p++;
  }

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

void Debugger::RemoteRead(void *address, void *buffer, size_t size) {
  for (auto iter = shared_memory.begin(); iter != shared_memory.end(); ++iter) {
    if(((uint64_t)address >= iter->remote_address) && 
       ((uint64_t)address + size <= (iter->remote_address + iter->size)))
    {
      uint64_t shm_address = iter->local_address + ((uint64_t)address - iter->remote_address);
      memcpy(buffer, (void *)shm_address, size);
      return;
    }
  }

  ssize_t ret = pread(proc_mem_fd, buffer, size, (ssize_t)address);
  if(ret != size) {
    FATAL("Error reading target memory");
  }
}

void Debugger::RemoteWrite(void *address, const void *buffer, size_t size) {
  for (auto iter = shared_memory.begin(); iter != shared_memory.end(); ++iter) {
    if(((uint64_t)address >= iter->remote_address) && 
       ((uint64_t)address + size <= (iter->remote_address + iter->size)))
    {
      uint64_t shm_address = iter->local_address + ((uint64_t)address - iter->remote_address);
      memcpy((void *)shm_address, buffer, size);
      return;
    }
  }

  ssize_t ret = pwrite(proc_mem_fd, buffer, size, (ssize_t)address);
  if(ret != size) {
    FATAL("Error writing target memory");
  }
}

#ifdef ARM64

uint64_t* Debugger::GetRegisterHelper(Register r, arch_reg_struct *regs) {
  switch (r) {
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
    case X30:
      return (uint64_t *)&(regs->regs[(int)r]);
    case SP:
      return (uint64_t *)&(regs->sp);
    case PC:
      return (uint64_t *)&(regs->pc);
    case CPSR:
      return (uint64_t *)&(regs->pstate);
    default:
      FATAL("Unimplemented register");
  }
}

#else

uint64_t* Debugger::GetRegisterHelper(Register r, arch_reg_struct *regs) {
  switch (r) {
    case RAX:
      return (uint64_t *)&(regs->rax);
    case RCX:
      return (uint64_t *)&(regs->rcx);
    case RDX:
      return (uint64_t *)&(regs->rdx);
    case RBX:
      return (uint64_t *)&(regs->rbx);
    case RSP:
      return (uint64_t *)&(regs->rsp);
    case RBP:
      return (uint64_t *)&(regs->rbp);
    case RSI:
      return (uint64_t *)&(regs->rsi);
    case RDI:
      return (uint64_t *)&(regs->rdi);
    case R8:
      return (uint64_t *)&(regs->r8);
    case R9:
      return (uint64_t *)&(regs->r9);
    case R10:
      return (uint64_t *)&(regs->r10);
    case R11:
      return (uint64_t *)&(regs->r11);
    case R12:
      return (uint64_t *)&(regs->r12);
    case R13:
      return (uint64_t *)&(regs->r13);
    case R14:
      return (uint64_t *)&(regs->r14);
    case R15:
      return (uint64_t *)&(regs->r15);
    case RIP:
      return (uint64_t *)&(regs->rip);

    default:
      FATAL("Unimplemented register");
  }
}

#endif

void Debugger::GetArchRegs(arch_reg_struct *regs) {
#ifdef ARM64
  iovec io;
  io.iov_base = regs;
  io.iov_len = sizeof(*regs);
  ptrace_check(PTRACE_GETREGSET, current_pid, (void*)NT_PRSTATUS, &io);
#else
  ptrace_check(PTRACE_GETREGS, current_pid, 0, regs);
#endif
}

void Debugger::SetArchRegs(arch_reg_struct *regs) {
#ifdef ARM64
  iovec io;
  io.iov_base = regs;
  io.iov_len = sizeof(*regs);
  ptrace_check(PTRACE_SETREGSET, current_pid, (void*)NT_PRSTATUS, &io);
#else
  ptrace_check(PTRACE_SETREGS, current_pid, 0, regs);
#endif
}

size_t Debugger::GetRegister(Register r) {
  arch_reg_struct regs;
  GetArchRegs(&regs);
  uint64_t *ptr = GetRegisterHelper(r, &regs);
  return *ptr;
}

void Debugger::SetRegister(Register r, size_t value) {
  arch_reg_struct regs;
  GetArchRegs(&regs);
  uint64_t *ptr = GetRegisterHelper(r, &regs);
  *ptr = value;
  SetArchRegs(&regs);
}

void Debugger::SaveRegisters(SavedRegisters* registers) {
  GetArchRegs(&registers->saved_context);
}

void Debugger::RestoreRegisters(SavedRegisters* registers) {
  SetArchRegs(&registers->saved_context);
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

  if (target_function_defined && !strcasecmp(module_name, target_module)) {
    target_address = GetTargetAddress(module);
    if (!target_address) {
      FATAL("Error determing target method address\n");
    }

    AddBreakpoint(target_address, BREAKPOINT_TARGET);
  }
}

void Debugger::OnModuleUnloaded(void *module) {
  if (trace_debug_events) {
    SAY("Debugger: Unloaded module at %p\n", module);
  }
}

#ifdef ARM64
static unsigned char syscall_buf64[] = {
    // svc #0
    0x01,
    0x00,
    0x00,
    0xD4,
    // brk 0
    0x00,
    0x00,
    0x20,
    0xD4,
  };
  // not supported
  static unsigned char syscall_buf32[] = { };
#else
static unsigned char syscall_buf64[] = {
    // syscall
    0x0F,
    0x05,
    // breakpoint
    0xcc,
  };

static unsigned char syscall_buf32[] = {
    // sysenter
    //0x0F,
    //0x34,
    // int 0x80
    0xcd,
    0x80,
    // breakpoint
    0xcc,
  };

#endif

void Debugger::RemoteSyscall() {
  SetRegister(ARCH_PC, syscall_address);

  uint64_t rsp = GetRegister(ARCH_SP);

  ptrace_check(PTRACE_SINGLESTEP, current_pid, nullptr, nullptr);

  int status = 0;
  int wait_ret = waitpid(current_pid, &status, __WALL);
  if(wait_ret != current_pid) {
    FATAL("Unexpected wait result after syscall");
  }
  // printf("syscall status: %x\n", status);

  // uint64_t rip = GetRegister(RIP);
  // printf("rip: %lx, syscall_address: %lx\n", rip, syscall_address);

  if(rsp != GetRegister(ARCH_SP)) FATAL("rsp mismatch %lx %lx", rsp, GetRegister(ARCH_SP));
  // printf("Syscall status: %x\n", status);
}

void Debugger::SetSyscallArgs(uint64_t *args, size_t num_args) {
#ifdef ARM64
  if(num_args > 0) SetRegister(X0, args[0]);
  if(num_args > 1) SetRegister(X1, args[1]);
  if(num_args > 2) SetRegister(X2, args[2]);
  if(num_args > 3) SetRegister(X3, args[3]);
  if(num_args > 4) SetRegister(X4, args[4]);
  if(num_args > 5) SetRegister(X5, args[5]);
#else
  if(child_ptr_size == 4) {
    if(num_args > 0) SetRegister(RBX, args[0]);
    if(num_args > 1) SetRegister(RCX, args[1]);
    if(num_args > 2) SetRegister(RDX, args[2]);
    if(num_args > 3) SetRegister(RSI, args[3]);
    if(num_args > 4) SetRegister(RDI, args[4]);
    if(num_args > 5) SetRegister(RBP, args[5]);
  } else {
    if(num_args > 0) SetRegister(RDI, args[0]);
    if(num_args > 1) SetRegister(RSI, args[1]);
    if(num_args > 2) SetRegister(RDX, args[2]);
    if(num_args > 3) SetRegister(R10, args[3]);
    if(num_args > 4) SetRegister(R8, args[4]);
    if(num_args > 5) SetRegister(R9, args[5]);
  }
#endif
}


void* Debugger::RemoteMmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  SetupSyscalls();

  SavedRegisters saved_regs;
  SaveRegisters(&saved_regs);

  uint64_t args[6];
  args[0] = (uint64_t)addr;
  args[1] = (uint64_t)length;
  args[2] = (uint64_t)prot;
  args[3] = (uint64_t)flags;
  args[4] = (uint64_t)fd;
  args[5] = (uint64_t)offset;
  SetSyscallArgs(args, 6);

#ifdef ARM64
  SetRegister(X8, 0xde);
#else
  if(child_ptr_size == 4) {
    SetRegister(RAX, 0xC0);
  } else {
    SetRegister(RAX, 9);
  }
#endif

  RemoteSyscall();

#ifdef ARM64
  uint64_t ret = GetRegister(X0);
#else
  uint64_t ret = GetRegister(RAX);
#endif

  RestoreRegisters(&saved_regs);

  return (void *)ret;
}

int Debugger::RemoteMunmap(void *addr, size_t len) {
  SetupSyscalls();

  SavedRegisters saved_regs;
  SaveRegisters(&saved_regs);

  uint64_t args[2];
  args[0] = (uint64_t)addr;
  args[1] = (uint64_t)len;
  SetSyscallArgs(args, 2);

#ifdef ARM64
  SetRegister(X8, 0xd7);
#else
  if(child_ptr_size == 4) {
    SetRegister(RAX, 0x5b);
  } else {
    SetRegister(RAX, 11);
  }
#endif

  RemoteSyscall();

#ifdef ARM64
  uint64_t ret = GetRegister(X0);
#else
  uint64_t ret = GetRegister(RAX);
#endif

  RestoreRegisters(&saved_regs);

  return (int)ret;
}

int Debugger::RemoteOpen(const char *pathname, int flags, mode_t mode) {
  // we are using openat syscall since it's also supported by ARM64

  SetupSyscalls();

  SavedRegisters saved_regs;
  SaveRegisters(&saved_regs);

  size_t path_len = strlen(pathname);
  uint64_t pathname_addr = syscall_address + getpagesize() / 2;
  RemoteWrite((void *)pathname_addr, pathname, path_len);

  uint64_t args[4];
  args[0] = AT_FDCWD;
  args[1] = pathname_addr;
  args[2] = (uint64_t)flags;
  args[3] = (uint64_t)mode;
  SetSyscallArgs(args, 4);

#ifdef ARM64
  SetRegister(X8, 0x38);
#else
  if(child_ptr_size == 4) {
    SetRegister(RAX, 0x127);
  } else {
    SetRegister(RAX, 0x101);
  }
#endif

  RemoteSyscall();

#ifdef ARM64
  uint64_t ret = GetRegister(X0);
#else
  uint64_t ret = GetRegister(RAX);
#endif

  RestoreRegisters(&saved_regs);

  return (int)ret;
}


int Debugger::RemoteMprotect(void *addr, size_t len, int prot) {
  SetupSyscalls();

  SavedRegisters saved_regs;
  SaveRegisters(&saved_regs);

  uint64_t args[3];
  args[0] = (uint64_t)addr;
  args[1] = (uint64_t)len;
  args[2] = (uint64_t)prot;
  SetSyscallArgs(args, 3);

#ifdef ARM64
  SetRegister(X8, 0xe2);
#else
  if(child_ptr_size == 4) {
    SetRegister(RAX, 0x7d);
  } else {
    SetRegister(RAX, 10);
  }
#endif

  RemoteSyscall();

#ifdef ARM64
  uint64_t ret = GetRegister(X0);
#else
  uint64_t ret = GetRegister(RAX);
#endif

  RestoreRegisters(&saved_regs);

  return (int)ret;
}


void Debugger::RemoteProtect(void *address, size_t size, MemoryProtection protection) {
  int ret = RemoteMprotect(address, size, GetProt(protection));
  if(ret) {
    FATAL("Could not apply memory protection");
  }
}

int Debugger::GetProt(MemoryProtection protection) {
  switch (protection) {
    case READONLY:
      return PROT_READ;
    case READWRITE:
      return PROT_READ | PROT_WRITE;
    case READEXECUTE:
      return PROT_READ | PROT_EXEC;
    case READWRITEEXECUTE:
      return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:
      FATAL("Unimplemented memory protection");
  }
}

Debugger::SharedMemory *Debugger::CreateSharedMemory(size_t size) {
  SharedMemory shm;
  char name[56];
  int fd;

  for(int i=0; i<100; i++) {
    curr_shm_index++;

#ifdef __ANDROID__
    sprintf(name, "/data/local/tmp/tinyinstshm_%d_%u", gettid(), curr_shm_index);
    fd = open(name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC , 
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#else
    sprintf(name, "tinyinstshm_%d_%u", gettid(), curr_shm_index);
    fd = shm_open(name, O_RDWR | O_CREAT,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#endif
    if (fd == -1) {
      WARN("Could not create shared memory, retrying with a new name");
      continue;
    }
    break;
  }
  if (fd == -1) {
    FATAL("Error creating shared memory");
  }

  shm.name = name;

  char procfile[32];
  char shm_path[PATH_MAX + 1];
  sprintf(procfile, "/proc/%d/fd/%d", getpid(), fd);
  auto shm_path_size = readlink(procfile, shm_path, PATH_MAX);
  if(shm_path_size <= 0) {
    FATAL("Error reading exe path");
  }
  shm_path[shm_path_size] = 0;
  // printf("shared memory at %s\n", shm_path);

  // extend shared memory object as by default it's initialized with size 0
  if(ftruncate(fd, size) == -1) {
    FATAL("Error creating shared memory, ftruncate");
  }

  // map shared memory to process address space
  shm.local_address = (uint64_t)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (shm.local_address == (uint64_t)MAP_FAILED)
  {
    FATAL("Error creating shared memory, mmap");
  }

  int remote_fd = RemoteOpen(shm_path, O_RDWR | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
  if(remote_fd <= 0) FATAL("RemoteOpen error");

  shm.remote_address = 0;
  shm.size = size;
  shm.local_fd = fd;
  shm.remote_fd = remote_fd;

  shared_memory.push_front(shm);
  return &(*shared_memory.begin());
}

void Debugger::ClearSharedMemory() {
  for(auto iter = shared_memory.begin(); iter != shared_memory.end(); iter++) {
    munmap((void *)iter->local_address, iter->size);
    close(iter->local_fd);
#ifdef __ANDROID__
    unlink(iter->name.c_str());
#else
    shm_unlink(iter->name.c_str());
#endif
  }
  shared_memory.clear();
}

void* Debugger::RemoteAllocate(size_t size, MemoryProtection protection, bool use_shared_memory) {
  SharedMemory *shm = NULL;
  if(use_shared_memory) shm = CreateSharedMemory(size);

  int fd = 0;
  int flags = 0;
  if(shm) {
    fd = shm->remote_fd;
    flags |= MAP_SHARED;
    shm->remote_address = 0;
  } else {
    flags |= MAP_PRIVATE | MAP_ANONYMOUS;
  }

  void *ret = RemoteMmap(NULL, size, GetProt(protection), flags, fd ,0);
  if(ret == MAP_FAILED) return NULL;

  if(shm) shm->remote_address = (uint64_t)ret;
  return ret;
}

void Debugger::RemoteFree(void *address, size_t size) {
  int ret = RemoteMunmap(address, size);
  if(ret) FATAL("Error freeing memory in child process");
}


void *Debugger::RemoteAllocateNear(uint64_t region_min,
				        uint64_t region_max,
				        size_t size,
				        MemoryProtection protection,
				        bool use_shared_memory)
{
  SharedMemory *shm = NULL;
  if(use_shared_memory) shm = CreateSharedMemory(size);

  uint64_t min_address, max_address;

  MapsParser maps_parser;
  std::vector<MapsEntry> map_entries;
  maps_parser.Parse(main_pid, map_entries);
  if(map_entries.empty()) FATAL("Error parsing /proc/%d/maps", main_pid);

  void *ret_address;

  //try before
  min_address = (region_max < 0x80000000) ? 0 : region_max - 0x80000000;
  max_address = (region_min < size) ? 0 : region_min - size;
  ret_address = RemoteAllocateBefore(min_address, max_address, size, protection, map_entries,shm);
  if (ret_address != NULL) {
    return ret_address;
  }

  //try after
  min_address = region_max;
  max_address = (UINT64_MAX - region_min < 0x80000000) ? UINT64_MAX : region_min + 0x80000000;
  if((child_ptr_size == 4) && (max_address > UINT32_MAX)) max_address = UINT32_MAX;
  ret_address = RemoteAllocateAfter(min_address, max_address, size, protection, map_entries, shm);
  if (ret_address != NULL) {
    return ret_address;
  }

  return NULL;
}

void *Debugger::RemoteAllocateAfter(uint64_t min_address,
                                    uint64_t max_address,
                                    size_t size,
                                    MemoryProtection protection,
                                    std::vector<MapsEntry> &map_entries,
                                    Debugger::SharedMemory *shm)
{
  uint64_t cur_address = min_address;
  uint64_t cur_entry_index = 0;
  MapsEntry *entry = NULL;

  uint64_t page_size = getpagesize();
  uint64_t page_offset = cur_address % page_size;
  if(page_offset) {
    cur_address += page_size - page_offset;
  }

  while(cur_address < max_address) {
    if(cur_entry_index >= map_entries.size()) {
      entry = NULL;
    } else {
      entry = &map_entries[cur_entry_index];
    }
    // printf("cur_address: %lx\n", cur_address);
    // if(entry) printf("cur_entry: %lx %lx\n", entry->addr_from, entry->addr_to);
    if(entry && (entry->addr_to <= cur_address)) {
      cur_entry_index++;
      continue;
    }
    if(entry && 
       (cur_address >= entry->addr_from) && 
       (cur_address < entry->addr_to)) 
    {
      cur_address = entry->addr_to;
      cur_entry_index++;
      continue;
    }
    if(entry && ((entry->addr_from - cur_address) < size)) {
      cur_address = entry->addr_to;
      cur_entry_index++;
      continue;
    }
    void *ret = RemoteAllocateAt(cur_address, size, protection, shm);
    if(ret) {
      return ret;
    }
    if(cur_address + page_size < cur_address) return NULL;
    cur_address += page_size;
  }
  return NULL;
}

void *Debugger::RemoteAllocateBefore(uint64_t min_address,
                                     uint64_t max_address,
                                     size_t size,
                                     MemoryProtection protection,
                                     std::vector<MapsEntry> &map_entries,
                                     Debugger::SharedMemory *shm)
{
  uint64_t cur_address = max_address;
  int64_t cur_entry_index = map_entries.size() - 1;
  MapsEntry *entry = NULL;
  
  uint64_t page_size = getpagesize();
  uint64_t page_offset = cur_address % page_size;
  if(page_offset) {
    cur_address -= page_size;
  }

  while(cur_address >= min_address) {
    if(cur_entry_index < 0) {
      entry = NULL;
    } else {
      entry = &map_entries[cur_entry_index];
    }
    if(entry && (entry->addr_from >= (cur_address + size))) {
      cur_entry_index--;
      continue;
    }
    if(entry && 
       ((cur_address + size) >= entry->addr_from) && 
       ((cur_address + size) < entry->addr_to)) 
    {
      if(entry->addr_from < size) return NULL;
      cur_address = entry->addr_from - size;
      cur_entry_index--;
      continue;
    }
    if(entry && (cur_address < entry->addr_to)) {
      if(entry->addr_from < size) return NULL;
      cur_address = entry->addr_from - size;
      cur_entry_index--;
      continue;
    }
    // printf("Attempting to allocate at %lx\n", cur_address);
    void *ret = RemoteAllocateAt(cur_address, size, protection, shm);
    if(ret) {
      // printf("Allocated at %p\n", ret);
      return ret;
    }
    // printf("Fail\n");
    if(cur_address < page_size) return NULL;
    cur_address -= page_size;
  }
  return NULL;
}


void *Debugger::RemoteAllocateAt(uint64_t address, uint64_t size, MemoryProtection protection, Debugger::SharedMemory *shm) {
  int fd = 0;
  int flags = MAP_FIXED_NOREPLACE;
  if(shm) {
    fd = shm->remote_fd;
    flags |= MAP_SHARED;
    shm->remote_address = 0;
  } else {
    flags |= MAP_PRIVATE | MAP_ANONYMOUS;
  }

  void *ret = RemoteMmap((void *)address, size, GetProt(protection), flags, fd, 0);
  if(ret != (void *)address) return NULL;

  if(shm) shm->remote_address = (uint64_t)ret;
  return ret;
}

void Debugger::OnEntrypoint() {
  if (trace_debug_events) {
    SAY("Debugger: Process entrypoint reached\n");
  }

  if(!attach_mode) SetupSyscalls();

  SetupModules();

  child_entrypoint_reached = true;
}

template<typename T_r_debug, typename T_link_map>
int Debugger::GetLoadedModulesT(std::set<LoadedModule> &modules, bool set_breakpoint) {
  T_r_debug debug;
  T_link_map map;

  RemoteRead((void *)(rendezvous_address), &debug, sizeof(debug));
  uint64_t cur_map_addr = (uint64_t)debug.r_map;

  // printf("State: %d\n", debug.r_state);
  // only care about the consistent state unless calling at entrypoint
  if((debug.r_state != T_r_debug::RT_CONSISTENT) && !set_breakpoint) return 0;

  modules.insert({main_binary_path, main_binary_header});

  while(cur_map_addr) {
    RemoteRead((void *)(cur_map_addr), &map, sizeof(map));

    char name[PATH_MAX + 1];
    if(!ReadCString((uint64_t)map.l_name, name, sizeof(name))) {
      FATAL("Error reading module name");
    }

    if(name[0] && (main_binary_path != name)) {
      modules.insert({std::string(name), (uint64_t)map.l_addr});
    }

    cur_map_addr = (uint64_t)map.l_next;
  }

  if(set_breakpoint) {
    AddBreakpoint((void *)(uint64_t)debug.r_brk, BREAKPOINT_NOTIFICATION); 
  }

  return 1;
}

int Debugger::GetLoadedModules(std::set<LoadedModule> &modules, bool set_breakpoint) {
  if(child_ptr_size == 4) {
    return GetLoadedModulesT<r_debug32, link_map32>(modules, set_breakpoint);
  } else {
    return GetLoadedModulesT<r_debug, link_map>(modules, set_breakpoint);
  }
}

void Debugger::OnLoadedModulesChanged(bool set_breakpoint) {
  std::set<LoadedModule> new_modules;

  if(!GetLoadedModules(new_modules, set_breakpoint)) return;

  std::vector<LoadedModule> loaded;
  std::vector<LoadedModule> unloaded;

  std::set_difference(loaded_modules.begin(), loaded_modules.end(),
                      new_modules.begin(), new_modules.end(),
                      std::back_inserter(unloaded));
  std::set_difference(new_modules.begin(), new_modules.end(),
                      loaded_modules.begin(), loaded_modules.end(),
                      std::back_inserter(loaded));

  loaded_modules = new_modules;

  for(auto iter = unloaded.begin(); iter != unloaded.end(); ++iter) {
    OnModuleUnloaded((void *)iter->address);  
  }

  for(auto iter = loaded.begin(); iter != loaded.end(); ++iter) {
    const char *name = iter->path.c_str();
    const char *base_name = strrchr(name, '/');
    base_name = (base_name) ? base_name + 1 : name;
    OnModuleLoaded((void *)iter->address, (char *)base_name);  
  }
}

void Debugger::SetupSyscalls() {
  if(syscall_address) return;

  size_t syscall_buf_size;
  unsigned char *syscall_buf;

  if(child_ptr_size == 4) {
    syscall_buf = syscall_buf32;
    syscall_buf_size = sizeof(syscall_buf32);
  } else {
    syscall_buf = syscall_buf64;
    syscall_buf_size = sizeof(syscall_buf64);
  }

  // set up everything so we can make syscalls in the target process
  char *saved_code = (char *)malloc(syscall_buf_size);
  RemoteRead((void *)entrypoint_address, saved_code, syscall_buf_size);
  RemoteWrite((void *)entrypoint_address, syscall_buf, syscall_buf_size);
  
  syscall_address = entrypoint_address;

  debugger_allocated_memory = (uint64_t)RemoteAllocate(getpagesize(), READWRITEEXECUTE);
  if(!debugger_allocated_memory) {
    FATAL("Error allocating memory in target");
  }
  RemoteWrite((void *)debugger_allocated_memory, syscall_buf, syscall_buf_size);

  syscall_address = debugger_allocated_memory;

  RemoteWrite((void *)entrypoint_address, saved_code, syscall_buf_size);

  free(saved_code);
}

void Debugger::SetupModules() {
  loaded_modules.insert({main_binary_path, main_binary_header});
  OnModuleLoaded((void *)main_binary_header, (char *)main_binary_name.c_str());

  uint64_t dynamic = GetSegment(main_binary_header, PT_DYNAMIC, 0);

  // statically linked and we already notified loading of main module
  if(!dynamic) {
    rendezvous_address = 0;
    return;
  }

  uint8_t e_ident;
  uint64_t pie_offset;
  GetElfIdentAndOffset(main_binary_header, &e_ident, &pie_offset);

  uint64_t rendezvous = 0;
  if(e_ident == 1) {
     Elf32_Dyn dyn;
     int i = 0;
     while(1) {
       RemoteRead((void *)(dynamic + i * sizeof(dyn)), &dyn, sizeof(dyn));
       i++;
       if(dyn.d_tag == DT_NULL) break;
       if(dyn.d_tag == DT_DEBUG) {
         rendezvous = dyn.d_un.d_ptr;
         break;
       }
     } 
  } else {
     Elf64_Dyn dyn;
     int i = 0;
     while(1) {
       RemoteRead((void *)(dynamic + i * sizeof(dyn)), &dyn, sizeof(dyn));
       i++;
       if(dyn.d_tag == DT_NULL) break;
       if(dyn.d_tag == DT_DEBUG) {
         rendezvous = dyn.d_un.d_ptr;
         break;
       }
     } 
  }

  if(!rendezvous) {
    FATAL("Error finding rendezvous structure");
  }

  rendezvous_address = rendezvous;

  OnLoadedModulesChanged(true);
}

void Debugger::OnNotifier() {
  // printf("Notifier breakpoint\n");

  //simulate a return


#ifdef ARM64 
  SetRegister(ARCH_PC, GetRegister(LR));
#else
  uint64_t rsp = GetRegister(RSP);
  uint64_t ret_address = 0;
  RemoteRead((void *)rsp, &ret_address, child_ptr_size);
  rsp = rsp + child_ptr_size;
  SetRegister(RSP, rsp);
  SetRegister(RIP, ret_address);
#endif

  OnLoadedModulesChanged(false);
}

size_t Debugger::GetReturnAddress() {
#ifdef ARM64 
  return GetRegister(LR);
#else
  if(child_ptr_size == 4) {
    uint32_t ra;
    RemoteRead((void*)GetRegister(RSP), &ra, sizeof(ra));
    return (size_t)ra;
  } else {
    uint64_t ra;
    RemoteRead((void*)GetRegister(RSP), &ra, sizeof(ra));
    return (size_t)ra;
  }
#endif
}

void Debugger::SetReturnAddress(size_t value) {
#ifdef ARM64 
  SetRegister(LR, value);
#else
  if(child_ptr_size == 4) {
    uint32_t ret_addr = (uint32_t)value;
    RemoteWrite((void*)GetRegister(RSP), &ret_addr, sizeof(ret_addr));
  } else {
    uint64_t ret_addr = (uint64_t)value;
    RemoteWrite((void*)GetRegister(RSP), &ret_addr, sizeof(ret_addr));
  }
#endif
}

void Debugger::ReadStack(void *stack_addr, uint64_t *buffer, size_t numitems) {
  if (child_ptr_size == 4) {
    uint32_t* buf32 = (uint32_t*)malloc(numitems * child_ptr_size);
    RemoteRead(stack_addr, buf32, numitems * child_ptr_size);
    for (size_t i = 0; i < numitems; i++) {
      buffer[i] = ((uint64_t)buf32[i]);
    }
    free(buf32);
    return;
  }
  RemoteRead(stack_addr, buffer, numitems * child_ptr_size);
}

void Debugger::WriteStack(void *stack_addr, uint64_t *buffer, size_t numitems) {
  if (child_ptr_size == 4) {
    uint32_t *buf32 = (uint32_t *)malloc(numitems * child_ptr_size);
    for (size_t i = 0; i < numitems; i++) {
      buf32[i] = (uint32_t)(buffer[i]);
    }
    RemoteWrite(stack_addr, buf32, numitems * child_ptr_size);
    free(buf32);
    return;
  }
  RemoteWrite(stack_addr, buffer, numitems * child_ptr_size);
}

void Debugger::GetFunctionArguments(uint64_t *arguments, size_t num_arguments, uint64_t sp, CallingConvention callconv) {
  int max_num_reg_args;
#ifdef ARM64
  max_num_reg_args = 8;
#else
  if(child_ptr_size == 4) {
    max_num_reg_args = 0; // todo do we need to support other calling conventions?
  } else {
    max_num_reg_args = 6;
  }
#endif

  for (int arg_index = 0; arg_index < max_num_reg_args && arg_index < num_arguments; ++arg_index) {
    arguments[arg_index] = GetRegister(ArgumentToRegister(arg_index));
  }

  if (num_arguments > max_num_reg_args) {
    ReadStack((void*)((uint64_t)sp + child_ptr_size),
              arguments + max_num_reg_args,
              num_arguments - max_num_reg_args);
  }
}

void Debugger::SetFunctionArguments(uint64_t *arguments, size_t num_arguments, uint64_t sp, CallingConvention callconv) {
  int max_num_reg_args;
#ifdef ARM64
  max_num_reg_args = 8;
#else
  if(child_ptr_size == 4) {
    max_num_reg_args = 0; // todo do we need to support other calling conventions?
  } else {
    max_num_reg_args = 6;
  }
#endif

  for (int arg_index = 0; arg_index < max_num_reg_args && arg_index < num_arguments; ++arg_index) {
    SetRegister(ArgumentToRegister(arg_index), arguments[arg_index]);
  }

  if (num_arguments > max_num_reg_args) {
    WriteStack((void*)((uint64_t)sp + child_ptr_size),
               arguments + max_num_reg_args,
               num_arguments - max_num_reg_args);
  }
}

void Debugger::HandleTargetReachedInternal() {
  saved_sp = (void*)GetRegister(ARCH_SP);
  saved_return_address = (void*)GetReturnAddress();

  if (loop_mode) {
    GetFunctionArguments((uint64_t *)saved_args, target_num_args, (uint64_t)saved_sp, CALLCONV_DEFAULT);
  }

  if (!target_reached) {
    target_reached = true;
    OnTargetMethodReached();
  }

  if (target_end_detection == RETADDR_STACK_OVERWRITE) {
    size_t return_address = PERSIST_END_EXCEPTION;
    RemoteWrite(saved_sp, &return_address, child_ptr_size);
  } else if (target_end_detection == RETADDR_BREAKPOINT) {
    AddBreakpoint((void*)GetTranslatedAddress((size_t)saved_return_address), BREAKPOINT_TARGET_END);
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

    SetFunctionArguments((uint64_t *)saved_args, target_num_args, (uint64_t)saved_sp, CALLCONV_DEFAULT);
  } else {
    SetRegister(ARCH_PC, (size_t)saved_return_address);
    AddBreakpoint((void*)GetTranslatedAddress((size_t)target_address), BREAKPOINT_TARGET);
  }
}


int Debugger::HandleDebuggerBreakpoint() {
  int ret = BREAKPOINT_UNKNOWN;

  Breakpoint *breakpoint = NULL, *tmp_breakpoint;
  for (auto iter = breakpoints.begin(); iter != breakpoints.end(); iter++) {
    tmp_breakpoint = *iter;
    if (tmp_breakpoint->address == (void*)(last_exception.ip)) {
      breakpoint = tmp_breakpoint;
      if (breakpoint->type & BREAKPOINT_NOTIFICATION) {
#ifdef ARM64
        uint32_t expected_opcode = 0xd65f03c0;
#else
        unsigned char expected_opcode = 0xc3;
#endif
        if(breakpoint->original_opcode != expected_opcode) {
          FATAL("Unexpected notifier function %x", (uint32_t)breakpoint->original_opcode);
        }
        OnNotifier();
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

void *Debugger::GetModuleEntrypoint(void *base_address) {
  uint64_t exe_address = (uint64_t)base_address;

  uint32_t magic;
  RemoteRead((void *)exe_address, &magic, sizeof(magic));
  if(magic != 0x464c457f) {
    FATAL("Elf header expected");
  }
  uint8_t e_ident;
  RemoteRead((void *)(exe_address + 4), &e_ident, sizeof(e_ident));
  if((e_ident != 1) && (e_ident != 2)) FATAL("e_ident invalid value");

  uint16_t e_type;
  RemoteRead((void *)(exe_address + 0x10), &e_type, sizeof(e_type));
 
  bool pie = (e_type == 3);

  uint16_t e_machine;
  RemoteRead((void *)(exe_address + 0x12), &e_machine, sizeof(e_machine));

  if(e_machine == 3) { // x86
    if(linux32_warning) {
      linux32_warning = false;
      WARN("32-bit Linux target detected. -patch_return_addresses flag might be needed.");
    }
    child_ptr_size = 4;
  } else if(e_machine == 0x3e) { // x64
    child_ptr_size = 8;
  } else if(e_machine == 0xB7) { // ARM64
    child_ptr_size = 8;
  } else {
    FATAL("Unsupported machine type 0x%x", (int)e_machine);
  }

  uint64_t entrypoint;
  if(e_ident == 1) {
    uint32_t entry32;
    RemoteRead((void *)(exe_address + 0x18), &entry32, sizeof(entry32));
    entrypoint = entry32;
  } else {
    RemoteRead((void *)(exe_address + 0x18), &entrypoint, sizeof(entrypoint));
  }

  if(pie) entrypoint += exe_address;

  if(!entrypoint) {
    FATAL("Couldn't find entrypoint");
  }

  return (void *)entrypoint;
}

void Debugger::GetImageSize(void *base_address, size_t *min_address, size_t *max_address) {
  uint64_t min = UINT64_MAX;
  uint64_t max = 0;
  bool found = false;

  std::string elf_filename;
  GetModuleFilename(base_address, &elf_filename);
  if(elf_filename.empty()) FATAL("Error retrieving module path");
  ResolveSymlinks(&elf_filename);

  MapsParser maps_parser;
  std::vector<MapsEntry> map_entries;
  maps_parser.Parse(main_pid, map_entries);
  if(map_entries.empty()) FATAL("Error parsing /proc/%d/maps", main_pid);
  for(auto iter = map_entries.begin(); iter <= map_entries.end(); iter++) {
    if(iter->name == elf_filename) {
      if(iter->addr_from < min) min = iter->addr_from;
      if(iter->addr_to > max) max = iter->addr_to;
      found = true;
    }
  }

  if(!found) FATAL("Error getting module bounds");

  *min_address = min;
  *max_address = max;
}

void Debugger::ExtractCodeRanges(void *module_base,
                                 size_t min_address,
                                 size_t max_address,
                                 std::list<AddressRange> *executable_ranges,
                                 size_t *code_size)
{
  std::string elf_filename;
  GetModuleFilename(module_base, &elf_filename);
  if(elf_filename.empty()) FATAL("Error retrieving module path");
  ResolveSymlinks(&elf_filename);

  *code_size = 0;

  MapsParser maps_parser;
  std::vector<MapsEntry> map_entries;
  maps_parser.Parse(main_pid, map_entries);
  if(map_entries.empty()) FATAL("Error parsing /proc/%d/maps", main_pid);
  for(auto iter = map_entries.begin(); iter <= map_entries.end(); iter++) {
    if(iter->name != elf_filename) continue;

    if(!(iter->permissions & PROT_EXEC)) continue;

    int ret = RemoteMprotect((void *)iter->addr_from, 
                             (iter->addr_to - iter->addr_from), 
                             iter->permissions ^ PROT_EXEC);
    if(ret) {
      FATAL("Could not apply memory protection");
    }

    AddressRange range;
    range.from = iter->addr_from;
    range.to = iter->addr_to;
    range.data = (char *)malloc(range.to - range.from);
    RemoteRead((void *)range.from, range.data, range.to - range.from);

    executable_ranges->push_back(range);
    *code_size += range.to - range.from;
  }
}

void Debugger::ProtectCodeRanges(std::list<AddressRange> *executable_ranges) {
  MapsParser maps_parser;
  std::vector<MapsEntry> map_entries;
  maps_parser.Parse(main_pid, map_entries);

  for(auto iter = executable_ranges->begin(); iter != executable_ranges->end(); iter++) {
    bool found = false;
    int prot = 0;
    for(auto mapsiter = map_entries.begin(); mapsiter != map_entries.end(); mapsiter++) {
      if(mapsiter->addr_from == iter->from && mapsiter->addr_to == iter->to) {
        found = true;
        prot = mapsiter->permissions;
        break;
      }
    }

    if(!found) FATAL("Error finding address range");

    if(!(prot & PROT_EXEC)) continue;

    int ret = RemoteMprotect((void *)iter->from, 
                             (iter->to - iter->from), 
                             prot ^ PROT_EXEC);
    if(ret) {
      FATAL("Could not apply memory protection");
    }
  }
}

void Debugger::PatchPointersRemote(void *base_address, std::unordered_map<size_t, size_t>& search_replace) {
  std::string elf_filename;
  GetModuleFilename(base_address, &elf_filename);
  if(elf_filename.empty()) FATAL("Error retrieving module path");
  ResolveSymlinks(&elf_filename);

  MapsParser maps_parser;
  std::vector<MapsEntry> map_entries;
  maps_parser.Parse(main_pid, map_entries);
  if(map_entries.empty()) FATAL("Error parsing /proc/%d/maps", main_pid);
  for(auto iter = map_entries.begin(); iter <= map_entries.end(); iter++) {
    if(iter->name != elf_filename) continue;

    PatchPointersRemote(iter->addr_from, iter->addr_to, search_replace);
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

// TODO: make faster
int Debugger::ReadCString(uint64_t address, char *str, size_t size) {
  size_t index = 0;
  while((index + 1) < size) {
    char c;
    RemoteRead((void *)(address + index), &c, 1);
    str[index] = c;
    index++;
    if(!c) return 1;
  }
  return 0;
}

void Debugger::ResolveSymlinks(std::string *path) {
  auto iter = symlink_cache.find(*path);
  if(iter != symlink_cache.end()) {
    *path = iter->second;
    return;
  }

  char buf[PATH_MAX];
  char *res = realpath(path->c_str(), buf);
  if(!res) {
    symlink_cache[*path] = *path;
  } else {
    *path = res;
    symlink_cache[*path] = res;
  }
}


void Debugger::GetElfIdentAndOffset(uint64_t header, uint8_t *ident, uint64_t *pie_offset) {
  uint8_t e_ident;
  RemoteRead((void *)(header + 4), &e_ident, sizeof(e_ident));
  if(ident) *ident = e_ident;
  
  if(pie_offset) *pie_offset = 0;

  uint16_t e_type;
  RemoteRead((void *)(header + 0x10), &e_type, sizeof(e_type)); 
  if((e_type == 3) && pie_offset) *pie_offset = header;
}

uint64_t Debugger::GetSegment(uint64_t header, uint32_t type, uint64_t *segment_size) {
  uint8_t e_ident;
  uint64_t pie_offset;
  GetElfIdentAndOffset(header, &e_ident, &pie_offset);

  uint16_t e_phentsize, e_phnum;
  uint64_t program_table;
  if(e_ident == 1) {
    uint32_t program_table32;
    RemoteRead((void *)(header + 0x1C), &program_table32, sizeof(program_table32));
    program_table = program_table32 + pie_offset;
    RemoteRead((void *)(header + 0x2A), &e_phentsize, sizeof(e_phentsize)); 
    RemoteRead((void *)(header + 0x2C), &e_phnum, sizeof(e_phnum)); 
  } else {
    RemoteRead((void *)(header + 0x20), &program_table, sizeof(program_table));
    program_table += pie_offset;
    RemoteRead((void *)(header + 0x36), &e_phentsize, sizeof(e_phentsize)); 
    RemoteRead((void *)(header + 0x38), &e_phnum, sizeof(e_phnum)); 
  }

  for(int i = 0; i < e_phnum; i++) {
    uint64_t program_header = program_table + i * e_phentsize;

    uint32_t p_type;
    RemoteRead((void *)(program_header), &p_type, sizeof(p_type));

    if(type == p_type) {
      uint64_t p_vaddr;
      uint64_t p_memsz;
      if(e_ident == 1) {
        uint32_t p_vaddr32;
        uint32_t p_memsz32;
        RemoteRead((void *)(program_header + 0x08), &p_vaddr32, sizeof(p_vaddr32));
        p_vaddr = p_vaddr32 + pie_offset;
        RemoteRead((void *)(program_header + 0x14), &p_memsz32, sizeof(p_memsz32));
        p_memsz = p_memsz32;
      } else {
        RemoteRead((void *)(program_header + 0x10), &p_vaddr, sizeof(p_vaddr));
        p_vaddr += pie_offset;
        RemoteRead((void *)(program_header + 0x28), &p_memsz, sizeof(p_memsz));
      }
      if(segment_size) *segment_size = p_memsz;
      return p_vaddr;
    }
  }

  if(segment_size) *segment_size = 0;
  return 0;
}

void Debugger::GetModuleFilename(void *base_address, std::string *name) {
  for(auto iter = loaded_modules.begin(); iter != loaded_modules.end(); iter++) {
    if(iter->address == (uint64_t)base_address) {
      *name = iter->path;
      return;
    }
  }
  FATAL("Could not find the module to do symbol lookup");
}

void *Debugger::GetSymbolAddress(void *base_address, const char *symbol_name) {
  std::string elf_filename;
  GetModuleFilename(base_address, &elf_filename);

  ElfFile file;
  file.OpenFile(elf_filename.c_str());
  uint64_t ret = file.GetSymbolAddress(symbol_name);
  if(ret && file.IsPIE()) ret += (uint64_t)base_address;

  return (void *)ret;
}

void Debugger::OnProcessCreated() {
  char procfile[24];
  char exe_path[PATH_MAX + 1];
  size_t exe_address = 0;
  syscall_address = 0;

  sprintf(procfile, "/proc/%d/exe", main_pid);
  auto exe_path_size = readlink(procfile, exe_path, PATH_MAX);
  if(exe_path_size <= 0) {
    FATAL("Error reading exe path");
  }
  exe_path[exe_path_size] = 0;
  main_binary_path = exe_path;

  char *base_name = strrchr(exe_path, '/');
  base_name = (base_name) ? base_name + 1 : exe_path;
  main_binary_name = base_name;

  std::string resolved_path = main_binary_path;
  ResolveSymlinks(&resolved_path);

  sprintf(procfile, "/proc/%d/mem", main_pid);
  proc_mem_fd = open(procfile, O_RDWR);

  MapsParser maps_parser;
  std::vector<MapsEntry> map_entries;
  maps_parser.Parse(main_pid, map_entries);
  if(map_entries.empty()) FATAL("Error parsing /proc/%d/maps", main_pid);
  for(auto iter = map_entries.begin(); iter <= map_entries.end(); iter++) {
    if(iter->name == resolved_path) {
      exe_address = iter->addr_from;
      break;
    }
  }

  if(!exe_address) FATAL("Error getting binary load address");

  // printf("Main binary %s loaded at 0x%lx\n", exe_path, exe_address);

  entrypoint_address = (uint64_t)GetModuleEntrypoint((void *)exe_address);

  main_binary_header = exe_address;

  // printf("Entrypoint: 0x%lx\n", entrypoint_address);

  if(!attach_mode) {
    AddBreakpoint((void *)entrypoint_address, BREAKPOINT_ENTRYPOINT);
  }
}

void Debugger::SetThreadOptions(pid_t pid) {
  // printf("Setting thread options for pid %d\n", pid);

  int64_t opts = 0;
  opts |= PTRACE_O_TRACEEXIT;
  opts |= PTRACE_O_TRACECLONE;
  opts |= PTRACE_O_TRACEFORK;
  opts |= PTRACE_O_TRACEVFORK;
  if(!attach_mode) opts |= PTRACE_O_EXITKILL;

  ptrace_check(PTRACE_SETOPTIONS, pid, nullptr, (void *)opts);
}

DebuggerStatus Debugger::Kill() {
  if(main_pid <= 0) return DEBUGGER_PROCESS_EXIT;

  killing_target = true;
  // ptrace_check(PTRACE_KILL, main_pid, 0, 0);
  kill(main_pid, SIGKILL);

  //SIGKILL is not handled, so DebugLoop must return DEBUGGER_PROCESS_EXIT
  dbg_last_status = DebugLoop(0xffffffff);
  if (dbg_last_status != DEBUGGER_PROCESS_EXIT) {
    FATAL("Unable to kill the process\n");
  }

  DeleteBreakpoints();
  killing_target = false;

  return dbg_last_status;
}

DebuggerStatus Debugger::HandleStopped(int status) {
  last_exception.type = OTHER;
  last_exception.ip = 0;
  last_exception.access_address = 0;
  last_exception.maybe_execute_violation = false;
  last_exception.maybe_write_violation = false;

  if(WSTOPSIG(status) == SIGTRAP) {
    if (((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) || ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))) {
      FATAL("fork() in a target is not supported");
      return DEBUGGER_CONTINUE;
    } else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
      unsigned long event_message = 0;
      ptrace_check(PTRACE_GETEVENTMSG, current_pid, nullptr, &event_message);
      pid_t new_thread_pid = (pid_t)event_message;
      if (trace_debug_events) printf("Debugger: New thread, pid: %d\n", new_thread_pid);
      if(threads.find(new_thread_pid) == threads.end()) {
        int new_thread_status = 0;
        pid_t ret_pid = waitpid(new_thread_pid, &new_thread_status, __WALL);
        if(ret_pid != new_thread_pid) FATAL("Unexpected waitpid result waiting for new thread\n");
        if(!WIFSTOPPED(new_thread_status)) FATAL("Unexpected status from a new thread");
        SetThreadOptions(new_thread_pid);
        ptrace_check(PTRACE_CONT, new_thread_pid, 0, 0);
        threads.insert(new_thread_pid);
      }
      return DEBUGGER_CONTINUE;
    } else {
      last_exception.type = BREAKPOINT;
#ifdef ARM64
      last_exception.ip = (void *)GetRegister(PC);
      SetRegister(PC, GetRegister(PC) + 4);
#else
      last_exception.ip = (void *)(GetRegister(RIP) - 1);
#endif
      if (trace_debug_events) {
        SAY("Debugger: Breakpoint at %p\n", last_exception.ip);
      }
      int breakpoint_type = HandleDebuggerBreakpoint();
      if (breakpoint_type & BREAKPOINT_TARGET) {
        return DEBUGGER_TARGET_START;
      }
      if (breakpoint_type & BREAKPOINT_TARGET_END) {
        return DEBUGGER_TARGET_END;
      }
    }
  } else if(WSTOPSIG(status) == SIGSEGV) {
    siginfo_t siginfo;
    ptrace_check(PTRACE_GETSIGINFO, current_pid, 0, &siginfo);

    last_exception.type = ACCESS_VIOLATION;
    last_exception.ip = (void *)GetRegister(ARCH_PC);
    last_exception.access_address = siginfo.si_addr;
    last_exception.maybe_execute_violation = true;
    last_exception.maybe_write_violation = true;
  } else if(WSTOPSIG(status) == SIGILL) {

    last_exception.type = ILLEGAL_INSTRUCTION;
    last_exception.ip = (void *)GetRegister(ARCH_PC);
    last_exception.access_address = last_exception.ip;
  } else if((WSTOPSIG(status) == SIGABRT) || (WSTOPSIG(status) == SIGFPE)) {

    last_exception.type = OTHER;
    last_exception.ip = (void *)GetRegister(ARCH_PC);
    last_exception.access_address = 0;
  } else  {
    WARN("Unhandled signal, status: %x", status);
    return DEBUGGER_CONTINUE;
  }

  // if we made it through to here, we have an exception we need to send up

  if((last_exception.type == ACCESS_VIOLATION) && 
     target_function_defined && 
     (last_exception.ip == (void*)PERSIST_END_EXCEPTION))
  {
  
    if (trace_debug_events) {
      SAY("Debugger: Persistence method ended\n");
    }

    HandleTargetEnded();
    return DEBUGGER_TARGET_END;
  } 

  if (OnException(&last_exception)) {
    return DEBUGGER_CONTINUE;
  }

  if(last_exception.type == BREAKPOINT) {
    return DEBUGGER_CONTINUE;
  } else {
    OnCrashed(&last_exception);
    return DEBUGGER_CRASHED;    
  }
}

DebuggerStatus Debugger::DebugLoop(uint32_t timeout) {
  // todo, which threads

  killed_by_watchdog = false;
  watchdog_timeout_time = GetCurTime() + timeout;

  if(current_pid) {
    ptrace(PTRACE_CONT, current_pid, 0, 0);
  }

  while(1) {

    int status;
    // printf("waiting...\n");
    if(timeout != 0xFFFFFFFF) watchdog_enabled = true;
    current_pid = waitpid(-1, &status, __WNOTHREAD);

    // printf("done, %d %d\n", current_pid, main_pid);
    //printf("RIP: %lx\n", GetRegister(RIP));
    if(current_pid <=0) {
      FATAL("waitpid error");
    }

    // printf("Status: %x\n", status);

    watchdog_mutex.lock();
    watchdog_enabled = false;
    if(killed_by_watchdog) {
      watchdog_mutex.unlock();
      return DEBUGGER_HANGED;
    }
    watchdog_mutex.unlock();

    if((threads.find(current_pid) == threads.end()) && (WIFSTOPPED(status))) {
      // must be a new thread
      SetThreadOptions(current_pid);
      ptrace_check(PTRACE_CONT, current_pid, 0, 0);
      threads.insert(current_pid);
      continue;
    }

    if(WIFSTOPPED(status) && ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))) {
      if (trace_debug_events) printf("Debugger: Thread %d exit\n", current_pid);
      threads.erase(current_pid);
      // not using ptrace_check as thread could not exist anymore
      ptrace(PTRACE_CONT, current_pid, 0, 0);
    } else if (WIFSTOPPED(status)) {
      DebuggerStatus debugger_status = DEBUGGER_CONTINUE;
      if(!killing_target) {
        debugger_status = HandleStopped(status);
      }
      if(debugger_status == DEBUGGER_CONTINUE) {
        ptrace_check(PTRACE_CONT, current_pid, 0, 0);
      } else {
        return debugger_status;
      }
    } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
      if(current_pid == main_pid) {
        is_target_alive = false;
        OnProcessExit();
        CleanupTarget();
        if(killed_by_watchdog) return DEBUGGER_HANGED;
        else return DEBUGGER_PROCESS_EXIT;
      }
    } else {
      FATAL("Unhandled status %x", status);
    }
  }
}

DebuggerStatus Debugger::Continue(uint32_t timeout) {
  if (loop_mode && (dbg_last_status == DEBUGGER_TARGET_END)) {
    dbg_last_status = DEBUGGER_TARGET_START;
    return dbg_last_status;
  }

  dbg_last_status = DebugLoop(timeout);
  return dbg_last_status;
}

DebuggerStatus Debugger::Run(char *cmd, uint32_t timeout) {
  FATAL("Deprecated Run interface - use Run(int argc, char **argv, uint32_t timeout) instead");
}

DebuggerStatus Debugger::Run(int argc, char **argv, uint32_t timeout) {
  killing_target = false;
  child_entrypoint_reached = false;
  attach_mode = false;

  pid_t child_pid = fork();
  if (child_pid == 0) {
    // if(setpgid(0, 0)) FATAL("setpgid error %d", errno);

    ptrace_check(PTRACE_TRACEME, 0, 0, 0);
    char **envp = GetEnvp();
    if(execve(argv[0], argv, envp) == -1) {
      FATAL("Error executing child, invalid executable path?");
    }
  } else if (child_pid < 0) {
    FATAL("Fork error");
  }

  int status;
  pid_t ret = waitpid(child_pid, &status, 0);
  if ((ret != child_pid) || !WIFSTOPPED(status) || (WSTOPSIG(status) != SIGTRAP)) {
    FATAL("Child process didn't start correctly");
  }

  SetThreadOptions(child_pid);

  threads.insert(child_pid);

  current_pid = child_pid;
  main_pid = child_pid;

  is_target_alive = true;

  OnProcessCreated();

  return Continue(timeout);
}

void Debugger::GetThreads(int pid) {
  char proctask[24];

  threads.clear();

  sprintf(proctask, "/proc/%d/task", pid);
  DIR *proc_dir = opendir(proctask);
  if(!proc_dir) {
    FATAL("Error opening %s, process doesn't exist?", proctask);
  }

  struct dirent *entry;
  while ((entry = readdir(proc_dir)) != NULL) {
    if(entry->d_name[0] == '.') continue;

    int tid = atoi(entry->d_name);

    if(tid) threads.insert(tid);
  }

  closedir(proc_dir);
}

DebuggerStatus Debugger::Attach(unsigned int pid, uint32_t timeout) {
  attach_mode = true;

  /*int ret = kill(pid, SIGSTOP);
  if(ret != 0) {
    FATAL("Error stopping process, errno: %d", errno);
  }*/

  GetThreads(pid);

  if(threads.empty()) FATAL("Error getting threads");

  if(threads.find(pid) == threads.end()) {
    // ret = kill(pid, SIGCONT);
    FATAL("Main thread in attached ptocess not found.");
  }

  for(auto iter = threads.begin(); iter != threads.end(); ++iter) {
    if (trace_debug_events) printf("Debugger: Attaching to pid: %d\n", *iter);
    int ptrace_ret = ptrace(PTRACE_ATTACH, *iter, 0, 0);
    if(ptrace_ret == -1) {
      if(errno == EPERM) FATAL("You don't have permissions to attach to the process. Try with sudo.");
      else if((errno == ESRCH) && (*iter != pid)) {
        // possibly thread died in the meantime
        threads.erase(*iter);
      } else FATAL("Error %d attaching to running process", errno);
    }
  }

  /*ret = kill(pid, SIGCONT);
  if(ret != 0) {
    FATAL("Error continuing process, errno: %d", errno);
  }*/

  for(auto iter = threads.begin(); iter != threads.end(); ++iter) {
    // printf("waiting for %d\n", *iter);
    int new_thread_status = 0;
    pid_t ret_pid = waitpid(*iter, &new_thread_status, __WALL);
    if(ret_pid != *iter) FATAL("Unexpected waitpid result waiting for new thread\n");
    // printf("status: %x\n", new_thread_status);
    if(!WIFSTOPPED(new_thread_status)) FATAL("Unexpected status from a new thread");
    threads.insert(*iter);
    SetThreadOptions(*iter);
  }

  // TODO new threads could have appeared in the meantime.
  // Now that all threads we know about are stopped we could check
  // if there are others we don't know about.

  current_pid = pid;
  main_pid = pid;
  is_target_alive = true;

  OnProcessCreated();
  OnEntrypoint();

  for(auto iter = threads.begin(); iter != threads.end(); ++iter) {
    // we'll continue the main thread in Continue() below
    if(*iter != current_pid) ptrace_check(PTRACE_CONT, *iter, 0, 0);
  }

  return Continue(timeout);
}

void Debugger::Watchdog() {
  while(1) {
    usleep(100000);

    watchdog_mutex.lock();
    if(watchdog_enabled && (GetCurTime() >= watchdog_timeout_time)) {
      int pid = main_pid;
      if(pid) {
        killed_by_watchdog = true;
        kill(pid, SIGSTOP);
      }
    }
    watchdog_mutex.unlock();
  }
}

void Debugger::CleanupTarget() {
  killing_target = false;
  attach_mode = false;
  is_target_alive = false;

  DeleteBreakpoints();
  threads.clear();
  loaded_modules.clear();

  ClearSharedMemory();

  if(proc_mem_fd) close(proc_mem_fd);

  main_pid = 0;
  current_pid = 0;
  main_binary_header = 0;
  rendezvous_address = 0;
  syscall_address = 0;
  debugger_allocated_memory = 0;
  child_entrypoint_reached = false;
  target_reached = false;

  main_binary_path.clear();
  main_binary_name.clear();

  dbg_last_status = DEBUGGER_NONE;
}

void Debugger::Init(int argc, char **argv) {
  watchdog_enabled = false;
  killed_by_watchdog = false;

  killing_target = false;
  attach_mode = false;
  is_target_alive = false;

  proc_mem_fd = 0;
  main_pid = 0;
  current_pid = 0;
  main_binary_header = 0;
  rendezvous_address = 0;
  syscall_address = 0;
  debugger_allocated_memory = 0;
  child_entrypoint_reached = false;
 
  loaded_modules.clear();
  breakpoints.clear();

  main_binary_path.clear();
  main_binary_name.clear();

  additional_env.clear();

  loop_mode = false;
  target_function_defined = false;
  target_reached = false;

  target_return_value = 0;

  target_module[0] = 0;
  target_method[0] = 0;
  target_offset = 0;
  saved_args = NULL;
  target_num_args = 0;
  target_address = NULL;

  dbg_last_status = DEBUGGER_NONE;
  
#ifdef ARM64
  target_end_detection = RETADDR_BREAKPOINT;
#else
  target_end_detection = RETADDR_STACK_OVERWRITE;
#endif

  std::list<char *> env_options;
  GetOptionAll("-target_env", argc, argv, &env_options);
  for (auto iter = env_options.begin(); iter != env_options.end(); iter++) {
    additional_env.push_back(*iter);
  }
  
  char *option;
  trace_debug_events = GetBinaryOption("-trace_debug_events",
                                       argc, argv,
                                       false);

  option = GetOption("-target_module", argc, argv);
  if (option) strncpy(target_module, option, PATH_MAX);

  option = GetOption("-target_method", argc, argv);
  if (option) strncpy(target_method, option, PATH_MAX);

  loop_mode = GetBinaryOption("-loop", argc, argv, loop_mode);

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

  linux32_warning = !GetBinaryOption("-patch_return_addresses", argc, argv, false);

  pthread_t thread_id;
  pthread_create(&thread_id, NULL, debugger_watchdog_thread, this);

  curr_shm_index = 0;
}
