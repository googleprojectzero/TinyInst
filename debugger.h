#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <list>

class Debugger {
public:

  virtual void Init(int argc, char **argv);
  int Run(char *cmd, uint32_t timeout);

protected:

  virtual void OnModuleLoaded(HMODULE module, char *module_name);
  virtual void OnModuleUnloaded(HMODULE module);
  virtual void OnPersistMethodReached(DWORD thread_id);
  virtual void OnProcessCreated(CREATE_PROCESS_DEBUG_INFO *info) {};
  virtual void OnEntrypoint();

  // should return true if the exception has been handled
  virtual bool OnException(EXCEPTION_RECORD *exception_record, DWORD thread_id) { return false; }

  void *GetModuleEntrypoint(void *base_address);
  void ReadStack(void *stack_addr, void **buffer, size_t numitems);
  void WriteStack(void *stack_addr, void **buffer, size_t numitems);
  DWORD GetProcOffset(char *data, char *name);
  DWORD GetImageSize(void *base_address);

private:
  struct Breakpoint {
    void *address;
    int type;
    unsigned char original_opcode;
    char module_name[MAX_PATH];
    void *module_base;
  };
  std::list<Breakpoint *> breakpoints;

  void KillProcess();
  void ResumeProcess();
  void StartProcess(char *cmd);
  void WaitProcessExit();
  int DebugLoop();
  int HandleDebuggerBreakpoint(void *address, DWORD thread_id);
  void OnPersistMethodEnded(DWORD thread_id);
  char *GetPersistenceOffset(HMODULE module);
  void AddBreakpoint(void *address, int type, char *module_name, void *module_base);
  DWORD GetLoadedModules(HMODULE **modules);
  void DeleteBreakpoints();

protected:

  HANDLE child_handle, child_thread_handle;

  bool child_entrypoint_reached;
  bool persist_target_reached;

  int32_t child_ptr_size = sizeof(void *);

private:

  HANDLE devnul_handle = INVALID_HANDLE_VALUE;

  DEBUG_EVENT dbg_debug_event;
  DWORD dbg_continue_status;
  bool dbg_continue_needed;
  uint64_t dbg_timeout_time;

  int wow64_target = 0;

  // persistence related
  int persist_num_args;
  int persist_iterations;
  uint64_t persist_offset;
  char persist_module[MAX_PATH];
  char persist_method[MAX_PATH];
  int calling_convention;
  void *persistence_address;
  void *saved_sp;
  void **saved_args;
  int persist_iterations_current;
};

#endif // DEBUGGER_H