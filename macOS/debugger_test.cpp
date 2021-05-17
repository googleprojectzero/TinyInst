#include "macOS/debugger.h"

#include <iostream>
#include <memory>

int main(int argc, char **argv) {
  if(argc < 2) {
    std::cerr << "No target binary specified" << std::endl;
    return -1;
  }

  int target_opt_ind = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      target_opt_ind = i + 1;
      break;
    }
  }

  int target_argc = (target_opt_ind) ? argc - target_opt_ind : 0;
  char **target_argv = (target_opt_ind) ? argv + target_opt_ind : NULL;

  if (target_argc != 2) return -1;

  auto dbg = std::make_unique<Debugger>();

  dbg->Init(argc, argv);
  DebuggerStatus status;
  if(dbg->IsTargetAlive()) {
    return 0;
  }
  status = dbg->Run(target_argc, target_argv, 200);

  std::string test(target_argv[1]);

  if(test == "hello_world") {
    if (status == DEBUGGER_PROCESS_EXIT) return 0;
  }

  else if(test == "hang") {
    dbg->Kill();
    if (status == DEBUGGER_HANGED) return 0;
  }

  else if(test == "stack_corruption") {
    dbg->Kill();
    if (status == DEBUGGER_CRASHED) return 0;
  }

  else if(test == "invalid_addr_access") {
    dbg->Kill();
    if (status == DEBUGGER_CRASHED) return 0;
  }

  else if(test == "exit") {
    if (status == DEBUGGER_PROCESS_EXIT) return 0;
  }

  else if(test == "loop") {
    int i = 10;
    while(--i > 0 && (status == DEBUGGER_TARGET_START || status == DEBUGGER_TARGET_END)) {
      status = dbg->Continue(200);
    }
    printf("status=%d && i=%d\n", status, i);
    if (status == DEBUGGER_TARGET_END && i == 0) return 0;
  }

  return -1;
}