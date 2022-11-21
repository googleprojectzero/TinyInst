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
#include <inttypes.h>
#include <stdbool.h>

#include "sslhook.h"


int main(int argc, char **argv)
{
  SSLInst *instrumentation = new SSLInst();
  instrumentation->Init(argc, argv);

  int target_opt_ind = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      target_opt_ind = i + 1;
      break;
    }
  }

  int target_argc = (target_opt_ind) ? argc - target_opt_ind : 0;
  char **target_argv = (target_opt_ind) ? argv + target_opt_ind : NULL;

  unsigned int pid = GetIntOption("-pid", argc, argv, 0);
  
  if (!target_argc && !pid) {
    printf("Usage:\n");
    printf("%s <options> -- <target command line>\n", argv[0]);
    printf("Or:\n");
    printf("%s <options> -pid <pid to attach to>\n", argv[0]);
    return 0;
  }
  
  DebuggerStatus status;
  if (target_argc) {
    status = instrumentation->Run(target_argc, target_argv, 0xFFFFFFFF);
  } else {
    status = instrumentation->Attach(pid, 0xFFFFFFFF);
  }

  switch (status) {
  case DEBUGGER_CRASHED:
    printf("Process crashed\n");
    instrumentation->Kill();
    break;
  case DEBUGGER_HANGED:
    printf("Process hanged\n");
    instrumentation->Kill();
    break;
  case DEBUGGER_PROCESS_EXIT:
    printf("Process exited normally\n");
    break;
  default:
    FATAL("Unexpected status received from the debugger\n");
    break;
  }

  return 0;
}
