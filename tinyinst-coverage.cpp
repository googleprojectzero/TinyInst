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

#include "common.h"
#include "litecov.h"

uint8_t *trace_bits;

LiteCov *instrumentation;
bool persist;
int num_iterations;
int cur_iteration;

// run a single iteration over the target process
// whether it's the whole process or target method
// and regardless if the target is persistent or not
// (should know what to do in pretty much all cases)
void RunTarget(int argc, char **argv, unsigned int pid, uint32_t timeout) {
  DebuggerStatus status;
  
  if (instrumentation->IsTargetFunctionDefined()) {
    if (cur_iteration == num_iterations) {
      instrumentation->Kill();
      cur_iteration = 0;
    }
  }

  // else clear only when the target function is reached
  if (!instrumentation->IsTargetFunctionDefined()) {
    instrumentation->ClearCoverage();
  }

  if (instrumentation->IsTargetAlive() && persist) {
    status = instrumentation->Continue(timeout);
  } else {
    instrumentation->Kill();
    cur_iteration = 0;
    if (argc) {
      status = instrumentation->Run(argc, argv, timeout);
    } else {
      status = instrumentation->Attach(pid, timeout);
    }
  }

  // if target function is defined,
  // we should wait until it is hit
  if (instrumentation->IsTargetFunctionDefined()) {
    if ((status != DEBUGGER_TARGET_START) && argc) {
      // try again with a clean process
      WARN("Target function not reached, retrying with a clean process\n");
      instrumentation->Kill();
      cur_iteration = 0;
      status = instrumentation->Run(argc, argv, timeout);
    }

    if (status != DEBUGGER_TARGET_START) {
      switch (status) {
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

    instrumentation->ClearCoverage();

    status = instrumentation->Continue(timeout);
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
    if (instrumentation->IsTargetFunctionDefined()) {
      printf("Process exit during target function\n");
    } else {
      printf("Process finished normally\n");
    }
    break;
  case DEBUGGER_TARGET_END:
    if (instrumentation->IsTargetFunctionDefined()) {
      printf("Target function returned normally\n");
      cur_iteration++;
    } else {
      FATAL("Unexpected status received from the debugger\n");
    }
    break;
  case DEBUGGER_NORMAL:
    printf("Process finished normally\n");
    break;
  default:
    FATAL("Unexpected status received from the debugger\n");
    break;
  }
}

int main(int argc, char **argv)
{
  instrumentation = new LiteCov();
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
  persist = GetBinaryOption("-persist", argc, argv, false);
  num_iterations = GetIntOption("-iterations", argc, argv, 1);
  char *outfile = GetOption("-coverage_file", argc, argv);

  if (!target_argc && !pid) {
    printf("Usage:\n"); 
    printf("%s <options> -- <target command line>\n", argv[0]);
    printf("Or:\n");
    printf("%s <options> -pid <pid to attach to>\n", argv[0]);
    return 0;
  }

  Coverage coverage, newcoverage;

  for (int i = 0; i < num_iterations; i++) {
    RunTarget(target_argc, target_argv, pid, 0xFFFFFFFF);

    Coverage newcoverage;

    instrumentation->GetCoverage(newcoverage, true);

    for (auto iter = newcoverage.begin(); iter != newcoverage.end(); iter++) {
      printf("Found %zd new offsets in %s\n", iter->offsets.size(), iter->module_name.c_str());
    }

    instrumentation->IgnoreCoverage(newcoverage);

    MergeCoverage(coverage, newcoverage);
  }
  
  if (outfile) WriteCoverage(coverage, outfile);

  instrumentation->Kill();

  return 0;
}
