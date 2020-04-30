#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <direct.h>
#include "windows.h"

#include "common.h"
#include "liteinst.h"

uint8_t *trace_bits;

uint8_t sinkhole_stds = 0;
uint64_t mem_limit = 0;
uint64_t cpu_aff = 0;

int main(int argc, char **argv)
{
  LiteInst *instrumentation = new LiteInst();
  instrumentation->Init(argc, argv);

  int target_opt_ind = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      target_opt_ind = i + 1;
      break;
    }
  }

  if (!target_opt_ind) {
    printf("Usage: %s <options> -- <target command line>\n", argv[0]);
    return 0;
  }

  char *cmd = ArgvToCmd(argc - target_opt_ind, argv + target_opt_ind);

  int persist_iterations = 10;
  char *option = GetOption("-fuzz_iterations", argc, argv);
  if (option) persist_iterations = atoi(option);

  for (int i = 0; i < persist_iterations; i++) {
    int ret = instrumentation->Run(cmd, 0xFFFFFFFF);

    switch (ret) {
    case FAULT_NONE:
      printf("Iteration finished normally\n");
      break;
    case FAULT_CRASH:
      printf("Target crashed\n");
      break;
    case FAULT_TMOUT:
      printf("Target hanged\n");
      break;
    }
  }

  return 0;
}
