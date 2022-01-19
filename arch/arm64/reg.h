/*
Copyright 2021 Google LLC

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

#ifndef ARCH_ARM64_REG_H
#define ARCH_ARM64_REG_H

#define ARCH_SP SP
#define ARCH_PC PC
#define ARCH_RETURN_VALUE_REGISTER X0
#define ORIG_ADDR_REG X0

enum Register {
  X0 = 0,
  X1,
  X2,
  X3,
  X4,
  X5,
  X6,
  X7,
  X8,
  X9,
  X10,
  X11,
  X12,
  X13,
  X14,
  X15,
  X16,
  X17,
  X18,
  X19,
  X20,
  X21,
  X22,
  X23,
  X24,
  X25,
  X26,
  X27,
  X28,
  X29,  // fp
  X30,  // lr
  X31,  // sp
  PC,
  CPSR,
  FP = X29,
  LR = X30,
  SP = X31,
  XZR = X31, // magic..
};

#endif  // ARCH_ARM64_REG_H
