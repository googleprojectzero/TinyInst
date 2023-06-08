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

#ifndef PROCMAPS_H
#define PROCMAPS_H

#include <inttypes.h>
#include <string>
#include <vector>
#include <sys/mman.h>

class MapsEntry {
public:
  uint64_t addr_from;
  uint64_t addr_to;
  uint32_t permissions;
  std::string name;

  bool IsReadable() { return (permissions & PROT_READ); }
  bool IsWritable() { return (permissions & PROT_WRITE); }
  bool IsExecutable() { return (permissions & PROT_EXEC); }
};

class MapsParser {
public:
  void Parse(int pid, std::vector<MapsEntry> &entries);

  void SplitLine(char *line, std::vector<std::string> &parts);
};

#endif /* PROCMAPS_H */