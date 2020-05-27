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

#ifndef COVERAGE_H
#define COVERAGE_H

#include <set>
#include <list>

class ModuleCoverage {
public:
  ModuleCoverage();
  ModuleCoverage(char *name, std::set<uint64_t> offsets);

  char module_name[MAX_PATH];
  std::set<uint64_t> offsets;
};

typedef std::list<ModuleCoverage> Coverage;

ModuleCoverage *GetModuleCoverage(Coverage &coverage, char *name);
void MergeCoverage(Coverage &coverage, Coverage &toAdd);
void WriteCoverage(Coverage& coverage, char *filename);

#endif // COVERAGE_H