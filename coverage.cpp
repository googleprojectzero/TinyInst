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

#include "windows.h"
#include "coverage.h"

ModuleCoverage::ModuleCoverage() {
  module_name[0] = 0;
}

ModuleCoverage::ModuleCoverage(char *name, std::set<uint64_t> offsets) {
  strcpy(module_name, name);
  this->offsets = offsets;
}

ModuleCoverage *GetModuleCoverage(Coverage &coverage, char *name) {
  for (auto iter = coverage.begin(); iter != coverage.end(); iter++) {
    if (_stricmp(iter->module_name, name) == 0) {
      return &(*iter);
    }
  }
  return NULL;
}

void MergeCoverage(Coverage &coverage, Coverage &toAdd) {
  for (auto iter = toAdd.begin(); iter != toAdd.end(); iter++) {
    ModuleCoverage *module_coverage = GetModuleCoverage(coverage, iter->module_name);
    if (module_coverage) {
      module_coverage->offsets.insert(
        iter->offsets.begin(),
        iter->offsets.end());
    } else {
      coverage.push_back({ iter->module_name, iter->offsets });
    }
  }
}

void WriteCoverage(Coverage& coverage, char *filename) {
  FILE *fp = fopen(filename, "w");
  if (!fp) {
    printf("Error opening %s\n", filename);
    return;
  }
  for (auto iter = coverage.begin(); iter != coverage.end(); iter++) {
    for (auto offsetiter = iter->offsets.begin(); offsetiter != iter->offsets.end(); offsetiter++) {
      fprintf(fp, "%s+0x%llx\n", iter->module_name, *offsetiter);
    }
  }
  fclose(fp);
}