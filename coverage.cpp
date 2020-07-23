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
#include <algorithm>

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

void CoverageIntersection(Coverage &coverage1,
  Coverage &coverage2,
  Coverage &result)
{
  for (auto iter = coverage1.begin(); iter != coverage1.end(); iter++) {
    ModuleCoverage *module1 = &(*iter);
    ModuleCoverage *module2 = GetModuleCoverage(coverage2, iter->module_name);
    if (!module2) continue;
    std::set<uint64_t> offsets;
    for (auto offset1 = module1->offsets.begin();
      offset1 != module1->offsets.end(); offset1++)
    {
      if (module2->offsets.find(*offset1) != module2->offsets.end()) {
        offsets.insert(*offset1);
      }
    }
    if (!offsets.empty()) {
      result.push_back({ iter->module_name, offsets });
    }
  }
}

void CoverageSymmetricDifference(Coverage &coverage1,
  Coverage &coverage2,
  Coverage &result)
{
  for (auto iter = coverage1.begin(); iter != coverage1.end(); iter++) {
    ModuleCoverage *module1 = &(*iter);
    ModuleCoverage *module2 = GetModuleCoverage(coverage2, iter->module_name);
    if (!module2) {
      result.push_back({ iter->module_name, iter->offsets });
    } else {
      std::set<uint64_t> offsets;
      for (auto offset1 = module1->offsets.begin();
        offset1 != module1->offsets.end(); offset1++)
      {
        if (module2->offsets.find(*offset1) == module2->offsets.end()) {
          offsets.insert(*offset1);
        }
      }
      for (auto offset2 = module2->offsets.begin();
        offset2 != module2->offsets.end(); offset2++)
      {
        if (module1->offsets.find(*offset2) == module1->offsets.end()) {
          offsets.insert(*offset2);
        }
      }
      if (!offsets.empty()) {
        result.push_back({ iter->module_name, offsets });
      }
    }
  }
  // still need to add coverage for modules in coverage2
  // not present in coverage1
  for (auto iter = coverage2.begin(); iter != coverage2.end(); iter++) {
    ModuleCoverage *module2 = &(*iter);
    ModuleCoverage *module1 = GetModuleCoverage(coverage1, iter->module_name);
    if (!module1) {
      result.push_back({ iter->module_name, iter->offsets });
    }
  }
}

// returns coverage2 not present in coverage1
void CoverageDifference(Coverage &coverage1,
  Coverage &coverage2,
  Coverage &result)
{
  for (auto iter = coverage2.begin(); iter != coverage2.end(); iter++) {
    ModuleCoverage *module1 = GetModuleCoverage(coverage1, iter->module_name);
    ModuleCoverage *module2 = &(*iter);
    if (!module1) {
      result.push_back({ iter->module_name, iter->offsets });
    } else {
      std::set<uint64_t> offsets;
      for (auto offset2 = module2->offsets.begin();
        offset2 != module2->offsets.end(); offset2++)
      {
        if (module1->offsets.find(*offset2) == module1->offsets.end()) {
          offsets.insert(*offset2);
        }
      }
      if (!offsets.empty()) {
        result.push_back({ iter->module_name, offsets });
      }
    }
  }
}

bool CoverageContains(Coverage &coverage1, Coverage &coverage2) {
  for (auto iter = coverage2.begin(); iter != coverage2.end(); iter++) {
    ModuleCoverage *module2 = &(*iter);
    ModuleCoverage *module1 = GetModuleCoverage(coverage1, iter->module_name);
    if (!module1) {
      return false;
    }
    for (auto offset_iter = module2->offsets.begin();
         offset_iter != module2->offsets.end(); offset_iter++)
    {
      if (module1->offsets.find(*offset_iter) == module1->offsets.end()) {
        return false;
      }
    }
  }
  return true;
}


void WriteCoverage(Coverage& coverage, char *filename) {
  FILE *fp = fopen(filename, "w");
  if (!fp) {
    printf("Error opening %s\n", filename);
    return;
  }
  for (auto iter = coverage.begin(); iter != coverage.end(); iter++) {
    for (auto offsetiter = iter->offsets.begin();
         offsetiter != iter->offsets.end(); offsetiter++)
    {
      fprintf(fp, "%s+0x%llx\n", iter->module_name, *offsetiter);
    }
  }
  fclose(fp);
}

void WriteCoverageBinary(Coverage& coverage, FILE *fp) {
  uint64_t num_modules = coverage.size();
  fwrite(&num_modules, sizeof(num_modules), 1, fp);
  for (auto iter = coverage.begin(); iter != coverage.end(); iter++) {
    fwrite(iter->module_name, sizeof(iter->module_name), 1, fp);
    uint64_t num_offsets = iter->offsets.size();
    fwrite(&num_offsets, sizeof(num_offsets), 1, fp);
    uint64_t *offsets = (uint64_t *)malloc(num_offsets * sizeof(uint64_t));
    size_t i = 0;
    for (auto iter2 = iter->offsets.begin(); iter2 != iter->offsets.end(); iter2++) {
      offsets[i] = *iter2;
      i++;
    }
    fwrite(offsets, sizeof(uint64_t), num_offsets, fp);
    free(offsets);
  }
}

void WriteCoverageBinary(Coverage& coverage, char *filename) {
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    printf("Error opening %s\n", filename);
    return;
  }
  WriteCoverageBinary(coverage, fp);
  fclose(fp);
}

void ReadCoverageBinary(Coverage& coverage, FILE *fp) {
  uint64_t num_modules;
  fread(&num_modules, sizeof(num_modules), 1, fp);
  for (size_t m = 0; m < num_modules; m++) {
    ModuleCoverage module_coverage;
    fread(module_coverage.module_name, sizeof(module_coverage.module_name), 1, fp);
    uint64_t num_offsets;
    fread(&num_offsets, sizeof(num_offsets), 1, fp);
    uint64_t *offsets = (uint64_t *)malloc(num_offsets * sizeof(uint64_t));
    fread(offsets, sizeof(uint64_t), num_offsets, fp);
    for (size_t i = 0; i < num_offsets; i++) {
      module_coverage.offsets.insert(offsets[i]);
    }
    free(offsets);
    coverage.push_back(module_coverage);
  }
}

void ReadCoverageBinary(Coverage& coverage, char *filename) {
  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("Error opening %s\n", filename);
    return;
  }
  ReadCoverageBinary(coverage, fp);
  fclose(fp);
}

void PrintCoverage(Coverage& coverage) {
  for (auto iter = coverage.begin(); iter != coverage.end(); iter++) {
    printf("%s\n", iter->module_name);
    for (auto offsetiter = iter->offsets.begin();
      offsetiter != iter->offsets.end(); offsetiter++)
    {
      printf("0x%llx ", *offsetiter);
    }
    printf("\n");
  }
}



