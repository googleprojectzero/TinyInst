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

#include <string>
#include <set>
#include <list>

class ModuleCoverage {
public:
  ModuleCoverage();
  ModuleCoverage(std::string& name, std::set<uint64_t> offsets);

  std::string module_name;
  std::set<uint64_t> offsets;
};

typedef std::list<ModuleCoverage> Coverage;

ModuleCoverage *GetModuleCoverage(Coverage &coverage, std::string &name);

void PrintCoverage(Coverage& coverage);
void WriteCoverage(Coverage& coverage, const char *filename);

void MergeCoverage(Coverage &coverage, Coverage &toAdd);
void CoverageIntersection(Coverage &coverage1,
                       Coverage &coverage2,
                       Coverage &result);
// returns coverage2 not present in coverage1
void CoverageDifference(Coverage &coverage1,
                        Coverage &coverage2,
                        Coverage &result);
// returns coverage2 not present in coverage1 and vice versa
void CoverageSymmetricDifference(Coverage &coverage1,
                                Coverage &coverage2,
                                Coverage &result);
bool CoverageContains(Coverage &coverage1, Coverage &coverage2);

void ReadCoverageBinary(Coverage& coverage, char *filename);
void ReadCoverageBinary(Coverage& coverage, FILE *fp);
void WriteCoverageBinary(Coverage& coverage, char *filename);
void WriteCoverageBinary(Coverage& coverage, FILE *fp);

#endif // COVERAGE_H

