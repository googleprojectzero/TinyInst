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

#include <stdio.h>
#include <string.h>

#include "procmaps.h"

void MapsParser::SplitLine(char *line, std::vector<std::string> &parts) {
  char *p = line;
  int numparts = 0;
  while(1) {
    if((*p == 0) || (*p == 0x0A) || (*p == 0x0D)) break;
    while((*p == 0x20) || (*p == 0x09)) p++;
    if((*p == 0) || (*p == 0x0A) || (*p == 0x0D)) break;
    char *start = p;
    if(numparts == 5) {
      // there can be spaces in path, treat them as normal characters
      while((*p != 0) && (*p != 0x0A) && (*p != 0x0D)) p++;
    } else {
      while((*p != 0x20) && (*p != 0x09) && (*p != 0) && (*p != 0x0A) && (*p != 0x0D)) p++;
    }
    char *end = p;
    std::string part(start, (end-start));
    parts.push_back(part);
    numparts++;
  }
}

void MapsParser::Parse(int pid, std::vector<MapsEntry> &entries) {
  char procfile[24];

  sprintf(procfile, "/proc/%d/maps", pid);
  FILE *fp = fopen(procfile, "r");
  if(!fp) return;

  char *line = NULL;
  size_t len = 0;
  while (getline(&line, &len, fp) != -1) {
    std::vector<std::string> parts;
    MapsEntry newentry;

    // printf("Line: %s", line);
    SplitLine(line, parts);
    if(parts.size() < 5) continue;

    //address range
    size_t addrrange_len = parts[0].length();
    char *addrrange = (char *)malloc(addrrange_len + 1);
    memcpy(addrrange, parts[0].data(), addrrange_len);
    addrrange[addrrange_len] = 0;
    char *dash = strchr(addrrange, '-');
    if(!dash) {
      free(addrrange);
      continue;
    }
    *dash = 0;
    newentry.addr_from = strtoul(addrrange, 0, 16);
    newentry.addr_to = strtoul(dash+1, 0, 16);
    free(addrrange);

    //permissions
    uint32_t permissions = 0;
    if(parts[1].length() < 3) continue;
    if(parts[1][0] == 'r') permissions += PROT_READ;
    if(parts[1][1] == 'w') permissions += PROT_WRITE;
    if(parts[1][2] == 'x') permissions += PROT_EXEC;
    newentry.permissions = permissions;

    // path
    if(parts.size() == 6) {
      newentry.name = parts[5];
    }

    entries.push_back(newentry);
  }

  if(line) free(line);
  fclose(fp);
}
