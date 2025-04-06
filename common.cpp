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

#include <stdio.h>
#include <inttypes.h>
#include <list>
#include <chrono>

#include "common.h"
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
  #include <tlhelp32.h>
#endif
#include <iostream>
#include <string>
#include <codecvt>
#include <locale> 

uint64_t GetCurTime(void) {
  auto duration =  std::chrono::system_clock::now().time_since_epoch();
  auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
  return millis;
}

bool BoolFromOptionValue(char *value) {
  if (_stricmp(value, "off") == 0) return false;
  if (_stricmp(value, "false") == 0) return false;
  if (_stricmp(value, "0") == 0) return false;
  return true;
}

bool GetBinaryOption(const char *name, int argc, char** argv, bool default_value) {
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) break;
    if (strcmp(argv[i], name) == 0) {
      if ((i + 1) < argc && strcmp(argv[i + 1], "--")) {
        return BoolFromOptionValue(argv[i + 1]);
      }
      return true;
    }
    if (strncmp(argv[i], name, strlen(name)) == 0) {
      if (argv[i][strlen(name)] == '=') {
        return BoolFromOptionValue(argv[i] + strlen(name) + 1);
      }
    }
  }
  return default_value;
}

char *GetOption(const char *name, int argc, char** argv) {
  for (int i = 0; i < argc; i++) {
    if(strcmp(argv[i], "--") == 0) return NULL;
    if(strcmp(argv[i], name) == 0) {
      if ((i + 1) < argc && strcmp(argv[i + 1], "--")) {
        return argv[i + 1];
      } else {
        return NULL;
      }
    }
    if (strncmp(argv[i], name, strlen(name)) == 0) {
      if (argv[i][strlen(name)] == '=') {
        return argv[i] + strlen(name) + 1;
      }
    }
  }
  return NULL;
}


void GetOptionAll(const char *name, int argc, char** argv, std::list<char *> *results) {
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) return;
    if (strcmp(argv[i], name) == 0) {
      if ((i + 1) < argc && strcmp(argv[i + 1], "--")) {
        results->push_back(argv[i + 1]);
      } else {
        return;
      }
    }
    if (strncmp(argv[i], name, strlen(name)) == 0) {
      if (argv[i][strlen(name)] == '=') {
        results->push_back(argv[i] + strlen(name) + 1);
      }
    }
  }
}

int GetIntOption(const char *name, int argc, char** argv, int default_value) {
  char *option = GetOption(name, argc, argv);
  if (!option) return default_value;
  return (int)strtol(option, NULL, 0);
}

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
  DWORD FindProcessId(char * process_name)
  {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
      while (Process32Next(snapshot, &entry) == TRUE)
      {
        if (stricmp(entry.szExeFile, process_name) == 0)
        {  
          CloseHandle(snapshot);
          return entry.th32ProcessID;
        }
      }
    }
  }
#endif

//quoting on Windows is weird
size_t ArgvEscapeWindows(char *in, char *out) {
  int needs_quoting = 0;
  size_t size = 0;
  char *p = in;
  size_t i;

  //check if quoting is necessary
  if (strchr(in, ' ')) needs_quoting = 1;
  if (strchr(in, '\"')) needs_quoting = 1;
  if (strchr(in, '\t')) needs_quoting = 1;
  if (strchr(in, '\n')) needs_quoting = 1;
  if (strchr(in, '\v')) needs_quoting = 1;
  if (!needs_quoting) {
    size = strlen(in);
    if (out) memcpy(out, in, size);
    return size;
  }

  if (out) out[size] = '\"';
  size++;

  while (*p) {
    size_t num_backslashes = 0;
    while ((*p) && (*p == '\\')) {
      p++;
      num_backslashes++;
    }

    if (*p == 0) {
      for (i = 0; i < (num_backslashes * 2); i++) {
        if (out) out[size] = '\\';
        size++;
      }
      break;
    }
    else if (*p == '\"') {
      for (i = 0; i < (num_backslashes * 2 + 1); i++) {
        if (out) out[size] = '\\';
        size++;
      }
      if (out) out[size] = *p;
      size++;
    }
    else {
      for (i = 0; i < num_backslashes; i++) {
        if (out) out[size] = '\\';
        size++;
      }
      if (out) out[size] = *p;
      size++;
    }

    p++;
  }

  if (out) out[size] = '\"';
  size++;

  return size;
}

size_t ArgvEscapeMacOS(char *in, char *out) {
  size_t size = 0;
  char *p = in;
  while (*p) {
    if (strchr("|&:;()<>~*@?!$#[]{}\\ '\"`\t\n\v\r", *p)) {
      if (out) out[size] = '\\';
      size++;
    }

    if (out) out[size] = *p;
    size++;

    p++;
  }

  return size;
}


char *ArgvToCmd(int argc, char** argv) {
  size_t len = 0;
  int i;
  char* buf, *ret;

  for (i = 0; i < argc; i++)
    len += ArgvEscape(argv[i], NULL) + 1;

  if (!len) FATAL("Error creating command line");

  buf = ret = (char *)malloc(len);

  for (i = 0; i < argc; i++) {
    size_t l = ArgvEscape(argv[i], buf);
    buf += l;
    *(buf++) = ' ';
  }

  ret[len - 1] = 0;

  // printf("%s\n", ret);

  return ret;
}
