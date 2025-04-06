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

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <list>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
    #include <windows.h>
    #define ArgvEscape ArgvEscapeWindows
#else
    #include <limits.h>
    #ifndef MAX_PATH
        #define MAX_PATH PATH_MAX
    #endif

    #include <strings.h>
    #define _stricmp strcasecmp

    #define ArgvEscape ArgvEscapeMacOS
#endif

#define SAY(...)    printf(__VA_ARGS__)

#define WARN(...) do { \
    SAY("[!] WARNING: " __VA_ARGS__); \
    SAY("\n"); \
  } while (0)

#define FATAL(...) do { \
    SAY("[-] PROGRAM ABORT : " __VA_ARGS__); \
    SAY("         Location : %s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } while (0)

#define USAGE_CHECK(condition, message) if(!(condition)) FATAL("%s\n", message);

struct AddressRange {
  size_t from;
  size_t to;
  char *data;
};

// gets time in milliseconds
uint64_t GetCurTime(void);

char *GetOption(const char *name, int argc, char** argv);
void GetOptionAll(const char *name, int argc, char** argv, std::list<char *> *results);
bool GetBinaryOption(const char *name, int argc, char** argv, bool default_value);
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
    DWORD FindProcessId(char * process_name);
#endif
int GetIntOption(const char *name, int argc, char** argv, int default_value);

char *ArgvToCmd(int argc, char** argv);

#endif
