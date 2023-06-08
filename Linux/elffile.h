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

#ifndef ELFFILE_H
#define ELFFILE_H


#include <inttypes.h>

#include <string>
#include <vector>

class ElfFile {
public:
  class Section {
  public:
    Section() {
      loaded = false;
      data = nullptr;
    }

    ~Section();

    void EnsureLoaded(FILE *fp);

    bool loaded;
    uint32_t type;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint64_t entsize;
    char *data;
  };

  ElfFile() {
    fp = 0;
    sections_loaded = false;
  }

  ~ElfFile();

  void OpenFile(const char *filename);

  void EnsureSections();

  Section *GetSectionByType(uint32_t type);
  Section *GetSectionByIndex(size_t index);

  uint64_t GetSymbolAddress(uint32_t section_type, const char *symbol_name);
  uint64_t GetSymbolAddress(const char *symbol_name);

  int IsPIE();

protected:
  void CloseFile();

  uint8_t elf_class;
  uint16_t elf_type;
  std::vector<Section> sections;
  bool sections_loaded;
  std::string filename;
  FILE *fp;
};

#endif /* ELFFILE_H */