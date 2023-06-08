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
#include <elf.h>

#include "common.h"
#include "elffile.h"

size_t fread_check(void *ptr, size_t size, size_t nmemb, FILE *stream) {
  size_t ret = fread(ptr, size, nmemb, stream);
  if(ret != nmemb) FATAL("fread error");
  return ret;
}

int fseek_check(FILE *stream, long offset, int whence) {
  int ret = fseek(stream, offset, whence);
  if(ret < 0) FATAL("fseek eroor");
  return ret;
}

ElfFile::Section::~Section() {
  if(data) free(data);
}

void ElfFile::Section::EnsureLoaded(FILE *fp) {
  if(data) return;

  data = (char *)malloc(size);
  fseek_check(fp, offset, SEEK_SET);
  fread_check(data, 1, size, fp);
}

ElfFile::~ElfFile() {
  CloseFile();
}

void ElfFile::OpenFile(const char *filename) {
  this->filename = filename;
  fp = fopen(filename, "rb");
  if(!fp) FATAL("Error opening %s", filename);

  // check the file and load class

  uint32_t magic;
  fread_check(&magic, sizeof(magic), 1, fp);
  if(magic != 0x464c457f) {
    FATAL("Elf header expected");
  }

  fread_check(&elf_class, sizeof(elf_class), 1, fp);

  fseek_check(fp, 0x10, SEEK_SET);
  fread_check(&elf_type, sizeof(elf_type), 1, fp);
}

void ElfFile::CloseFile() {
  if(fp) fclose(fp);
  fp = 0;
}

void ElfFile::EnsureSections() {
  if(sections_loaded) return;

  uint64_t e_shoff;
  uint16_t e_shentsize, e_shnum;

  if(elf_class == 1) {
    uint32_t e_shoff32;
    fseek_check(fp, 0x20, SEEK_SET);
    fread_check(&e_shoff32, sizeof(e_shoff32), 1, fp);
    e_shoff = e_shoff32;
    fseek_check(fp, 0x2E, SEEK_SET);
    fread_check(&e_shentsize, sizeof(e_shentsize), 1, fp);
    fread_check(&e_shnum, sizeof(e_shnum), 1, fp);
  } else {
    fseek_check(fp, 0x28, SEEK_SET);
    fread_check(&e_shoff, sizeof(e_shoff), 1, fp);
    fseek_check(fp, 0x3A, SEEK_SET);
    fread_check(&e_shentsize, sizeof(e_shentsize), 1, fp);
    fread_check(&e_shnum, sizeof(e_shnum), 1, fp);
  }

  char* sectionsbuf = (char *)malloc(e_shentsize * e_shnum);

  fseek_check(fp, e_shoff, SEEK_SET);
  fread_check(sectionsbuf, e_shentsize, e_shnum, fp);

  bool found = false;
  char *section = sectionsbuf;
  for(size_t i = 0; i < e_shnum; i++) {
    Section newsection;
    newsection.type = *(uint32_t *)(section + 0x04);
    if(elf_class == 1) {
      newsection.offset = *(uint32_t *)(section + 0x10);
      newsection.size = *(uint32_t *)(section + 0x14);
      newsection.link = *(uint32_t *)(section + 0x18);
      newsection.entsize = *(uint32_t *)(section + 0x24);
    } else {
      newsection.offset = *(uint64_t *)(section + 0x18);
      newsection.size = *(uint64_t *)(section + 0x20);
      newsection.link = *(uint32_t *)(section + 0x28);
      newsection.entsize = *(uint64_t *)(section + 0x38);
    }
    sections.push_back(newsection);
    section += e_shentsize;
  }

  free(sectionsbuf);

  sections_loaded = true;
}

ElfFile::Section *ElfFile::GetSectionByType(uint32_t type) {
  EnsureSections();

  for(size_t i = 0; i < sections.size(); i++) {
    Section *section = &sections[i];
    if(section->type == type) {
      section->EnsureLoaded(fp);
      return section;
    }
  }
  return NULL;
}

ElfFile::Section *ElfFile::GetSectionByIndex(size_t index) {
  EnsureSections();
  if(index >= sections.size()) FATAL("Requested invalid section index");
  Section *ret = &sections[index];
  ret->EnsureLoaded(fp);
  return ret;
}

uint64_t ElfFile::GetSymbolAddress(uint32_t section_type, const char *symbol_name) {
  Section *symbol_section, *string_section;
  symbol_section = GetSectionByType(section_type);
  if(!symbol_section) return 0;
  string_section = GetSectionByIndex(symbol_section->link);

  size_t nsymbols = symbol_section->size / symbol_section->entsize;

  for(int i = 0; i < nsymbols; i++) {
    uint64_t name_index, value;
    if(elf_class == 1) {
      Elf32_Sym *sym = (Elf32_Sym *)(symbol_section->data + i * symbol_section->entsize);
      name_index = sym->st_name;
      value = sym->st_value;
    } else {
      Elf64_Sym *sym = (Elf64_Sym *)(symbol_section->data + i * symbol_section->entsize);
      name_index = sym->st_name;
      value = sym->st_value;
    }
    char *name = string_section->data + name_index;
    // printf("Symbol: %s\n", name);
    if(strcmp(name, symbol_name) == 0) {
      return value;
    }
  }
  return 0;
}

uint64_t ElfFile::GetSymbolAddress(const char *symbol_name) {
  uint64_t ret = GetSymbolAddress(SHT_SYMTAB, symbol_name);
  if(ret) return ret;
  return GetSymbolAddress(SHT_DYNSYM, symbol_name);
}

int ElfFile::IsPIE() {
  if(elf_type == ET_DYN) return 1;
  return 0;
}
