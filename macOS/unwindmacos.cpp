/*
Copyright 2021 Google LLC

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

#include "unwindmacos.hpp"

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>

UnwindDataMacOS::UnwindDataMacOS() {
  addr = NULL;
  size = 0;
  buffer = NULL;
  header = NULL;
}

void UnwindDataMacOS::AddEncoding(compact_unwind_encoding_t encoding, size_t translated_address) {
  if (metadata_list.empty() || metadata_list.back().encoding != encoding) {
    metadata_list.push_back(Metadata(encoding, translated_address, translated_address));
  }
  else {
    metadata_list.back().max_address = translated_address;
  }
}

UnwindGeneratorMacOS::UnwindGeneratorMacOS(TinyInst& tinyinst) : UnwindGenerator(tinyinst) {

}


void UnwindGeneratorMacOS::OnModuleInstrumented(ModuleInfo* module) {
  size_t file_vm_slide = 0;
  section_64 unwind_section;
  tinyinst_.GetSectionAndSlide(module->module_header, "__TEXT", "__unwind_info", &unwind_section, &file_vm_slide);

  module->unwind_data = new UnwindDataMacOS();
  module->unwind_data->addr = (void*)(file_vm_slide + unwind_section.addr);
  module->unwind_data->size = unwind_section.size;

  module->unwind_data->buffer = (void*)malloc(unwind_section.size);
  tinyinst_.RemoteRead(module->unwind_data->addr,
                       module->unwind_data->buffer,
                       module->unwind_data->size);

  module->unwind_data->header = (struct unwind_info_section_header *)module->unwind_data->buffer;
}

void UnwindGeneratorMacOS::OnBasicBlockStart(ModuleInfo* module,
                                             size_t original_address,
                                             size_t translated_address) {
  FirstLevelLookup(module, original_address, translated_address);
}

void UnwindGeneratorMacOS::OnInstruction(ModuleInfo* module,
                                         size_t original_address,
                                         size_t translated_address) {
  FirstLevelLookup(module, original_address, translated_address);
}

void UnwindGeneratorMacOS::OnBasicBlockEnd(ModuleInfo* module,
                                           size_t original_address,
                                           size_t translated_address) {
  FirstLevelLookup(module, original_address, translated_address - 1);
}

void UnwindGeneratorMacOS::OnModuleUninstrumented(ModuleInfo *module) {
  free(module->unwind_data->buffer);
  delete module->unwind_data;
}

void UnwindGeneratorMacOS::FirstLevelLookup(ModuleInfo *module, size_t original_address, size_t translated_address) {
  size_t original_offset = original_address - (size_t)module->module_header;

  struct unwind_info_section_header_index_entry *first_level_entry = NULL;
  size_t first_level_entries_start = (size_t)module->unwind_data->buffer
                                      + module->unwind_data->header->indexSectionOffset;

  uint32_t low_index = 0;
  uint32_t high_index = module->unwind_data->header->indexCount;
  while (low_index < high_index) {
    uint32_t mid_index = low_index + (high_index - low_index) / 2;

    size_t curr_first_level_entry_addr = first_level_entries_start
                                         + mid_index * sizeof(struct unwind_info_section_header_index_entry);

    struct unwind_info_section_header_index_entry *curr_first_level_entry =
      (struct unwind_info_section_header_index_entry *)curr_first_level_entry_addr;

    if (curr_first_level_entry->functionOffset <= original_offset) {
      first_level_entry = curr_first_level_entry;
      low_index = mid_index + 1;
    } else {
      high_index = mid_index;
    }
  }

  if (first_level_entry->secondLevelPagesSectionOffset != 0) {
    SecondLevelLookup(module, original_address, translated_address, first_level_entry);
  }
}


void UnwindGeneratorMacOS::SecondLevelLookup(ModuleInfo *module,
                                            size_t original_address,
                                            size_t translated_address,
                                            struct unwind_info_section_header_index_entry *first_level_entry) {
  if (first_level_entry->secondLevelPagesSectionOffset == 0) {
    return;
  }

  size_t second_level_page_addr = (size_t)module->unwind_data->buffer
                                  + first_level_entry->secondLevelPagesSectionOffset;

  if (*(uint32_t*)second_level_page_addr == UNWIND_SECOND_LEVEL_COMPRESSED) {
    SecondLevelLookupCompressed(module, original_address, translated_address, first_level_entry, second_level_page_addr);
  } else if (*(uint32_t*)second_level_page_addr == UNWIND_SECOND_LEVEL_REGULAR) {
    SecondLevelLookupRegular(module, original_address, translated_address, first_level_entry, second_level_page_addr);
  }
}


void UnwindGeneratorMacOS::SecondLevelLookupCompressed(ModuleInfo *module,
                                                       size_t original_address,
                                                       size_t translated_address,
                                                       struct unwind_info_section_header_index_entry *first_level_entry,
                                                       size_t second_level_page_addr) {
  struct unwind_info_compressed_second_level_page_header *second_level_header =
    (struct unwind_info_compressed_second_level_page_header *)second_level_page_addr;

  uint32_t second_level_entry = 0;
  size_t second_level_entries_start = second_level_page_addr + second_level_header->entryPageOffset;

  uint16_t low_index = 0;
  uint16_t high_index = second_level_header->entryCount;
  while (low_index < high_index) {
    uint16_t mid_index = low_index + (high_index - low_index) / 2;
    size_t curr_second_level_entry_addr = second_level_entries_start + mid_index * sizeof(uint32_t);

    uint32_t curr_entry = *(uint32_t*)curr_second_level_entry_addr;
    uint32_t curr_entry_encoding_index = UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX(curr_entry);
    uint32_t curr_entry_func_offset = UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(curr_entry);

    if ((size_t)module->module_header + first_level_entry->functionOffset + curr_entry_func_offset <= original_address) {
      second_level_entry = curr_entry;
      low_index = mid_index + 1;
    } else {
      high_index = mid_index;
    }
  }

  compact_unwind_encoding_t encoding;
  uint32_t entry_encoding_index = UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX(second_level_entry);
  uint32_t entry_func_offset = UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(second_level_entry);
  if (entry_encoding_index < module->unwind_data->header->commonEncodingsArrayCount) {
    encoding = *(compact_unwind_encoding_t*)((size_t)module->unwind_data->buffer
                                             + module->unwind_data->header->commonEncodingsArraySectionOffset
                                             + entry_encoding_index * sizeof(compact_unwind_encoding_t));
  } else {
    encoding = *(compact_unwind_encoding_t*)((size_t)module->unwind_data->buffer
                                             + second_level_header->encodingsPageOffset
                                             + (entry_encoding_index - module->unwind_data->header->commonEncodingsArrayCount) * sizeof(compact_unwind_encoding_t));
  }

  module->unwind_data->AddEncoding(encoding, translated_address);
}

void UnwindGeneratorMacOS::SecondLevelLookupRegular(ModuleInfo *module,
                                                    size_t original_address,
                                                    size_t translated_address,
                                                    struct unwind_info_section_header_index_entry *first_level_entry,
                                                    size_t second_level_page_addr) {
  struct unwind_info_regular_second_level_page_header *second_level_header =
    (struct unwind_info_regular_second_level_page_header *)second_level_page_addr;

  struct unwind_info_regular_second_level_entry *second_level_entry = 0;
  size_t second_level_entries_start = second_level_page_addr + second_level_header->entryPageOffset;

  uint16_t low_index = 0;
  uint16_t high_index = second_level_header->entryCount;
  while (low_index < high_index) {
    uint16_t mid_index = low_index + (high_index - low_index) / 2;
    size_t curr_second_level_entry_addr = second_level_entries_start
                                          + mid_index * sizeof(struct unwind_info_regular_second_level_entry);

    struct unwind_info_regular_second_level_entry *curr_entry =
      (struct unwind_info_regular_second_level_entry *)curr_second_level_entry_addr;

    if ((size_t)module->module_header + curr_entry->functionOffset <= original_address) {
      second_level_entry = curr_entry;
      low_index = mid_index + 1;
    } else {
      high_index = mid_index;
    }
  }

  module->unwind_data->AddEncoding(second_level_entry->encoding, translated_address);
}
