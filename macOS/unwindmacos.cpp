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

#include "unwindmacos.h"

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>

UnwindDataMacOS::UnwindDataMacOS() {
  unwind_section_address = NULL;
  unwind_section_size = 0;
  unwind_section_buffer = NULL;
  unwind_section_header = NULL;
  last_encoding_lookup = LastEncodingLookup();
}

UnwindDataMacOS::~UnwindDataMacOS() {
  free(unwind_section_buffer);
  unwind_section_buffer = NULL;
}

void UnwindDataMacOS::AddEncoding(size_t original_address, size_t translated_address) {
  if (encoding_map.empty()) {
    return;
  }

  if (original_address < last_encoding_lookup.original_min_address
      || last_encoding_lookup.original_max_address <= original_address) {
    auto it = encoding_map.upper_bound(original_address);
    if (it == encoding_map.begin()) {
      last_encoding_lookup = LastEncodingLookup(0, 0, it->first - 1);
    } else if (it == encoding_map.end()) { // Sentinel entry
      last_encoding_lookup = LastEncodingLookup(0, prev(it)->first, -1);
    } else {
      last_encoding_lookup = LastEncodingLookup(prev(it)->second, prev(it)->first, it->first - 1);
    }
  }

  if (!last_encoding_lookup.IsValid()) {
    return;
  }

  if (metadata_list.empty() || metadata_list.back().encoding != last_encoding_lookup.encoding) {
    metadata_list.push_back(Metadata(last_encoding_lookup.encoding,
                                     translated_address, translated_address));
  } else {
    metadata_list.back().translated_max_address = translated_address;
  }
}

void UnwindGeneratorMacOS::OnModuleInstrumented(ModuleInfo* module) {
  UnwindDataMacOS *unwind_data = new UnwindDataMacOS();

  size_t file_vm_slide = 0;
  section_64 unwind_section;
  if (tinyinst_.GetSectionAndSlide(module->module_header, "__TEXT", "__unwind_info",
                                   &unwind_section, &file_vm_slide)) {
    unwind_data->unwind_section_address = (void*)(file_vm_slide + unwind_section.addr);
    unwind_data->unwind_section_size = unwind_section.size;

    unwind_data->unwind_section_buffer = (void*)malloc(unwind_section.size);
    tinyinst_.RemoteRead(unwind_data->unwind_section_address,
                         unwind_data->unwind_section_buffer,
                         unwind_data->unwind_section_size);

    unwind_data->unwind_section_header =
      (unwind_info_section_header *)unwind_data->unwind_section_buffer;

    if (unwind_data->unwind_section_header->version != UNWIND_SECTION_VERSION) {
      FATAL("Unexpected version (%u) in Unwind Section Header",
            unwind_data->unwind_section_header->version);
    }
  } else {
    FATAL("Unable to find __unwind_info section in module %s (0x%lx)\n"
          "Aborting since there is no support for .eh_frame DWARF entries at the moment.\n",
          module->module_name.c_str(), (size_t)module->module_header);
  }

  module->unwind_data = unwind_data;
  PopulateEncodingMapFirstLevel(module);
}

void UnwindGeneratorMacOS::OnBasicBlockStart(ModuleInfo* module,
                                             size_t original_address,
                                             size_t translated_address) {
  ((UnwindDataMacOS *)module->unwind_data)->AddEncoding(original_address, translated_address);
}

void UnwindGeneratorMacOS::OnInstruction(ModuleInfo* module,
                                         size_t original_address,
                                         size_t translated_address) {
  ((UnwindDataMacOS *)module->unwind_data)->AddEncoding(original_address, translated_address);
}

void UnwindGeneratorMacOS::OnBasicBlockEnd(ModuleInfo* module,
                                           size_t original_address,
                                           size_t translated_address) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;
  if (unwind_data->last_encoding_lookup.IsValid()) {
    unwind_data->metadata_list.back().translated_max_address = translated_address - 1;
  }
}

void UnwindGeneratorMacOS::OnModuleUninstrumented(ModuleInfo *module) {
  delete module->unwind_data;
  module->unwind_data = NULL;
}

void UnwindGeneratorMacOS::PopulateEncodingMapFirstLevel(ModuleInfo *module) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  unwind_info_section_header *unwind_section_header = unwind_data->unwind_section_header;

  if (unwind_section_header->indexSectionOffset
      + unwind_section_header->indexCount
        * sizeof(unwind_info_section_header_index_entry) > unwind_data->unwind_section_size) {
    FATAL("The first-level indexSection array is located outside the Unwind Section buffer\n");
  }
  size_t curr_first_level_entry_addr = (size_t)unwind_data->unwind_section_buffer
                                       + unwind_section_header->indexSectionOffset;

  // last entry is a sentinel entry
  // (secondLevelPagesSectionOffset == 0, functionOffset == maximum_mapped_address + 1)
  for (int entry_cnt = 0; entry_cnt < unwind_section_header->indexCount; ++entry_cnt) {
    unwind_info_section_header_index_entry *curr_first_level_entry =
      (unwind_info_section_header_index_entry *)curr_first_level_entry_addr;

    if (entry_cnt + 1 == unwind_section_header->indexCount) { // Sentinel entry
      unwind_data->encoding_map[(size_t)module->module_header
                                + curr_first_level_entry->functionOffset] = 0;
    } else {
      PopulateEncodingMapSecondLevel(module, curr_first_level_entry);
    }

    curr_first_level_entry_addr += sizeof(unwind_info_section_header_index_entry);
  }
}


void UnwindGeneratorMacOS::PopulateEncodingMapSecondLevel(ModuleInfo *module,
                                                          unwind_info_section_header_index_entry *first_level_entry) {
  if (first_level_entry->secondLevelPagesSectionOffset == 0) {
    return;
  }

  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  if (first_level_entry->secondLevelPagesSectionOffset
      + sizeof(uint32_t) > unwind_data->unwind_section_size) {
    FATAL("The second_level_page_header.kind field is located outside the Unwind Section buffer\n");
  }
  size_t second_level_page_addr = (size_t)unwind_data->unwind_section_buffer
                                  + first_level_entry->secondLevelPagesSectionOffset;

  uint32_t unwind_second_level_type = *(uint32_t*)second_level_page_addr;
  if (unwind_second_level_type == UNWIND_SECOND_LEVEL_COMPRESSED) {
    PopulateEncodingMapCompressed(module, first_level_entry, second_level_page_addr);
  } else if (unwind_second_level_type == UNWIND_SECOND_LEVEL_REGULAR) {
    PopulateEncodingMapRegular(module, first_level_entry, second_level_page_addr);
  }
}


void UnwindGeneratorMacOS::PopulateEncodingMapCompressed(ModuleInfo *module,
                                                         unwind_info_section_header_index_entry *first_level_entry,
                                                         size_t second_level_page_addr) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  if (first_level_entry->secondLevelPagesSectionOffset
      + sizeof(unwind_info_compressed_second_level_page_header) > unwind_data->unwind_section_size) {
    FATAL("The compressed second_level_page_header is located outside the Unwind Section buffer\n");
  }
  unwind_info_compressed_second_level_page_header *second_level_header =
    (unwind_info_compressed_second_level_page_header *)second_level_page_addr;

  if (first_level_entry->secondLevelPagesSectionOffset
      + second_level_header->entryPageOffset
      + second_level_header->entryCount * sizeof(uint32_t) > unwind_data->unwind_section_size) {
    FATAL("The compressed second-level array is located outside the Unwind Section buffer\n");
  }

  size_t curr_second_level_entry_addr = second_level_page_addr + second_level_header->entryPageOffset;
  for (int curr_cnt = 0; curr_cnt < second_level_header->entryCount; ++curr_cnt) {
    uint32_t curr_second_level_entry = *(uint32_t*)curr_second_level_entry_addr;
    uint32_t curr_entry_encoding_index =
      UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX(curr_second_level_entry);
    uint32_t curr_entry_func_offset =
      UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(curr_second_level_entry);

    compact_unwind_encoding_t encoding;
    unwind_info_section_header *unwind_section_header = unwind_data->unwind_section_header;
    if (curr_entry_encoding_index < unwind_section_header->commonEncodingsArrayCount) {
      encoding =
        *(compact_unwind_encoding_t*)((size_t)unwind_data->unwind_section_buffer
                                      + unwind_section_header->commonEncodingsArraySectionOffset
                                      + curr_entry_encoding_index * sizeof(compact_unwind_encoding_t));
    } else {
      encoding =
        *(compact_unwind_encoding_t*)((size_t)unwind_data->unwind_section_buffer
                                      + second_level_header->encodingsPageOffset
                                      + (curr_entry_encoding_index
                                         - unwind_section_header->commonEncodingsArrayCount)
                                        * sizeof(compact_unwind_encoding_t));
    }

    unwind_data->encoding_map[(uint64_t)module->module_header
                              + first_level_entry->functionOffset
                              + curr_entry_func_offset] = encoding;

    curr_second_level_entry_addr += sizeof(uint32_t);
  }
}

void UnwindGeneratorMacOS::PopulateEncodingMapRegular(ModuleInfo *module,
                                                      unwind_info_section_header_index_entry *first_level_entry,
                                                      size_t second_level_page_addr) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  if (first_level_entry->secondLevelPagesSectionOffset
      + sizeof(unwind_info_regular_second_level_page_header) > unwind_data->unwind_section_size) {
    FATAL("The regular second_level_page_header is located outside the Unwind Section buffer\n");
  }
  unwind_info_regular_second_level_page_header *second_level_header =
    (unwind_info_regular_second_level_page_header *)second_level_page_addr;

  if (first_level_entry->secondLevelPagesSectionOffset
      + second_level_header->entryPageOffset
      + second_level_header->entryCount
        * sizeof(unwind_info_regular_second_level_entry) > unwind_data->unwind_section_size) {
    FATAL("The regular second-level array is located outside the Unwind Section buffer\n");
  }

  size_t curr_second_level_entry_addr = second_level_page_addr + second_level_header->entryPageOffset;
  for (int curr_cnt = 0; curr_cnt < second_level_header->entryCount; ++curr_cnt) {
    unwind_info_regular_second_level_entry *curr_second_level_entry =
      (unwind_info_regular_second_level_entry *)curr_second_level_entry_addr;

    unwind_data->encoding_map[(uint64_t)module->module_header
                              + curr_second_level_entry->functionOffset] = curr_second_level_entry->encoding;

    curr_second_level_entry_addr += sizeof(unwind_info_regular_second_level_entry);
  }
}
