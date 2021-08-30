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
  have_data_to_register = false;
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
  for (uint32_t entry_cnt = 0; entry_cnt < unwind_section_header->indexCount; ++entry_cnt) {
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

void UnwindGeneratorMacOS::OnModuleLoaded(void *module, char *module_name) {
  if(strcmp(module_name, "libunwind.dylib")) return;
  
  register_frame_addr = (size_t)tinyinst_.GetSymbolAddress(module, (char*)"___register_frame");
  
  if(!register_frame_addr) {
    FATAL("Error locating __register_frame\n");
  }
}

bool UnwindGeneratorMacOS::HandleBreakpoint(ModuleInfo* module, void *address) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  auto it = unwind_data->register_breakpoints.find((size_t)address);
  
  if(it == unwind_data->register_breakpoints.end()) {
    return false;
  }

  // printf("registration completed\n");

  tinyinst_.RestoreRegisters(&it->second.saved_registers);
  
  tinyinst_.SetRegister(ARCH_PC, it->second.continue_ip);
  
  // one-time breakpoint
  unwind_data->register_breakpoints.erase(it);
  
  return true;
}

// the idea is that this produces a minimal valid FDE
// but since __register_frame doesn't return a value
// it's not possible to test if the registration actually succeeds
size_t UnwindGeneratorMacOS::WriteTestFde(ModuleInfo *module) {
  // need to write a CIE first
  // see CFI_Parser<A>::parseCIE
  unsigned char test_cie[] =
  {
    0x0d, 0x00, 0x00, 0x00, // CIE length
    0x00, 0x00, 0x00, 0x00, // CIE id, must be zero
    0x03, // version
    0x00, // empty augmentation string
    0x00, // code aligment factor, LEB128 encoded
    0x00, // data aligment factor, LEB128 encoded
    0x00 // return address register, LEB128 encoded
  };
  tinyinst_.WriteCode(module, test_cie, sizeof(test_cie));
  
  size_t fde_address = tinyinst_.GetCurrentInstrumentedAddress(module);
  
  // see CFI_Parser<A>::decodeFDE
  unsigned char test_fde[] = {
    0x18, 0x00, 0x00, 0x00, // FDE length
    0x11, 0x00, 0x00, 0x00, // offset to CIE from current location, this is sizeof(test_cie) + 4(current offset into fde)
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PC start, 0x1000 here
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PC range, 0 here
  };
  tinyinst_.WriteCode(module, test_cie, sizeof(test_cie));

  return fde_address;
}

size_t UnwindGeneratorMacOS::MaybeRedirectExecution(ModuleInfo* module, size_t IP) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  // TODO(aniculae): set unwind_data->have_data_to_register variable
  // if there are new FDEs that need to be registered
  // since the last call to MaybeRedirectExecution.
  // If we're emitting registration code every time, we'll very
  // quickly run out of allocated space for instrumented code
  if(!unwind_data->have_data_to_register) {
    return IP;
  }
  
  size_t code_size_before = module->instrumented_code_allocated;

  //TODO(aniculae): Write everything that needs to be written to the target process here
  std::vector<size_t> fde_addresses;
  size_t test_fde_address = WriteTestFde(module);
  fde_addresses.push_back(test_fde_address);
  
  size_t fde_array_start = tinyinst_.GetCurrentInstrumentedAddress(module);
  
  //TODO(aniculae): Write *addresses* of FDEs to-be-registered here
  for(auto it = fde_addresses.begin(); it != fde_addresses.end(); it++) {
    tinyinst_.WritePointer(module, *it);
  }

  size_t fde_array_end = tinyinst_.GetCurrentInstrumentedAddress(module);
 
  if(!register_frame_addr) {
    FATAL("Need to register frames, but the address of __register_frame() is still unknown\n");
  }
  
  // address from which the target will continue execution
  // now it's the same as fde_array_end, but that might change in the future
  // if other stuff gets written before the next line
  size_t continue_address = tinyinst_.GetCurrentInstrumentedAddress(module);
  
  // make sure we aren't clobbering the stack
  tinyinst_.assembler_->OffsetStack(module, -tinyinst_.sp_offset);

  size_t assembly_offset = module->instrumented_code_allocated;
  
  unsigned char register_assembly_x86[] =
  { 0x48, 0x8B, 0x1D, 0x13, 0x00, 0x00, 0x00, // mov rbx, [rip + offset]; rbx becomes the current array pointer
    0x4C, 0x8B, 0x25, 0x14, 0x00, 0x00, 0x00, // mov r12, [rip + offset]; r12 becomes the end array pointer
    0x4C, 0x8B, 0x2D, 0x15, 0x00, 0x00, 0x00, // mov r13, [rip + offset]; r13 becomes __register_frame address
    0xE9, 0x18, 0x00, 0x00, 0x00, // jmp 0x18
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // array start addr goes here
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // array end addr goes here
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // __register_frame addr goes here
    0x4C, 0x39, 0xE3, // cmp rbx, r12
    0x0F, 0x83, 0x0F, 0x00, 0x00, 0x00, // JAE 0x0F (loop end)
    0x48, 0x8B, 0x3B, // mov rdi, [rbx]
    0x41, 0xFF, 0xD5, // call r13
    0x48, 0x83, 0xC3, 0x08, // add rbx, 8
    0xE9, 0xe8, 0xff, 0xff, 0xff, // jmp to loop start
   };
  size_t register_assembly_x86_data_offset = 26;
  
  // write the assembly snippet that calls __register_frame
  tinyinst_.WriteCode(module, register_assembly_x86, sizeof(register_assembly_x86));
  
  // fill out the missing pieces in the assembly snippet
  tinyinst_.WritePointerAtOffset(module,
                                 fde_array_start,
                                 assembly_offset +
                                 register_assembly_x86_data_offset);
  tinyinst_.WritePointerAtOffset(module,
                                 fde_array_end,
                                 assembly_offset +
                                 register_assembly_x86_data_offset + 8);
  tinyinst_.WritePointerAtOffset(module,
                                 register_frame_addr,
                                 assembly_offset +
                                 register_assembly_x86_data_offset + 16);
  
  // restore stack
  tinyinst_.assembler_->OffsetStack(module, tinyinst_.sp_offset);

  // insert a breakpoint instruction
  size_t breakpoint_address = tinyinst_.GetCurrentInstrumentedAddress(module);
  tinyinst_.assembler_->Breakpoint(module);
  
  // save all registers and register a breakpoint
  // the breakpoint is handled by UnwindGeneratorMacOS::HandleBreakpoint
  SavedRegisters saved_registers;
  tinyinst_.SaveRegisters(&saved_registers);
  unwind_data->register_breakpoints[breakpoint_address] = {saved_registers, IP};
  
  // compute how much data we wrote and commit it all to the target process
  size_t code_size_after = module->instrumented_code_allocated;
  tinyinst_.CommitCode(module, code_size_before, (code_size_after - code_size_before));

  // we registered everything we have so far
  unwind_data->have_data_to_register = false;
  
  // give the target process the address to continue from
  return continue_address;
}
