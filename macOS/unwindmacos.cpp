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
#include "common.h"

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>

#include <third_party/llvm/libunwind/dwarf2.h>
#include <third_party/llvm/libunwind/CompactUnwinder.hpp>

#define LOOKUP_TABLE_CHUNK_SIZE (1024*1024)
#define LOOKUP_TABLE_ELEMENT_SIZE (4 * sizeof(void *))
#define LOOKUP_TABLE_BUCKETS 16384 //needs to be a power of two
#ifdef ARM64
#define ARCH_IP_VALUE_REGISTER X22
#define ARCH_PERSONALITY_VALUE_REGISTER X1
#else
#define ARCH_IP_VALUE_REGISTER RAX
#define ARCH_PERSONALITY_VALUE_REGISTER RBX
#endif

constexpr unsigned char UnwindGeneratorMacOS::register_assembly_x86[];

void UnwindGeneratorMacOS::Init(int argc, char **argv) {
  in_process_lookup = true;
  
  in_process_lookup = GetBinaryOption("-unwind_in_process_lookup",
                                      argc, argv, in_process_lookup);
}

bool UnwindDataMacOS::LookupPersonality(size_t ip, size_t *personality) {
  if((ip >= last_personality_lookup.min_address) &&
     (ip < last_personality_lookup.max_address))
  {
    *personality = last_personality_lookup.personality;
    return last_personality_lookup.found;
  }

  auto it = encoding_map.upper_bound(ip);
  if (it == encoding_map.begin()) {
    last_personality_lookup.Init(false, -1, 0, it->first - 1);
  } else if (it == encoding_map.end()) { // Sentinel entry
    last_personality_lookup.Init(false, -1, prev(it)->first, -1);
  } else {
    compact_unwind_encoding_t encoding = prev(it)->second;
    // TODO(ifratric): If the encoding is a pointer to DWARF,
    // do we need to extract the personality from there
    // or is the personality index valid regardless?
    uint32_t personality_index = EXTRACT_BITS(encoding, UNWIND_PERSONALITY_MASK);
    if(personality_index >= personality_vector.size()) {
      FATAL("personality_index out of bounds");
    }
    last_personality_lookup.Init(true, personality_vector[personality_index],
                                 prev(it)->first, it->first - 1);
  }

  *personality = last_personality_lookup.personality;
  return last_personality_lookup.found;
}

UnwindDataMacOS::UnwindDataMacOS() {
  unwind_section_address = NULL;
  unwind_section_size = 0;
  unwind_section_buffer = NULL;
  unwind_section_header = NULL;
  registered_fde = false;
}

UnwindDataMacOS::~UnwindDataMacOS() {
  free(unwind_section_buffer);
  unwind_section_buffer = NULL;
}

void UnwindGeneratorMacOS::CheckUnwindBufferBounds(ModuleInfo *module, const char *array_description,
                                                   size_t start_address, size_t size) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  if (start_address < (size_t)unwind_data->unwind_section_buffer
      || (size_t)unwind_data->unwind_section_buffer + unwind_data->unwind_section_size < start_address + size) {
    FATAL("%s is located outside the Unwind Section buffer\n", array_description);
  }
}

void UnwindGeneratorMacOS::SanityCheckUnwindHeader(ModuleInfo *module) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;
  unwind_info_section_header *unwind_section_header = unwind_data->unwind_section_header;

  if (unwind_section_header->version != UNWIND_SECTION_VERSION) {
    FATAL("Unexpected version (%u) in Unwind Section Header", unwind_section_header->version);
  }

  size_t common_encodings_array_addr = (size_t)unwind_data->unwind_section_buffer
                                       + unwind_section_header->commonEncodingsArraySectionOffset;
  CheckUnwindBufferBounds(module, "Common encodings array", common_encodings_array_addr,
                          unwind_section_header->commonEncodingsArrayCount * sizeof(compact_unwind_encoding_t));

  size_t personality_array_addr = (size_t)unwind_data->unwind_section_buffer
                                  + unwind_section_header->personalityArraySectionOffset;
  CheckUnwindBufferBounds(module, "Personality array", personality_array_addr,
                          unwind_section_header->personalityArrayCount * sizeof(uint32_t));

  size_t first_level_array_addr = (size_t)unwind_data->unwind_section_buffer
                                  + unwind_section_header->indexSectionOffset;
  CheckUnwindBufferBounds(module, "First-level indexSection array", first_level_array_addr,
                          unwind_section_header->indexCount * sizeof(unwind_info_section_header_index_entry));
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
  } else {
    FATAL("Unable to find __unwind_info section in module %s (0x%lx)\n"
          "Aborting since there is no support for .eh_frame DWARF entries at the moment.\n",
          module->module_name.c_str(), (size_t)module->module_header);
  }

  module->unwind_data = unwind_data;
  SanityCheckUnwindHeader(module);

  ExtractPersonalityArray(module);
  ExtractFirstLevel(module);
}

void UnwindGeneratorMacOS::OnModuleUninstrumented(ModuleInfo *module) {
  delete module->unwind_data;
  module->unwind_data = NULL;
}

void UnwindGeneratorMacOS::OnReturnAddress(ModuleInfo *module,
                                           size_t original_address,
                                           size_t translated_address) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  size_t personality;
  bool lookup_success = unwind_data->LookupPersonality(original_address - 1,
                                                       &personality);
  // if we are in an area that has no unwinding information,
  // no need to store anything
  if(!lookup_success) return;
  
  unwind_data->return_addresses[translated_address] =
    {original_address, personality};
}

size_t UnwindGeneratorMacOS::WriteCIE(ModuleInfo *module,
                                      const char *augmentation,
                                      size_t personality_addr) {

  ByteStream cie;
  cie.PutValue<uint32_t>(0);                  // CIE id, must be zero
  cie.PutValue<uint8_t>(3);                   // version
  cie.PutString(augmentation);                // augmentation string
  cie.PutULEB128Value(1);                     // code alignment factor, ULEB128 encoded
  cie.PutSLEB128Value(1);                     // data alignment factor, SLEB128 encoded
  cie.PutULEB128Value(16);                    // return address register, ULEB128 encoded

  cie.PutULEB128Value(9);                     // augmentation length
  cie.PutValue<uint8_t>(0);                   // personality encoding
  cie.PutValue<uint64_t>(personality_addr);   // personality address

  cie.PutValueFront<uint32_t>(cie.size());    // CIE length

  size_t cie_address = tinyinst_.GetCurrentInstrumentedAddress(module);
  tinyinst_.WriteCode(module, cie.data(), cie.size());

  return cie_address;
}

void UnwindGeneratorMacOS::ExtractPersonalityArray(ModuleInfo *module) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;
  unwind_info_section_header *unwind_section_header = unwind_data->unwind_section_header;

  size_t curr_personality_entry_addr = (size_t)unwind_data->unwind_section_buffer
                                       + unwind_section_header->personalityArraySectionOffset;

  unwind_data->personality_vector.clear();
  unwind_data->personality_vector.push_back(0);
  for (int curr_cnt = 0; curr_cnt < unwind_section_header->personalityArrayCount; ++curr_cnt) {
    uint32_t personality_offset = *(uint32_t*)curr_personality_entry_addr;
    size_t personality_address;
    tinyinst_.RemoteRead((void*)((size_t)module->module_header + personality_offset),
                         &personality_address,
                         sizeof(size_t));
    unwind_data->personality_vector.push_back(personality_address);

    curr_personality_entry_addr += sizeof(uint32_t);
  }
}

void UnwindGeneratorMacOS::ExtractFirstLevel(ModuleInfo *module) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;
  unwind_info_section_header *unwind_section_header = unwind_data->unwind_section_header;

  size_t curr_first_level_entry_addr = (size_t)unwind_data->unwind_section_buffer
                                       + unwind_section_header->indexSectionOffset;

  // last entry is a sentinel entry
  // (secondLevelPagesSectionOffset == 0,
  //  functionOffset == maximum_mapped_address + 1)
  for (int entry_cnt = 0; entry_cnt < unwind_section_header->indexCount; ++entry_cnt) {
    unwind_info_section_header_index_entry *curr_first_level_entry =
      (unwind_info_section_header_index_entry *)curr_first_level_entry_addr;

    if (entry_cnt + 1 == unwind_section_header->indexCount) { // Sentinel entry
      unwind_data->encoding_map[(size_t)module->module_header
                                + curr_first_level_entry->functionOffset] = 0;
    } else {
      ExtractEncodingsSecondLevel(module, curr_first_level_entry);
    }

    curr_first_level_entry_addr += sizeof(unwind_info_section_header_index_entry);
  }
}

void UnwindGeneratorMacOS::ExtractEncodingsSecondLevel(ModuleInfo *module,
                                                       unwind_info_section_header_index_entry *first_level_entry) {
  if (first_level_entry->secondLevelPagesSectionOffset == 0) {
    return;
  }

  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  size_t second_level_page_addr = (size_t)unwind_data->unwind_section_buffer
                                  + first_level_entry->secondLevelPagesSectionOffset;
  CheckUnwindBufferBounds(module, "second_level_page_header.kind",
                          second_level_page_addr, sizeof(uint32_t));

  uint32_t unwind_second_level_type = *(uint32_t*)second_level_page_addr;
  if (unwind_second_level_type == UNWIND_SECOND_LEVEL_COMPRESSED) {
    ExtractEncodingsCompressed(module, first_level_entry, second_level_page_addr);
  } else if (unwind_second_level_type == UNWIND_SECOND_LEVEL_REGULAR) {
    ExtractEncodingsRegular(module, first_level_entry, second_level_page_addr);
  }
}


compact_unwind_encoding_t UnwindGeneratorMacOS::GetCompactEncoding(ModuleInfo *module,
                                                                   size_t second_level_page_addr,
                                                                   uint32_t curr_entry_encoding_index) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;
  unwind_info_section_header *unwind_section_header = unwind_data->unwind_section_header;
  unwind_info_compressed_second_level_page_header *second_level_header =
    (unwind_info_compressed_second_level_page_header *)second_level_page_addr;

  if (curr_entry_encoding_index < unwind_section_header->commonEncodingsArrayCount) {
    return *(compact_unwind_encoding_t*)
           ((size_t)unwind_data->unwind_section_buffer
            + unwind_section_header->commonEncodingsArraySectionOffset
            + curr_entry_encoding_index * sizeof(compact_unwind_encoding_t));
  } else if (curr_entry_encoding_index - unwind_section_header->commonEncodingsArrayCount
             < second_level_header->encodingsCount) {
    return *(compact_unwind_encoding_t*)
           (second_level_page_addr
            + second_level_header->encodingsPageOffset
            + (curr_entry_encoding_index - unwind_section_header->commonEncodingsArrayCount)
                * sizeof(compact_unwind_encoding_t));
  }

  FATAL("The compressed encoding index is invalid\n");
}

void UnwindGeneratorMacOS::ExtractEncodingsCompressed(ModuleInfo *module,
                                                      unwind_info_section_header_index_entry *first_level_entry,
                                                      size_t second_level_page_addr) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  CheckUnwindBufferBounds(module, "Compressed second_level_page_header", second_level_page_addr,
                          sizeof(unwind_info_compressed_second_level_page_header));

  unwind_info_compressed_second_level_page_header *second_level_header =
    (unwind_info_compressed_second_level_page_header *)second_level_page_addr;

  CheckUnwindBufferBounds(module, "Second-level local encodings array",
                          second_level_page_addr + second_level_header->encodingsPageOffset,
                          second_level_header->encodingsCount * sizeof(compact_unwind_encoding_t));

  size_t curr_second_level_entry_addr = second_level_page_addr + second_level_header->entryPageOffset;
  CheckUnwindBufferBounds(module, "Compressed second-level array", curr_second_level_entry_addr,
                          second_level_header->entryCount * sizeof(uint32_t));

  for (int curr_cnt = 0; curr_cnt < second_level_header->entryCount; ++curr_cnt) {
    uint32_t curr_second_level_entry = *(uint32_t*)curr_second_level_entry_addr;
    uint32_t curr_entry_encoding_index =
      UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX(curr_second_level_entry);
    uint32_t curr_entry_func_offset =
      UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(curr_second_level_entry);

    compact_unwind_encoding_t encoding = GetCompactEncoding(module,
                                                            second_level_page_addr,
                                                            curr_entry_encoding_index);

    unwind_data->encoding_map[(uint64_t)module->module_header
                              + first_level_entry->functionOffset
                              + curr_entry_func_offset] = encoding;

    curr_second_level_entry_addr += sizeof(uint32_t);
  }
}

void UnwindGeneratorMacOS::ExtractEncodingsRegular(ModuleInfo *module,
                                                   unwind_info_section_header_index_entry *first_level_entry,
                                                   size_t second_level_page_addr) {
  WARN("ExtractEncodingsRegular() function was never tested");
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  CheckUnwindBufferBounds(module, "Regular second_level_page_header", second_level_page_addr,
                          sizeof(unwind_info_regular_second_level_page_header));

  unwind_info_regular_second_level_page_header *second_level_header =
    (unwind_info_regular_second_level_page_header *)second_level_page_addr;

  size_t curr_second_level_entry_addr = second_level_page_addr + second_level_header->entryPageOffset;
  CheckUnwindBufferBounds(module, "Regular second-level array", curr_second_level_entry_addr,
                          second_level_header->entryCount * sizeof(unwind_info_regular_second_level_entry));

  for (int curr_cnt = 0; curr_cnt < second_level_header->entryCount; ++curr_cnt) {
    unwind_info_regular_second_level_entry *curr_second_level_entry =
      (unwind_info_regular_second_level_entry *)curr_second_level_entry_addr;

    unwind_data->encoding_map[(size_t)module->module_header
                              + curr_second_level_entry->functionOffset] = curr_second_level_entry->encoding;

    curr_second_level_entry_addr += sizeof(unwind_info_regular_second_level_entry);
  }
}

void UnwindGeneratorMacOS::OnModuleLoaded(void *module, char *module_name) {
  if(strcmp(module_name, "libunwind.dylib") == 0) {
    register_frame_addr = (size_t)tinyinst_.GetSymbolAddress(module, (char*)"___register_frame");
    if(!register_frame_addr) {
      FATAL("Error locating __register_frame\n");
    }

    unwind_getip = (size_t)tinyinst_.GetSymbolAddress(module, (char*)"__Unwind_GetIP");
    if(!unwind_getip) {
      FATAL("Error locating __Unwind_GetIP\n");
    }

    unwind_setip = (size_t)tinyinst_.GetSymbolAddress(module, (char*)"__Unwind_SetIP");
    if(!unwind_setip) {
      FATAL("Error locating __Unwind_SetIP\n");
    }
  }
}

bool UnwindGeneratorMacOS::HandleBreakpoint(ModuleInfo* module, void *address) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  if(in_process_lookup) {
    if((size_t)address == unwind_data->personality_breakpoint) {
      size_t ip = tinyinst_.GetRegister(ARCH_IP_VALUE_REGISTER);
      WARN("Unwinding lookup failed for IP %zx", ip);
      return true;
    }
  } else {
    if((size_t)address == unwind_data->personality_breakpoint) {
      size_t ip = tinyinst_.GetRegister(ARCH_IP_VALUE_REGISTER);

      auto it = unwind_data->return_addresses.find(ip);
      if (it != unwind_data->return_addresses.end()) {
        ip = it->second.original_return_address - 1;
        size_t personality = it->second.personality;
        tinyinst_.SetRegister(ARCH_IP_VALUE_REGISTER, ip);
        tinyinst_.SetRegister(ARCH_PERSONALITY_VALUE_REGISTER, personality);
        // printf("Set personality to %zx\n", personality);
      } else {
        WARN("Unwinding lookup failed for IP %zx", ip);
      }
      return true;
    }
  }
  
  if((size_t)address == unwind_data->register_breakpoint) {
    tinyinst_.RestoreRegisters(&unwind_data->register_breakpoint_data.saved_registers);
    tinyinst_.SetRegister(ARCH_PC, unwind_data->register_breakpoint_data.continue_ip);
    // printf("Registration done\n");
    return true;
  }
  
  return false;
}

size_t UnwindGeneratorMacOS::WriteFDE(ModuleInfo *module,
                                      size_t cie_address,
                                      size_t min_address,
                                      size_t max_address)
{
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;
  size_t fde_address = tinyinst_.GetCurrentInstrumentedAddress(module);

  ByteStream fde;
  fde.PutValue<uint32_t>(fde_address - cie_address + 4); // CIE pointer
  fde.PutValue<uint64_t>(min_address);                   // PC start
  fde.PutValue<uint64_t>(max_address - min_address);     // PC range
  fde.PutULEB128Value(0);                                // aug length

  fde.PutValueFront<uint32_t>(fde.size());               // length

  tinyinst_.WriteCode(module, fde.data(), fde.size());
  return fde_address;
}

size_t UnwindGeneratorMacOS::MaybeRedirectExecution(ModuleInfo* module, size_t IP) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;
  
  if(in_process_lookup) WriteLookupTable(module);
  
  if(unwind_data->registered_fde) {
    return IP;
  }

  if(!register_frame_addr || !unwind_getip || !unwind_setip) {
    FATAL("Need to register unwinding data, but the addresses of libunwind functions are still unknown\n");
  }
  
  size_t code_size_before = module->instrumented_code_allocated;

  size_t personality = WriteCustomPersonality(module);
  size_t cie_address = WriteCIE(module, "zP", personality);
  
  std::vector<size_t> fde_addresses;
  size_t fde_address = WriteFDE(module, cie_address,
                                (size_t)module->instrumented_code_remote,
                                (size_t)module->instrumented_code_remote +
                                module->instrumented_code_size);
  fde_addresses.push_back(fde_address);
  
  size_t fde_array_start = tinyinst_.GetCurrentInstrumentedAddress(module);
  for(auto it = fde_addresses.begin(); it != fde_addresses.end(); it++) {
    tinyinst_.WritePointer(module, *it);
  }
  size_t fde_array_end = tinyinst_.GetCurrentInstrumentedAddress(module);
 
  // address from which the target will continue execution
  // now it's the same as fde_array_end, but that might change in the future
  // if other stuff gets written before the next line
  size_t continue_address = tinyinst_.GetCurrentInstrumentedAddress(module);

  size_t assembly_offset = module->instrumented_code_allocated;
  
  // write the assembly snippet that calls __register_frame
  tinyinst_.WriteCode(module,
                      (void*)register_assembly_x86,
                      sizeof(register_assembly_x86));
  
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

  // insert a breakpoint instruction
  size_t breakpoint_address = tinyinst_.GetCurrentInstrumentedAddress(module);
  tinyinst_.assembler_->Breakpoint(module);
  
  // save all registers and register a breakpoint
  // the breakpoint is handled by UnwindGeneratorMacOS::HandleBreakpoint
  SavedRegisters saved_registers;
  tinyinst_.SaveRegisters(&saved_registers);
  unwind_data->register_breakpoint = breakpoint_address;
  unwind_data->register_breakpoint_data = {saved_registers, IP};
  
  // compute how much data we wrote and commit it all to the target process
  size_t code_size_after = module->instrumented_code_allocated;
  tinyinst_.CommitCode(module, code_size_before, (code_size_after - code_size_before));

  // we registered everything we have so far
  unwind_data->registered_fde = true;
  
  // give the target process the address to continue from
  return continue_address;
}

// The custom personality routines invoke the original routines, but before
// doing so, they modify the IP value to point to the original code (instead
// of the instrumented code). This way, the IP is found within the LSDA
// table and the stack unwinding process succeeds.
size_t UnwindGeneratorMacOS::WriteCustomPersonality(ModuleInfo* module) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;
  
  if(in_process_lookup && !unwind_data->lookup_table.header_remote) {
    FATAL("Unwind lookup table not initialized");
  }

  size_t new_personality_addr = tinyinst_.GetCurrentInstrumentedAddress(module);
  
  unsigned char assembly_part1[] = {
    // function prologue
    0x55, // push rbp
    0x48, 0x89, 0xE5, // mov rbp, rsp
    // save registers we're modifying
    0x53, // push rbx
    0x41, 0x54, // push r12
    0x41, 0x55, // push r13
    0x41, 0x56, // push r14
    0x41, 0x57, // push r15
    0x41, 0x57, // push r15, twice for alignment
    // push personality parameters on stack
    0x57, // push rdi
    0x56, // push rsi
    0x52, // push rdx
    0x51, // push rcx
    0x41, 0x50, // push r8
    0x41, 0x51,  // push r9
    // set up registers we'll need
    0x48, 0x31, 0xDB, // xor rbx, rbx
    0x4C, 0x8B, 0x3D, 0x13, 0x00, 0x00, 0x00, // mov r15, [rip + offset]; r15 becomes hashtable ptr
    0x4C, 0x8B, 0x25, 0x14, 0x00, 0x00, 0x00, // mov r12, [rip + offset]; r12 becomes _Unwind_GetIP
    0x4C, 0x8B, 0x2D, 0x15, 0x00, 0x00, 0x00, // mov r13, [rip + offset]; r13 becomes _Unwind_SetIP
    0xE9, 0x18, 0x00, 0x00, 0x00 // jmp 0x18
  };
  
  tinyinst_.WriteCode(module, assembly_part1, sizeof(assembly_part1));
  tinyinst_.WritePointer(module, unwind_data->lookup_table.header_remote);
  tinyinst_.WritePointer(module, unwind_getip);
  tinyinst_.WritePointer(module, unwind_setip);

  unsigned char assembly_part2[] = {
    // save the unwinding context in r14 for later
    0x4D, 0x89, 0xC6, // mov    r14,r8
    // _Unwind_GetIP(context)
    0x4C, 0x89, 0xC7, // mov    rdi,r8
    0x41, 0xFF, 0xD4  // call   r12
  };
  
  tinyinst_.WriteCode(module, assembly_part2, sizeof(assembly_part2));

  if(!in_process_lookup) {
    size_t breakpoint_address = tinyinst_.GetCurrentInstrumentedAddress(module);
    tinyinst_.assembler_->Breakpoint(module);
    unwind_data->personality_breakpoint = breakpoint_address;
  } else {
    WritePersonalityLookup(module);
  }

  unsigned char assembly_part3[] = {
    // _Unwind_SetIP(context, modified_ip)
    0x4C, 0x89, 0xF7, // mov    rdi,r14
    0x48, 0x89, 0xC6, // mov    rsi,rax
    0x41, 0xFF, 0xD5, // call   r13
    // restore original personality parameters
    0x41, 0x59, // pop r9
    0x41, 0x58, // pop r8
    0x59, // pop rcx
    0x5A, // pop rdx
    0x5E, // pop rsi
    0x5F, // pop rdi
    0x48, 0x85, 0xDB, // test   rbx,rbx
    0x0F, 0x84, 0x07, 0x00, 0x00, 0x00, // je no_original_personality
    // call original personality function
    0xFF, 0xD3, // call rbx
    0xE9, 0x07, 0x00, 0x00, 0x00, // jmp end
    // no_original_personality:
    0x48, 0xC7, 0xC0, 0x08, 0x00, 0x00, 0x00, // mov rax,8 (_URC_CONTINUE_UNWIND )
    // end:
    //restore registers
    0x41, 0x5F, // pop r15
    0x41, 0x5F, // pop r15
    0x41, 0x5E, // pop r14
    0x41, 0x5D, // pop r13
    0x41, 0x5C, // pop r12
    0x5B, // pop rbx
    //function epilogue
    0x48, 0x89, 0xEC, // mov    rsp,rbp
    0x5D, // pop rbp
    0xC3 // ret
  };

  tinyinst_.WriteCode(module, assembly_part3, sizeof(assembly_part3));

  return new_personality_addr;
}

void UnwindGeneratorMacOS::WritePersonalityLookup(ModuleInfo* module) {
  UnwindDataMacOS *unwind_data = (UnwindDataMacOS *)module->unwind_data;

  unsigned char x64_assembly[] = {
    0x48, 0x89, 0xC1, //mov rcx, rax
    0x48, 0x81, 0xE1, 0xAA, 0xAA, 0xAA, 0x0A, // and rcx,0xaaaaaaa, to be replaced
    0x4D, 0x8B, 0x3C, 0xCF, // mov r15,QWORD PTR [r15+rcx*8]
    // loop_start:
    0x4D, 0x85, 0xFF, // test r15,r15
    0x74, 0x15, //je not_found
    0x49, 0x3B, 0x07, // cmp rax,QWORD PTR [r15]
    0x74, 0x06, // je found
    0x4D, 0x8B, 0x7F, 0x18, // mov r15,QWORD PTR [r15+0x18]
    0xEB, 0xF0, // jmp loop_start
    // found:
    0x49, 0x8B, 0x47, 0x08, // mov rax, QWORD PTR [r15+0x8]
    0x49, 0x8B, 0x5F, 0x10, // mov rbx, QWORD PTR [r15+0x10]
    0xEB, 0x01, // jmp end
    // not_found:
    0xCC // int3
  };
  size_t mask_offset = 6;
  *(uint32_t *)(&x64_assembly[mask_offset]) = (LOOKUP_TABLE_BUCKETS - 1);
  
  tinyinst_.WriteCode(module, x64_assembly, sizeof(x64_assembly));
  size_t breakpoint_address = (size_t)tinyinst_.GetCurrentInstrumentedAddress(module) - 1;
  unwind_data->personality_breakpoint = breakpoint_address;
}

UnwindDataMacOS::LookupTable::~LookupTable() {
  if(header_local) free(header_local);
}

size_t UnwindGeneratorMacOS::AllocateLookupTableChunk() {
  size_t ret = (size_t)tinyinst_.RemoteAllocate(LOOKUP_TABLE_CHUNK_SIZE);
  if(!ret) {
    FATAL("Error allocating unwinding lookup table. Please run with -unwind_in_process_lookup=0");
  }
  return ret;
}

void UnwindGeneratorMacOS::WriteLookupTable(ModuleInfo* module) {
  UnwindDataMacOS *data = (UnwindDataMacOS *)module->unwind_data;
  UnwindDataMacOS::LookupTable *lookup_table = &data->lookup_table;

  if(!in_process_lookup) return;

  // init if needed
  if(!lookup_table->header_remote) {
    lookup_table->header_remote = AllocateLookupTableChunk();
    lookup_table->header_local = (size_t *)malloc(LOOKUP_TABLE_BUCKETS * sizeof(size_t));
    memset(lookup_table->header_local, 0, LOOKUP_TABLE_BUCKETS * sizeof(size_t));
    lookup_table->buffer_end = lookup_table->header_remote + LOOKUP_TABLE_CHUNK_SIZE;
    lookup_table->buffer_cur = lookup_table->header_remote + LOOKUP_TABLE_BUCKETS * sizeof(size_t);
  }

  // nothing to write
  if(data->return_addresses.empty()) return;
  
  size_t space_left = lookup_table->buffer_end - lookup_table->buffer_cur;
  if(space_left < LOOKUP_TABLE_ELEMENT_SIZE) {
    lookup_table->buffer_cur = AllocateLookupTableChunk();
    lookup_table->buffer_end = lookup_table->buffer_cur + LOOKUP_TABLE_CHUNK_SIZE;
    space_left = LOOKUP_TABLE_CHUNK_SIZE;
  }
  
  unsigned char *remote_buf = (unsigned char *)lookup_table->buffer_cur;
  unsigned char *local_buf = (unsigned char *)malloc(space_left);
  unsigned char *local_buf_cur = local_buf;
  
  for(auto iter = data->return_addresses.begin();
      iter != data->return_addresses.end(); iter++)
  {
    if(space_left < LOOKUP_TABLE_ELEMENT_SIZE) {
      tinyinst_.RemoteWrite((void *)remote_buf,
                            (void *)local_buf,
                            (size_t)(local_buf_cur - local_buf));
      lookup_table->buffer_cur = AllocateLookupTableChunk();
      lookup_table->buffer_end = lookup_table->buffer_cur + LOOKUP_TABLE_CHUNK_SIZE;
      space_left = LOOKUP_TABLE_CHUNK_SIZE;
      free(local_buf);
      remote_buf = (unsigned char *)lookup_table->buffer_cur;
      local_buf = (unsigned char *)malloc(space_left);
      local_buf_cur = local_buf;
    }
    
    size_t instrumented_ip = iter->first;
    size_t original_ip = iter->second.original_return_address - 1;
    size_t personality = iter->second.personality;
    size_t hash_bucket = instrumented_ip % LOOKUP_TABLE_BUCKETS;
    size_t previous_head = lookup_table->header_local[hash_bucket];
    
    size_t new_head = lookup_table->buffer_cur;
    lookup_table->header_local[hash_bucket] = new_head;
    
    // printf("%zx -> %zx\n", instrumented_ip, original_ip);
    
    *((size_t *)local_buf_cur) = instrumented_ip;
    *(((size_t *)local_buf_cur) + 1) = original_ip;
    *(((size_t *)local_buf_cur) + 2) = personality;
    *(((size_t *)local_buf_cur) + 3) = previous_head;
    local_buf_cur += LOOKUP_TABLE_ELEMENT_SIZE;
    lookup_table->buffer_cur += LOOKUP_TABLE_ELEMENT_SIZE;
    space_left -= LOOKUP_TABLE_ELEMENT_SIZE;
  }
  
  // header
  tinyinst_.RemoteWrite((void *)lookup_table->header_remote,
                        (void *)lookup_table->header_local,
                        LOOKUP_TABLE_BUCKETS * sizeof(size_t));
  
  tinyinst_.RemoteWrite((void *)remote_buf,
                        (void *)local_buf,
                        (size_t)(local_buf_cur - local_buf));
  
  // printf("Wrote %zd lookup table entries\n", data->return_addresses.size());
  data->return_addresses.clear();
  free(local_buf);
}
