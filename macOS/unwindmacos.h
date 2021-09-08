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

#ifndef unwindmacos_h
#define unwindmacos_h

#include <vector>
#include <map>

#include <stdio.h>
#include "unwind.h"
#include "tinyinst.h"
#include <mach-o/compact_unwind_encoding.h>

#include <third_party/llvm/LEB128.h>

class UnwindDataMacOS: public UnwindData {
public:
  UnwindDataMacOS();
  ~UnwindDataMacOS();

  void *unwind_section_address;
  uint64_t unwind_section_size;
  void *unwind_section_buffer;
  unwind_info_section_header *unwind_section_header;

  std::vector<size_t> cie_addresses;

  void LookupOriginalMetadata(size_t original_address);
  void TranslateAndAddMetadata(size_t original_address,
                               size_t translated_address);

  struct Metadata {
    uint32_t personality_index;
    size_t min_address;
    size_t max_address;

    Metadata() {
      personality_index = (uint32_t)(-1);
      min_address = (size_t)(-1);
      max_address = 0;
    }

    Metadata(uint32_t personality_index,
               size_t min_address,
               size_t max_address) {
      this->personality_index = personality_index;
      this->min_address = min_address;
      this->max_address = max_address;
    }

    inline bool Valid() {
      return (personality_index != (uint32_t)(-1)
              && min_address != 0 && min_address != (size_t)(-1)
              && max_address != 0 && max_address != (size_t)(-1));
    }

    inline bool Miss(size_t address) {
      return (address < min_address || max_address <= address);
    }
  };

  Metadata last_original_metadata_lookup;
  std::vector<Metadata> translated_metadata_list;

  std::map<size_t, compact_unwind_encoding_t> encoding_map;
  
  struct BreakpointData {
    SavedRegisters saved_registers;
    size_t continue_ip;
  };
  std::unordered_map<size_t, BreakpointData> register_breakpoints;

  // Maps the addresses of the original personality routines (the keys)
  // to the addresses of our custom personality routines (the values). 
  std::unordered_map<size_t, size_t> translated_personalities;
  std::unordered_set<size_t> personality_breakpoints;

  // Maps the return addresses in the instrumented code (the keys)
  // to the return addresses in the original code (the values).
  std::map<size_t, size_t> return_addresses;
};

class ByteStream {
private:
  std::vector<uint8_t> byte_stream;

public:
  size_t size() {
    return byte_stream.size();
  }

  uint8_t *data() {
    return byte_stream.data();
  }

  template<typename T>
  void PutValue(T value) {
    for (int i = 0; i < sizeof(T); ++i) {
      byte_stream.push_back((value >> (i * 8)) & 0xff);
    }
  }

  template<typename T>
  void PutValueFront(T value) {
    PutValue(value);
    std::rotate(byte_stream.begin(), byte_stream.end() - sizeof(T), byte_stream.end());
  }

  void PutString(const char *s) {
    for (char *p = (char *)s; *p; p++) {
      byte_stream.push_back(*p);
    }
    byte_stream.push_back(0);
  }

  void PutULEB128Value(uint64_t value) {
    encodeULEB128(value, byte_stream);
  }

  void PutSLEB128Value(int64_t value) {
    encodeSLEB128(value, byte_stream);
  }
};

class UnwindGeneratorMacOS : public UnwindGenerator {
public:
  UnwindGeneratorMacOS(TinyInst& tinyinst) : UnwindGenerator(tinyinst), register_frame_addr(0) {}
  ~UnwindGeneratorMacOS() = default;

  void OnModuleInstrumented(ModuleInfo* module) override;
  void OnModuleUninstrumented(ModuleInfo* module) override;

  size_t MaybeRedirectExecution(ModuleInfo* module, size_t IP) override;

  void OnBasicBlockStart(ModuleInfo* module,
                         size_t original_address,
                         size_t translated_address) override;

  void OnInstruction(ModuleInfo* module,
                     size_t original_address,
                     size_t translated_address) override;

  void OnBasicBlockEnd(ModuleInfo* module,
                       size_t original_address,
                       size_t translated_address) override;
  
  void OnModuleLoaded(void *module, char *module_name) override;

  void OnReturnAddress(ModuleInfo *module,
                       size_t original_address,
                       size_t translated_address) override;
  
  bool HandleBreakpoint(ModuleInfo* module, void *address) override;

private:
  void SanityCheckUnwindHeader(ModuleInfo *module);
  void CheckUnwindBufferBounds(ModuleInfo *module, const char *array_description,
                               size_t start_address, size_t end_address);

  void ExtractFirstLevel(ModuleInfo *module);
  void ExtractEncodingsSecondLevel(ModuleInfo *module,
                                   unwind_info_section_header_index_entry *first_level_entry);
  void ExtractEncodingsCompressed(ModuleInfo *module,
                                  unwind_info_section_header_index_entry *first_level_entry,
                                  size_t second_level_page_addr);
  void ExtractEncodingsRegular(ModuleInfo *module,
                               unwind_info_section_header_index_entry *first_level_entry,
                               size_t second_level_page_addr);

  compact_unwind_encoding_t GetCompactEncoding(ModuleInfo *module,
                                               size_t second_level_page_addr,
                                               uint32_t curr_entry_encoding_index);

  size_t WriteCIE(ModuleInfo *module, const char *augmentation, size_t personality_addr);
  void WriteCIEs(ModuleInfo *module);
  size_t WriteFDE(ModuleInfo *module, UnwindDataMacOS::Metadata metadata);
  
  size_t GetCustomPersonality(ModuleInfo* module, size_t original_personality);
  
  size_t register_frame_addr;
  size_t unwind_getip;
  size_t unwind_setip;

  static constexpr unsigned char register_assembly_x86[] = {
    // save registers
    0x53, // push   rbx
    0x41, 0x54, // push   r12
    0x41, 0x55, // push   r13
    // save rbp, rsp
    0x55, // push rbp
    0x48, 0x89, 0xE5, // mov rbp, rsp
    // fix stack alignment
    0x48, 0xF7, 0xC4, 0x0F, 0x00, 0x00, 0x00, // test   rsp,0xf
    0x0F, 0x84, 0x02, 0x00, 0x00, 0x00, // je skip_alignment
    //0x0F, 0x85, 0x02, 0x00, 0x00, 0x00, // jne skip_alignment
    0x6A, 0x00, // push 0
    // load parameters
    0x48, 0x8B, 0x1D, 0x13, 0x00, 0x00, 0x00, // mov rbx, [rip + offset]; rbx becomes the current array pointer
    0x4C, 0x8B, 0x25, 0x14, 0x00, 0x00, 0x00, // mov r12, [rip + offset]; r12 becomes the end array pointer
    0x4C, 0x8B, 0x2D, 0x15, 0x00, 0x00, 0x00, // mov r13, [rip + offset]; r13 becomes __register_frame address
    0xE9, 0x18, 0x00, 0x00, 0x00, // jmp 0x18
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // array start addr goes here
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // array end addr goes here
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // __register_frame addr goes here
    // loop start
    0x4C, 0x39, 0xE3, // cmp rbx, r12
    0x0F, 0x83, 0x0F, 0x00, 0x00, 0x00, // JAE 0x0F (loop end)
    0x48, 0x8B, 0x3B, // mov rdi, [rbx]
    0x41, 0xFF, 0xD5, // call r13
    0x48, 0x83, 0xC3, 0x08, // add rbx, 8
    0xE9, 0xe8, 0xff, 0xff, 0xff, // jmp to loop start
    //restore rsp, rbp
    0x48, 0x89, 0xEC, // mov    rsp,rbp
    0x5D, // pop rbp
    // restore registers
    0x41, 0x5D, // pop    r13
    0x41, 0x5C, // pop    r12
    0x5B, // pop    rbx
  };

  static const size_t register_assembly_x86_data_offset = 50;
};

#endif /* unwindmacos_h */
