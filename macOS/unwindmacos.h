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
#include <unordered_map>

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

  std::vector<size_t> personality_vector;
  
  bool registered_fde;

  bool LookupPersonality(size_t ip, size_t *personality);

  struct PersonalityLookup {
    PersonalityLookup() {
      found = false;
      personality = (size_t)(-1);
      min_address = 0;
      max_address = 0;
    }
 
    void Init(bool found,
              size_t personality,
              size_t min_address,
              size_t max_address)
    {
      this->found = found;
      this->personality = personality;
      this->min_address = min_address;
      this->max_address = max_address;
    }

    bool found;
    size_t personality;
    size_t min_address;
    size_t max_address;
  };
  
  PersonalityLookup last_personality_lookup;

  std::map<size_t, compact_unwind_encoding_t> encoding_map;
  
  struct BreakpointData {
    SavedRegisters saved_registers;
    size_t continue_ip;
  };
  
  size_t register_breakpoint;
  BreakpointData register_breakpoint_data;

  size_t personality_breakpoint;

  struct ReturnAddressInfo {
    size_t original_return_address;
    size_t personality;
  };
  
  // Maps the return addresses in the instrumented code (the keys)
  // to the return addresses in the original code (the values).
  std::unordered_map<size_t, ReturnAddressInfo> return_addresses;
  
  class LookupTable {
  public:
    LookupTable() {
      header_local = NULL;
      header_remote = 0;
      buffer_cur = 0;
      buffer_end = 0;
    }
    
    ~LookupTable();

    size_t *header_local;
    size_t header_remote;
    size_t buffer_cur;
    size_t buffer_end;
  };
  
  LookupTable lookup_table;
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
  UnwindGeneratorMacOS(TinyInst& tinyinst) : UnwindGenerator(tinyinst),
                                             register_frame_addr(0),
                                             unwind_getip(0),
#ifdef ARM64
                                             unwind_cursor_setReg(0),
                                             unwind_cursor_setInfoBasedOnIPRegister(0) {}
#else
                                             unwind_setip(0) {}
#endif
  ~UnwindGeneratorMacOS() = default;
  
  void Init(int argc, char **argv) override;

  void OnModuleInstrumented(ModuleInfo* module) override;
  void OnModuleUninstrumented(ModuleInfo* module) override;

  size_t MaybeRedirectExecution(ModuleInfo* module, size_t IP) override;

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

  void ExtractPersonalityArray(ModuleInfo *module);

  size_t WriteCIE(ModuleInfo *module,
                  const char *augmentation,
                  size_t personality_addr);
  size_t WriteFDE(ModuleInfo *module,
                  size_t cie_address,
                  size_t min_address,
                  size_t max_address);
  
  size_t WriteCustomPersonality(ModuleInfo* module);
  void WritePersonalityLookup(ModuleInfo* module);

  size_t AllocateLookupTableChunk();
  void WriteLookupTable(ModuleInfo* module);
  
  size_t register_frame_addr;
  size_t unwind_getip;
#ifdef ARM64
  size_t unwind_cursor_setReg;
  size_t unwind_cursor_setInfoBasedOnIPRegister;
#else
  size_t unwind_setip;
#endif
  
  bool in_process_lookup;

#ifdef ARM64
  static constexpr unsigned char register_assembly_arm64[] = {
    // save registers
      0xff, 0xc3, 0x00, 0xd1, // sub sp, sp, #48
      0xe0, 0x4f, 0x02, 0xa9, // stp x0, x19, [sp, #32]
      0xf4, 0x57, 0x01, 0xa9, // stp x20, x21, [sp, #16]
      0xfd, 0x7b, 0x00, 0xa9, // stp fp, lr, [sp, #0]
      0xfd, 0x03, 0x00, 0x91, // mov fp, sp
      0xa0, 0x0f, 0x40, 0x92, // and x0, fp, #0xf
      0x40, 0x00, 0x00, 0xb4, // cbz x0, skip_alignment
      0xff, 0x23, 0x00, 0xd1, // sub sp, sp, #8
    // skip_alignment:
      0x93, 0x00, 0x00, 0x58, // ldr x19, #16; x19 becomes the current array pointer
      0xb4, 0x00, 0x00, 0x58, // ldr x20, #20; x20 becomes the end array pointer
      0xd5, 0x00, 0x00, 0x58, // ldr x21, #24; x21 becomes __register_frame address
      0x09, 0x00, 0x00, 0x14, // b #36; loop
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // array start addr goes here
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // array end addr goes here
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // __register_frame addr goes here
    // loop:
      0x7f, 0x02, 0x14, 0xeb, // cmp x19, x20
      0xaa, 0x00, 0x00, 0x54, // b.ge loop_end
      0x60, 0x02, 0x40, 0xf9, // ldr x0, [x19]
      0xa0, 0x02, 0x3f, 0xd6, // blr x21
      0x73, 0x22, 0x00, 0x91, // add x19, x19, #8
      0xfb, 0xff, 0xff, 0x17, // b loop
    // loop_end:
      0xbf, 0x03, 0x00, 0x91, // mov sp, fp
      0xfd, 0x7b, 0x40, 0xa9, // ldp fp, lr, [sp, #0]
      0xf4, 0x57, 0x41, 0xa9, // ldp x20, x21, [sp, #16]
      0xe0, 0x4f, 0x42, 0xa9, // ldp x0, x19, [sp, #32]
      0xff, 0xc3, 0x00, 0x91, // add sp, sp, #48
  };
  static const size_t register_assembly_arm64_data_offset = 48;
#else
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
#endif
};

#endif /* unwindmacos_h */
