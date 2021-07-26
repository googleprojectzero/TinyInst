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

class UnwindDataMacOS: public UnwindData {
public:
  UnwindDataMacOS();
  ~UnwindDataMacOS();

  void *unwind_section_address;
  uint64_t unwind_section_size;
  void *unwind_section_buffer;
  unwind_info_section_header *unwind_section_header;

  void AddEncoding(size_t original_address,
                   size_t translated_address);

  struct Metadata {
    compact_unwind_encoding_t encoding;
    size_t translated_min_address;
    size_t translated_max_address;

    Metadata();

    Metadata(compact_unwind_encoding_t encoding,
             size_t translated_min_address,
             size_t translated_max_address)
    : encoding(encoding),
      translated_min_address(translated_min_address),
      translated_max_address(translated_max_address)
    {}
  };

  std::vector<Metadata> metadata_list;
  std::map<size_t, compact_unwind_encoding_t> encoding_map;

  struct LastEncodingLookup {
    compact_unwind_encoding_t encoding;
    size_t original_min_address;
    size_t original_max_address;

    LastEncodingLookup() {
      encoding = 0;
      original_min_address = (size_t)(-1);
      original_max_address = 0;
    }

    LastEncodingLookup(compact_unwind_encoding_t encoding,
                       size_t original_min_address,
                       size_t original_max_address)
    : encoding(encoding),
      original_min_address(original_min_address),
      original_max_address(original_max_address)
    {}

    inline bool IsValid() {
      return encoding != 0
             && original_min_address != 0 && original_min_address != (size_t)(-1)
             && original_max_address != 0 && original_max_address != (size_t)(-1);
    }
  };

  LastEncodingLookup last_encoding_lookup;
};

class UnwindGeneratorMacOS : public UnwindGenerator {
public:
  UnwindGeneratorMacOS(TinyInst& tinyinst) : UnwindGenerator(tinyinst), register_frame_addr(0) {}
  ~UnwindGeneratorMacOS() = default;

  void OnModuleInstrumented(ModuleInfo* module) override;
  void OnModuleUninstrumented(ModuleInfo* module) override;

  // To be implemented in an upcoming stage of Stack Unwinding on macOS
//  size_t MaybeRedirectExecution(ModuleInfo* module, size_t IP) {
//    return IP;
//  }
//
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
  
  bool HandleBreakpoint(void *address) override;

private:
  void PopulateEncodingMapFirstLevel(ModuleInfo *module);
  void PopulateEncodingMapSecondLevel(ModuleInfo *module,
                                      unwind_info_section_header_index_entry *first_level_entry);
  void PopulateEncodingMapCompressed(ModuleInfo *module,
                                     unwind_info_section_header_index_entry *first_level_entry,
                                     size_t second_level_page_addr);
  void PopulateEncodingMapRegular(ModuleInfo *module,
                                  unwind_info_section_header_index_entry *first_level_entry,
                                  size_t second_level_page_addr);
  
  size_t register_frame_addr;
};

#endif /* unwindmacos_h */
