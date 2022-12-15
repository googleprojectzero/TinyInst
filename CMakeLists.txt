# Copyright 2020 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION "3.1")
set (CMAKE_CXX_STANDARD 17)

add_subdirectory(third_party)

project("tinyinst")

include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include)

set (arch_specific_files
    arch/x86/reg.h
    arch/x86/x86_helpers.h
    arch/x86/x86_helpers.cpp
    arch/x86/x86_assembler.h
    arch/x86/x86_assembler.cpp
    arch/x86/x86_litecov.cpp
)

set (cross_platform_files
     common.h
     common.cpp
     assembler.h
     instruction.h
     tinyinst.h
     tinyinst.cpp
     coverage.h
     coverage.cpp
     litecov.h
     litecov.cpp
     unwind.h
     hook.cpp
     hook.h
)

set (platform_specific_files
    Windows/debugger.h
    Windows/debugger.cpp
    Windows/winunwind.cpp
    Windows/winunwind.h
  )

add_library(tinyinst STATIC
  ${arch_specific_files}
  ${arch_specific_files}
  ${platform_specific_files}
  ${cross_platform_files}
)

target_include_directories(tinyinst PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include
)

add_dependencies(tinyinst xed)
target_link_libraries(tinyinst
  ${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/lib/xed.lib
  Dbghelp.lib)

project("litecov")

add_executable(litecov
  tinyinst-coverage.cpp
)

target_link_libraries(litecov tinyinst)
