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
set (CMAKE_CXX_STANDARD 11)

# Determine whether TinyInst should be build for arm64 or x86
if(APPLE AND NOT DEFINED ${ARCHITECTURE})
  EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)
endif()
add_subdirectory(third_party)

project("tinyinst")

include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include)

set (arch_specific_files
    arch/x86/x86_helpers.h
    arch/x86/x86_helpers.cpp
    arch/x86/x86_assembler.h
    arch/x86/x86_assembler.cpp
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
)

if (WIN32)
  set (platform_specific_files
       Windows/debugger.h
       Windows/debugger.cpp
  )
elseif (APPLE)
  if (${ARCHITECTURE} MATCHES arm64)
    add_definitions(-DARM64)
    set(CMAKE_REQUIRED_LINK_OPTIONS "-arch;arm64")
  endif()
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig_client.c
           ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig_server.c
           ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig_client.h
           ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig_server.h
    COMMAND mig -user ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig_client.c
                -server ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig_server.c
                -header ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig_client.h
                -sheader ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig_server.h
                ${CMAKE_CURRENT_SOURCE_DIR}/macOS/mig.defs
    COMMENT "Generating Mig files"
  )

  set (platform_specific_files
       macOS/debugger.h
       macOS/debugger.cpp
       macOS/machtarget.h
       macOS/machtarget.cpp
       macOS/mig_client.h
       macOS/mig_client.c
       macOS/mig_server.h
       macOS/mig_server.c
  )
endif()


if(${ARCHITECTURE} MATCHES arm64)
  add_library(tinyinst STATIC
    common.h
    common.cpp
    ${platform_specific_files}
  )
else()
  add_library(tinyinst STATIC
    ${arch_specific_files}
    ${cross_platform_files}
    ${platform_specific_files}
  )
  add_dependencies(tinyinst xed)
endif()
target_include_directories(tinyinst PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include
)
if (WIN32)  
  target_link_libraries(tinyinst
                        ${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/lib/xed.lib
                        Dbghelp.lib
  )
elseif (APPLE)
  if(${ARCHITECTURE} MATCHES arm64)
  else()
    target_link_libraries(tinyinst
                          ${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/lib/libxed.a
    )
  endif()
endif()

if(NOT (${ARCHITECTURE} MATCHES arm64))
project("litecov")

add_executable(litecov
  tinyinst-coverage.cpp
)

target_link_libraries(litecov tinyinst)
endif()
