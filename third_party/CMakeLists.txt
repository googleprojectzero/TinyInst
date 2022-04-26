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

if (${ARCHITECTURE} MATCHES arm64)
project("reil")
add_library(reil STATIC
    reil/reil/aarch64/decoder.cpp
    reil/reil/aarch64/printer.cpp
    reil/reil/aarch64/decoder.h
)
target_include_directories(reil PUBLIC
  reil/
)

else()
project("xed")

find_package (Python3 REQUIRED)

set(XED_INTERFACE_H ${CMAKE_CURRENT_BINARY_DIR}/obj/wkit/include/xed/xed-interface.h)

if (WIN32) 
  set(XED_LIB ${CMAKE_CURRENT_BINARY_DIR}/obj/wkit/lib/xed.lib)
elseif (APPLE)
  set(XED_LIB ${CMAKE_CURRENT_BINARY_DIR}/obj/wkit/lib/libxed.a)
endif()

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
  set(XED_HOST_CPU "--host-cpu=ia32")
else()
  set(XED_HOST_CPU "")
endif()

# Attempt to fix building XED on VS2022 and later
# Because having a custom build system is just awesome :-/
if(MSVC_VERSION AND (MSVC_VERSION GREATER 1929))
  get_filename_component(VS_BIN_PATH "${CMAKE_C_COMPILER}" DIRECTORY)
  set(VS_LIB_EXE "${VS_BIN_PATH}/lib.exe")
  set(XED_ADDITONAL_FLAGS --cc ${CMAKE_C_COMPILER} --cxx ${CMAKE_CXX_COMPILER} --linker ${CMAKE_LINKER} --ar ${VS_LIB_EXE})
else()
  set(XED_ADDITONAL_FLAGS "")
endif()

set (BUILD_XED_COMMAND
     ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/xed/mfile.py ${XED_HOST_CPU} ${XED_ADDITONAL_FLAGS}
)

if (WIN32)
  add_custom_command(
    OUTPUT ${XED_LIB} ${XED_INTERFACE_H}
    COMMAND ${BUILD_XED_COMMAND}
    COMMENT "Building Xed"
  )
elseif (APPLE)
  add_custom_command(
    OUTPUT ${XED_LIB} ${XED_INTERFACE_H}
    COMMAND ${BUILD_XED_COMMAND}
    COMMAND ranlib ${XED_LIB}
    COMMENT "Building Xed"
  )
endif()

add_custom_target(
  xed
  DEPENDS ${XED_LIB} ${XED_INTERFACE_H}
)
endif()
