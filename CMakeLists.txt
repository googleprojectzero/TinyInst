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

add_subdirectory(third_party)


project("tinyinst")

include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/lib)

add_library(tinyinst STATIC
  common.h
  common.cpp
  Windows/debugger.h
  Windows/debugger.cpp
  tinyinst.h
  tinyinst.cpp
  coverage.h
  coverage.cpp
  litecov.h
  litecov.cpp
  )

add_dependencies(tinyinst xed)

target_link_libraries(tinyinst "xed.lib")
target_link_libraries(tinyinst "Dbghelp.lib")


project("litecov")

add_executable(litecov
  tinyinst-coverage.cpp
  )

target_link_libraries(litecov tinyinst)


