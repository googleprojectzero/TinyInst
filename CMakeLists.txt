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


project("liteinst")

include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/lib)

add_library(liteinst STATIC
  common.h
  common.cpp
  debugger.h
  debugger.cpp
  liteinst.h
  liteinst.cpp
  coverage.h
  coverage.cpp
  litecov.h
  litecov.cpp
  )

add_dependencies(liteinst xed)

target_link_libraries(liteinst "xed.lib")
target_link_libraries(liteinst "Dbghelp.lib")


project("litecov")

add_executable(litecov
  liteinst-coverage.cpp
  )

target_link_libraries(litecov liteinst)


