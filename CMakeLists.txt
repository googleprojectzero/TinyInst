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

# Determine whether TinyInst should be build for arm64 or x86
if(APPLE AND NOT DEFINED ${ARCHITECTURE})
  EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)
endif()
add_subdirectory(third_party)

project("tinyinst")

include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/obj/wkit/include)

set (arch_specific_files
     x86_helpers.h
     x86_helpers.cpp
)

set (cross_platform_files
     common.h
     common.cpp
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
    project(tinyinst)
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
  # add_dependencies(tinyinst reil)
else()
  add_library(tinyinst STATIC
    ${arch_specific_files}
    ${cross_platform_files}
    ${platform_specific_files}
  )
  add_dependencies(tinyinst xed)
endif()
target_include_directories(tinyinst PUBLIC . )
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


project("litecov")

add_executable(litecov
  tinyinst-coverage.cpp
)

target_link_libraries(litecov tinyinst)

### Tests
add_executable(test_app ${CMAKE_CURRENT_SOURCE_DIR}/macOS/test_app.cpp)
add_executable(debugger_test ${CMAKE_CURRENT_SOURCE_DIR}/macOS/debugger_test.cpp)
target_link_libraries(debugger_test tinyinst)
target_include_directories(debugger_test PUBLIC . )

if(APPLE)
  if(NOT EXISTS "/usr/bin/codesign")
    message(FATAL_ERROR "/usr/bin/codesign not found")
  endif()
  add_custom_command(TARGET debugger_test POST_BUILD
      COMMAND /usr/bin/codesign -o runtime --force --sign - --entitlements ${CMAKE_CURRENT_SOURCE_DIR}/macOS/entitlements.xent ${CMAKE_CURRENT_BINARY_DIR}/debugger_test
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMENT "Adding entitlements..."
  )

  add_custom_command(TARGET test_app POST_BUILD
      COMMAND /usr/bin/codesign -o runtime --force --sign - --entitlements ${CMAKE_CURRENT_SOURCE_DIR}/macOS/entitlements.xent ${CMAKE_CURRENT_BINARY_DIR}/test_app
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMENT "Adding entitlements..."
  )
add_test(NAME DebuggerTestHelloWorld
  COMMAND sh -c "$<TARGET_FILE:debugger_test> -- $<TARGET_FILE:test_app> hello_world")
add_test(NAME DebuggerTestHang
  COMMAND sh -c "$<TARGET_FILE:debugger_test> -- $<TARGET_FILE:test_app> hang")
add_test(NAME DebuggerTestStackCorruption
  COMMAND sh -c "$<TARGET_FILE:debugger_test> -- $<TARGET_FILE:test_app> stack_corruption")
add_test(NAME DebuggerTestInvalidAddress
  COMMAND sh -c "$<TARGET_FILE:debugger_test> -- $<TARGET_FILE:test_app> invalid_addr_access")
add_test(NAME DebuggerTestExit
  COMMAND sh -c "$<TARGET_FILE:debugger_test> -- $<TARGET_FILE:test_app> exit")
add_test(NAME DebuggerTestLoop
  COMMAND sh -c "$<TARGET_FILE:debugger_test> -target_module=test_app -target_method=_main -nargs=2 -loop=1 -- $<TARGET_FILE:test_app> loop")
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)
enable_testing()
endif()