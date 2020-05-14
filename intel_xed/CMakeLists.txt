cmake_minimum_required(VERSION "3.1")

project("xed")

find_package (Python3 REQUIRED)

set(XED_INTERFACE_H ${CMAKE_CURRENT_BINARY_DIR}/obj/wkit/include/xed/xed-interface.h)
set(XED_LIB ${CMAKE_CURRENT_BINARY_DIR}/obj/wkit/lib/xed.lib)

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
  set(XED_HOST_CPU "--host-cpu=ia32")
else()
  set(XED_HOST_CPU "")
endif()

add_custom_command(
  OUTPUT ${XED_LIB} ${XED_INTERFACE_H}
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/xed/mfile.py ${XED_HOST_CPU}
  COMMENT "Building Xed"
)

add_custom_target(
  xed
  DEPENDS ${XED_LIB} ${XED_INTERFACE_H}
)
