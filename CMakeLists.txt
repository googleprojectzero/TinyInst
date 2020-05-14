cmake_minimum_required(VERSION "3.1")

add_subdirectory(intel_xed)

project("liteinst")

file(GLOB liteinst_src
    "*.h"
    "*.cpp"
)

include_directories(${CMAKE_CURRENT_BINARY_DIR}/intel_xed/obj/wkit/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/intel_xed/obj/wkit/lib)

add_executable("liteinst" ${liteinst_src})

add_dependencies(liteinst xed)

target_link_libraries(liteinst "xed.lib")
target_link_libraries(liteinst "Dbghelp.lib")
