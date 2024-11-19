cmake_minimum_required(VERSION 3.28)
project(dll_to_shellcode)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(dll_to_shellcode
  main.cpp
  main.hpp)

if(WIN32)
    target_compile_definitions(dll_to_shellcode PRIVATE WINDOWS)
endif()