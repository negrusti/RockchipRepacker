cmake_minimum_required(VERSION 3.16)
project(rkimg C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(rkimg src/rkimg.c)

if(MSVC)
  target_compile_options(rkimg PRIVATE /W4)
else()
  target_compile_options(rkimg PRIVATE -Wall -Wextra -Wpedantic)
endif()
