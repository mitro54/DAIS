cmake_minimum_required(VERSION 3.20)

project(DASH)
include_directories(include)
include(FetchContent)

# Settings (Standard C++23)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# Fetch pybind11
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG        v3.0.1
)
FetchContent_MakeAvailable(pybind11)

# Find python
find_package(Python 3.12 COMPONENTS Interpreter Development REQUIRED)

# THE INGREDIENTS (List every .cpp file you create here)
add_executable(DASH 
    src/main.cpp
    src/core/engine.cpp
    src/core/session.cpp
    # If you add a new file, just add a new line here
)

# Tells CMake where to find your header files (.hpp)
target_include_directories(DASH PRIVATE include)

# THE GARNISH (Libraries)

# This does two things:
# 1. Links the Python C library (libpython) so you can use the interpreter.
# 2. Sets up the include paths for Python headers.
target_link_libraries(DASH PRIVATE pybind11::embed)

# Linux-Specific Linking
# 'util' is required for openpty/forkpty on Linux. 
# 'pthread' is required for the std::thread we use in Engine.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(DASH PRIVATE util pthread)
endif()