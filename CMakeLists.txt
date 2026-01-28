cmake_minimum_required(VERSION 3.20)

project(DAIS)
include_directories(include)
include(FetchContent)

# Settings (Standard C++20)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# =============================================================================
# Code Coverage Support (gcov/lcov)
# =============================================================================
# Enable with: cmake -DENABLE_COVERAGE=ON ..
# Then run tests and use lcov to generate report
option(ENABLE_COVERAGE "Enable code coverage instrumentation (gcov/lcov)" OFF)

if(ENABLE_COVERAGE)
    message(STATUS "Code coverage enabled")
    # GCC/Clang coverage flags
    # -fprofile-update=atomic: Fixes negative counts in multi-threaded code (thread-safety)
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage -fprofile-update=atomic)
    add_link_options(--coverage)
endif()

# Pass the absolute project path to C++ code.
# This ensures DAIS finds 'src/py_scripts' even if you run it via an alias or from another folder.
add_compile_definitions(DAIS_ROOT="${CMAKE_SOURCE_DIR}")

# Fetch pybind11
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG        v3.0.1
)
FetchContent_MakeAvailable(pybind11)

# Find python
# Relaxed version requirement slightly to ensure compatibility if you update Python later
find_package(Python 3.8 COMPONENTS Interpreter Development REQUIRED)

# =============================================================================
# Build Agents (Remote Execution Binaries)
# =============================================================================
# Run the shell script to compile agents and generate the header.
# We interpret it with 'bash' assuming it's available in PATH (WSL/Linux/Git Bash).
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/include/core/dais_agents.hpp
    COMMAND bash ${CMAKE_SOURCE_DIR}/src/remote/build_agents.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building remote agents and generating header..."
    VERBATIM
)

# Create a target so the executable can depend on it
add_custom_target(BuildAgents DEPENDS ${CMAKE_SOURCE_DIR}/include/core/dais_agents.hpp)

# THE INGREDIENTS (List every .cpp file you create here)
add_executable(DAIS 
    src/main.cpp
    src/core/engine.cpp
    src/core/session.cpp
    # If you add a new file, just add a new line here
)
add_dependencies(DAIS BuildAgents)


# Tells CMake where to find your header files (.hpp)
target_include_directories(DAIS PRIVATE include)

# THE GARNISH (Libraries)
target_link_libraries(DAIS PRIVATE pybind11::embed)

# Linux-Specific Linking
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(DAIS PRIVATE util pthread)
endif()

# Install the Main Executable
install(TARGETS DAIS DESTINATION bin)