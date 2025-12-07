# Boilerplate (Just copy paste this always)
cmake_minimum_required(VERSION 3.20)

project(DASH)
include_directories(include)

# Settings (Standard C++23)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# THE INGREDIENTS (List every .cpp file you create here)
add_executable(DASH 
    src/main.cpp
    src/core/engine.cpp
    src/core/session.cpp
    # If you add a new file, just add a new line here
)

# THE GARNISH (Libraries)
# If you are on Linux, you need 'util' for PTYs.
target_link_libraries(DASH util pthread)