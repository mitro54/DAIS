# &lt; DATA / AI SHELL >
... DASH

- Is still in planning and researching stage

## What
- This project will be a PTY, pseudoterminal, a shell wrapper. 
- Core will be written in C++, that will support Python scripts as extensions to the C++ core. 

## Scope 
- Projects scope is to create a helpful extension for Data / AI Engineers in their day-to-day tasks, running in their favorite shell.
- This project will use present technologies and as an open-source, allows others to contribute their ideas and features to it as well.
- Allows Python scripts so other Data / AI oriented people can use the language they are most confident in.

## Why
Why not, terminals should be smarter

## Build
### Create a build folder and cd in to it
`mkdir build`
`cd build`

### Run cmake and make
`cmake ..` or `cmake -DCMAKE_CXX_COMPILER=g++-14 ..` to make sure it uses GCC 14 for C++23
`make`

### Run it
`./DASH`