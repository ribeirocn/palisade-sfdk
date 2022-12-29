# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.24

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.24.1/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.24.1/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk

# Include any dependencies generated for this target.
include src/sfdk/CMakeFiles/simple-integers.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/sfdk/CMakeFiles/simple-integers.dir/compiler_depend.make

# Include the progress variables for this target.
include src/sfdk/CMakeFiles/simple-integers.dir/progress.make

# Include the compile flags for this target's objects.
include src/sfdk/CMakeFiles/simple-integers.dir/flags.make

src/sfdk/CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o: src/sfdk/CMakeFiles/simple-integers.dir/flags.make
src/sfdk/CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o: src/sfdk/examples/simple-integers.cpp
src/sfdk/CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o: src/sfdk/CMakeFiles/simple-integers.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/sfdk/CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o"
	cd /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT src/sfdk/CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o -MF CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o.d -o CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o -c /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk/examples/simple-integers.cpp

src/sfdk/CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.i"
	cd /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk/examples/simple-integers.cpp > CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.i

src/sfdk/CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.s"
	cd /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk/examples/simple-integers.cpp -o CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.s

# Object files for target simple-integers
simple__integers_OBJECTS = \
"CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o"

# External object files for target simple-integers
simple__integers_EXTERNAL_OBJECTS =

bin/examples/sfdk/simple-integers: src/sfdk/CMakeFiles/simple-integers.dir/examples/simple-integers.cpp.o
bin/examples/sfdk/simple-integers: src/sfdk/CMakeFiles/simple-integers.dir/build.make
bin/examples/sfdk/simple-integers: lib/libPALISADEsfdk.0.1.0.dylib
bin/examples/sfdk/simple-integers: /usr/local/lib/libPALISADEpke.1.11.7.dylib
bin/examples/sfdk/simple-integers: /usr/local/lib/libPALISADEbinfhe.1.11.7.dylib
bin/examples/sfdk/simple-integers: /usr/local/lib/libPALISADEcore.1.11.7.dylib
bin/examples/sfdk/simple-integers: src/sfdk/CMakeFiles/simple-integers.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../bin/examples/sfdk/simple-integers"
	cd /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/simple-integers.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/sfdk/CMakeFiles/simple-integers.dir/build: bin/examples/sfdk/simple-integers
.PHONY : src/sfdk/CMakeFiles/simple-integers.dir/build

src/sfdk/CMakeFiles/simple-integers.dir/clean:
	cd /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk && $(CMAKE_COMMAND) -P CMakeFiles/simple-integers.dir/cmake_clean.cmake
.PHONY : src/sfdk/CMakeFiles/simple-integers.dir/clean

src/sfdk/CMakeFiles/simple-integers.dir/depend:
	cd /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk /Users/carlosribeiro/Library/CloudStorage/OneDrive-UniversidadedeLisboa/VisualCode/palisade-sfdk/src/sfdk/CMakeFiles/simple-integers.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/sfdk/CMakeFiles/simple-integers.dir/depend

