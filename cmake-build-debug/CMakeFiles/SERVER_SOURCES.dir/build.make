# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/tom/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/201.7223.86/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/tom/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/201.7223.86/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/SERVER_SOURCES.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/SERVER_SOURCES.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/SERVER_SOURCES.dir/flags.make

CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.o: CMakeFiles/SERVER_SOURCES.dir/flags.make
CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.o: ../Server/server.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.o -c /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/Server/server.cpp

CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/Server/server.cpp > CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.i

CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/Server/server.cpp -o CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.s

# Object files for target SERVER_SOURCES
SERVER_SOURCES_OBJECTS = \
"CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.o"

# External object files for target SERVER_SOURCES
SERVER_SOURCES_EXTERNAL_OBJECTS =

libSERVER_SOURCES.a: CMakeFiles/SERVER_SOURCES.dir/Server/server.cpp.o
libSERVER_SOURCES.a: CMakeFiles/SERVER_SOURCES.dir/build.make
libSERVER_SOURCES.a: CMakeFiles/SERVER_SOURCES.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libSERVER_SOURCES.a"
	$(CMAKE_COMMAND) -P CMakeFiles/SERVER_SOURCES.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/SERVER_SOURCES.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/SERVER_SOURCES.dir/build: libSERVER_SOURCES.a

.PHONY : CMakeFiles/SERVER_SOURCES.dir/build

CMakeFiles/SERVER_SOURCES.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/SERVER_SOURCES.dir/cmake_clean.cmake
.PHONY : CMakeFiles/SERVER_SOURCES.dir/clean

CMakeFiles/SERVER_SOURCES.dir/depend:
	cd /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/cmake-build-debug /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/cmake-build-debug /home/tom/CLionProjects/FOC_cybersec_fin/FOC_cybersec/FOC/cmake-build-debug/CMakeFiles/SERVER_SOURCES.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/SERVER_SOURCES.dir/depend

