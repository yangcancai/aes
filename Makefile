# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.24

# Default target executed when no arguments are given to make.
default_target: all
.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:

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
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.24.0/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.24.0/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/cam/proj/c/aes

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/cam/proj/c/aes

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/local/Cellar/cmake/3.24.0/bin/ccmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache
.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/local/Cellar/cmake/3.24.0/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache
.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/cam/proj/c/aes/CMakeFiles /Users/cam/proj/c/aes//CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /Users/cam/proj/c/aes/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean
.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named aes_library

# Build rule for target.
aes_library: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 aes_library
.PHONY : aes_library

# fast build rule for target.
aes_library/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes_library.dir/build.make CMakeFiles/aes_library.dir/build
.PHONY : aes_library/fast

#=============================================================================
# Target rules for targets named aes_static

# Build rule for target.
aes_static: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 aes_static
.PHONY : aes_static

# fast build rule for target.
aes_static/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes_static.dir/build.make CMakeFiles/aes_static.dir/build
.PHONY : aes_static/fast

src/aes.o: src/aes.c.o
.PHONY : src/aes.o

# target to build an object file
src/aes.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes_library.dir/build.make CMakeFiles/aes_library.dir/src/aes.c.o
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes_static.dir/build.make CMakeFiles/aes_static.dir/src/aes.c.o
.PHONY : src/aes.c.o

src/aes.i: src/aes.c.i
.PHONY : src/aes.i

# target to preprocess a source file
src/aes.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes_library.dir/build.make CMakeFiles/aes_library.dir/src/aes.c.i
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes_static.dir/build.make CMakeFiles/aes_static.dir/src/aes.c.i
.PHONY : src/aes.c.i

src/aes.s: src/aes.c.s
.PHONY : src/aes.s

# target to generate assembly for a file
src/aes.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes_library.dir/build.make CMakeFiles/aes_library.dir/src/aes.c.s
	$(MAKE) $(MAKESILENT) -f CMakeFiles/aes_static.dir/build.make CMakeFiles/aes_static.dir/src/aes.c.s
.PHONY : src/aes.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... aes_library"
	@echo "... aes_static"
	@echo "... src/aes.o"
	@echo "... src/aes.i"
	@echo "... src/aes.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system
