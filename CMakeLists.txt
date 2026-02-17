cmake_minimum_required(VERSION 3.10)

# On Linux, cross-compile for Windows so windows.h and MinGW are used
if(UNIX AND NOT APPLE AND NOT CMAKE_CROSSCOMPILING)
  set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/toolchain-mingw64.cmake")
endif()

project(hammer-surf-utils LANGUAGES C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(extern/minhook)

# Default to Release (compile.sh used -O2)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Match compile.sh: -O2 -Wall
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

add_library(hammer-surf-utils SHARED
  dll.c
  tier0.c
  wrapper.c
)

target_include_directories(hammer-surf-utils PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(hammer-surf-utils PRIVATE psapi minhook)

# Match compile.sh: -Wl,--enable-stdcall-fixup (needed for Windows DLL exports)
target_link_options(hammer-surf-utils PRIVATE "LINKER:--enable-stdcall-fixup")

# Match compile.sh: output version.dll into ../../.. (same location as script)
set_target_properties(hammer-surf-utils PROPERTIES
  OUTPUT_NAME version
  PREFIX ""
  SUFFIX ".dll"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../../.."
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../../.."
)

# Build as Windows DLL (WIN32 is set when using mingw toolchain)
if(WIN32)
  set_target_properties(hammer-surf-utils PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS OFF
  )
endif()
