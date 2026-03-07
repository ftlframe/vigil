cmake_minimum_required(VERSION 3.15)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
project(vigil C CXX)

find_library(PCAP_LIB pcap)

# ── C core library (shared by both targets) ──────────────────────────
add_library(vigil_core STATIC
  src/core/capture.c
  src/core/parse.c
  src/core/arena.c
  src/core/hashmap.c
  src/core/spscbuf.c
)
target_include_directories(vigil_core PUBLIC include)
target_link_libraries(vigil_core ${PCAP_LIB})
target_compile_options(vigil_core PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(vigil_core PRIVATE -fsanitize=address,undefined)
  target_link_options(vigil_core PRIVATE -fsanitize=address,undefined)
endif()

# ── Original CLI target ──────────────────────────────────────────────
add_executable(vigil src/core/main.c)
target_link_libraries(vigil vigil_core)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(vigil PRIVATE -fsanitize=address,undefined)
  target_link_options(vigil PRIVATE -fsanitize=address,undefined)
endif()

# ── FTXUI (fetched at configure time) ────────────────────────────────
include(FetchContent)
FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG        v5.0.0
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(ftxui)

# ── Dashboard target ─────────────────────────────────────────────────
add_executable(vigil_dashboard src/ui/dashboard/main.cpp)
target_link_libraries(vigil_dashboard vigil_core ftxui::screen ftxui::dom ftxui::component pthread)
target_compile_options(vigil_dashboard PRIVATE -Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(vigil_dashboard PRIVATE -fsanitize=address,undefined)
  target_link_options(vigil_dashboard PRIVATE -fsanitize=address,undefined)
endif()
