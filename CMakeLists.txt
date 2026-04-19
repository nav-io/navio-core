# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Ubuntu 22.04 LTS Jammy Jellyfish, https://wiki.ubuntu.com/Releases, EOSS in June 2027:
#  - CMake 3.22.1, https://packages.ubuntu.com/jammy/cmake
#
# Centos Stream 9, https://www.centos.org/cl-vs-cs/#end-of-life, EOL in May 2027:
#  - CMake 3.26.5, https://mirror.stream.centos.org/9-stream/AppStream/x86_64/os/Packages/
cmake_minimum_required(VERSION 3.22)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not allowed.")
endif()

if(POLICY CMP0171)
  cmake_policy(SET CMP0171 NEW)
endif()

get_directory_property(precious_variables CACHE_VARIABLES)

#=============================
# Project / Package metadata
#=============================
set(CLIENT_NAME "Navio Core")
set(CLIENT_VERSION_MAJOR 0)
set(CLIENT_VERSION_MINOR 1)
set(CLIENT_VERSION_BUILD 0)
set(CLIENT_VERSION_RC 0)
set(CLIENT_VERSION_IS_RELEASE "false")
set(COPYRIGHT_YEAR "2024")

set(CMAKE_TRY_COMPILE_PLATFORM_VARIABLES
  CMAKE_CXX_COMPILE_OBJECT
  CMAKE_OBJCXX_COMPILE_OBJECT
  CMAKE_CXX_LINK_EXECUTABLE
)

project(NavioCore
  VERSION ${CLIENT_VERSION_MAJOR}.${CLIENT_VERSION_MINOR}.${CLIENT_VERSION_BUILD}
  DESCRIPTION "Navio client software"
  HOMEPAGE_URL "https://nav.io/"
  LANGUAGES NONE
)

set(CLIENT_VERSION_STRING ${PROJECT_VERSION})
if(CLIENT_VERSION_RC GREATER 0)
  string(APPEND CLIENT_VERSION_STRING "rc${CLIENT_VERSION_RC}")
endif()

set(COPYRIGHT_HOLDERS "The %s developers")
set(COPYRIGHT_HOLDERS_FINAL "The ${CLIENT_NAME} developers")
set(CLIENT_BUGREPORT "https://github.com/nav-io/navio-core/issues")

#=============================
# Language setup
#=============================
if(CMAKE_VERSION VERSION_LESS 4.2 AND CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT CMAKE_HOST_APPLE)
  set(CMAKE_INSTALL_NAME_TOOL "${CMAKE_COMMAND} -E true")
endif()
enable_language(CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/module)
include(ProcessConfigurations)

if(NOT DEFINED CMAKE_OPTIMIZE_DEPENDENCIES)
  set(CMAKE_OPTIMIZE_DEPENDENCIES TRUE)
endif()

#=============================
# Configurable options
#=============================
include(CMakeDependentOption)

option(BUILD_DAEMON "Build naviod executable." ON)
option(BUILD_CLI "Build navio-cli executable." ON)
option(BUILD_STAKER "Build navio-staker executable." ON)

option(BUILD_TESTS "Build test_navio and other unit test executables." ON)
option(BUILD_TX "Build navio-tx executable." ${BUILD_TESTS})
option(BUILD_UTIL "Build navio-util executable." ${BUILD_TESTS})

option(BUILD_UTIL_CHAINSTATE "Build experimental navio-chainstate executable." OFF)
option(BUILD_KERNEL_LIB "Build experimental naviokernel library." ${BUILD_UTIL_CHAINSTATE})

option(BUILD_LIBBLSCT_ONLY "Build libblsct.a only, disabling all other targets." OFF)

option(ENABLE_WALLET "Enable wallet." ON)
if(ENABLE_WALLET)
  find_package(SQLite3 3.7.17 REQUIRED)
  if(NOT TARGET SQLite3::SQLite3) # CMake < 4.3
    add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
  endif()
endif()
cmake_dependent_option(BUILD_WALLET_TOOL "Build navio-wallet tool." ${BUILD_TESTS} "ENABLE_WALLET" OFF)

option(REDUCE_EXPORTS "Attempt to reduce exported symbols in the resulting executables." OFF)
option(CMAKE_COMPILE_WARNING_AS_ERROR "Treat compiler warnings as errors." OFF)
option(WITH_CCACHE "Attempt to use ccache for compiling." ON)

option(WITH_ZMQ "Enable ZMQ notifications." OFF)
if(WITH_ZMQ)
  find_package(ZeroMQ 4.0.0 MODULE REQUIRED)
endif()

option(WITH_USDT "Enable tracepoints for Userspace, Statically Defined Tracing." OFF)
if(WITH_USDT)
  find_package(USDT MODULE REQUIRED)
endif()

option(ENABLE_EXTERNAL_SIGNER "Enable external signer support." ON)

option(BUILD_BENCH "Build bench_navio executable." OFF)
option(BUILD_FUZZ_BINARY "Build fuzz binary." OFF)
option(BUILD_FOR_FUZZING "Build for fuzzing. Enabling this will disable all other targets and override BUILD_FUZZ_BINARY." OFF)

option(INSTALL_MAN "Install man pages." ON)

set(APPEND_CPPFLAGS "" CACHE STRING "Preprocessor flags appended to the command line after all other flags.")
set(APPEND_CFLAGS "" CACHE STRING "C compiler flags appended to the command line after all other flags.")
set(APPEND_CXXFLAGS "" CACHE STRING "(Objective) C++ compiler flags appended to the command line after all other flags.")
set(APPEND_LDFLAGS "" CACHE STRING "Linker flags appended to the command line after all other flags.")
string(APPEND CMAKE_CXX_COMPILE_OBJECT " ${APPEND_CPPFLAGS} ${APPEND_CXXFLAGS}")
string(APPEND CMAKE_CXX_CREATE_SHARED_LIBRARY " ${APPEND_LDFLAGS}")
string(APPEND CMAKE_CXX_LINK_EXECUTABLE " ${APPEND_LDFLAGS}")

set(configure_warnings)

include(CheckLinkerSupportsPIE)
check_linker_supports_pie(configure_warnings)

add_library(core_interface INTERFACE)
add_library(core_interface_relwithdebinfo INTERFACE)
add_library(core_interface_debug INTERFACE)
target_link_libraries(core_interface INTERFACE
  $<$<CONFIG:RelWithDebInfo>:core_interface_relwithdebinfo>
  $<$<CONFIG:Debug>:core_interface_debug>
)
target_compile_definitions(core_interface INTERFACE HAVE_CONFIG_H)

if(BUILD_FOR_FUZZING)
  message(WARNING "BUILD_FOR_FUZZING=ON will disable all other targets and force BUILD_FUZZ_BINARY=ON.")
  set(BUILD_DAEMON OFF)
  set(BUILD_CLI OFF)
  set(BUILD_STAKER OFF)
  set(BUILD_TX OFF)
  set(BUILD_UTIL OFF)
  set(BUILD_UTIL_CHAINSTATE OFF)
  set(BUILD_KERNEL_LIB OFF)
  set(BUILD_WALLET_TOOL OFF)
  set(ENABLE_EXTERNAL_SIGNER OFF)
  set(WITH_ZMQ OFF)
  set(BUILD_TESTS OFF)
  set(BUILD_BENCH OFF)
  set(BUILD_FUZZ_BINARY ON)
  set(BUILD_LIBBLSCT_ONLY OFF)

  target_compile_definitions(core_interface INTERFACE
    FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  )
endif()

if(BUILD_LIBBLSCT_ONLY)
  message(WARNING "BUILD_LIBBLSCT_ONLY=ON will disable all other targets.")
  set(BUILD_DAEMON OFF)
  set(BUILD_CLI OFF)
  set(BUILD_STAKER OFF)
  set(BUILD_TX OFF)
  set(BUILD_UTIL OFF)
  set(BUILD_UTIL_CHAINSTATE OFF)
  set(BUILD_KERNEL_LIB OFF)
  set(BUILD_WALLET_TOOL OFF)
  set(ENABLE_WALLET OFF)
  set(WITH_ZMQ OFF)
  set(BUILD_TESTS OFF)
  set(BUILD_BENCH OFF)
  set(BUILD_FUZZ_BINARY OFF)
endif()

include(TryAppendCXXFlags)
include(TryAppendLinkerFlag)

target_compile_definitions(core_interface_debug INTERFACE
  DEBUG
  DEBUG_LOCKORDER
  DEBUG_LOCKCONTENTION
  RPC_DOC_CHECK
  ABORT_ON_FAILED_ASSUME
)

if(WIN32)
  target_compile_definitions(core_interface INTERFACE
    _WIN32_WINNT=0x0A00
    _WIN32_IE=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
  )

  if(MSVC)
    if(VCPKG_TARGET_TRIPLET MATCHES "-static")
      set(msvc_library_linkage "")
    else()
      set(msvc_library_linkage "DLL")
    endif()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>${msvc_library_linkage}")
    unset(msvc_library_linkage)

    target_compile_definitions(core_interface INTERFACE
      _UNICODE;UNICODE
    )
    target_compile_options(core_interface INTERFACE
      /utf-8
      /Zc:preprocessor
      /Zc:__cplusplus
      /sdl
    )
    target_link_options(core_interface INTERFACE
      /MANIFEST:NO
    )
    list(APPEND CMAKE_VS_GLOBALS "UseMultiToolTask=true")
  endif()

  if(MINGW)
    target_compile_definitions(core_interface INTERFACE
      WIN32
      _WINDOWS
      _MT
    )
    try_append_cxx_flags("-Wa,-muse-unaligned-vector-move" TARGET core_interface SKIP_LINK)
    try_append_linker_flag("-static" TARGET core_interface)
    try_append_linker_flag("-Wl,--major-subsystem-version,6" TARGET core_interface)
    try_append_linker_flag("-Wl,--minor-subsystem-version,2" TARGET core_interface)
  endif()

  if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    try_append_cxx_flags("/bigobj" TARGET core_interface_debug SKIP_LINK)
  else()
    try_append_cxx_flags("-Wa,-mbig-obj" TARGET core_interface_debug SKIP_LINK)
  endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  target_compile_definitions(core_interface INTERFACE
    _FILE_OFFSET_BITS=64
  )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_compile_definitions(core_interface INTERFACE OBJC_OLD_DISPATCH_PROTOTYPES=0)
  try_append_linker_flag("-Wl,-dead_strip" TARGET core_interface)
  try_append_linker_flag("-Wl,-dead_strip_dylibs" TARGET core_interface)
  if(CMAKE_HOST_APPLE)
    try_append_linker_flag("-Wl,-headerpad_max_install_names" TARGET core_interface)
  endif()
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(core_interface INTERFACE
  Threads::Threads
)

add_library(sanitize_interface INTERFACE)
target_link_libraries(core_interface INTERFACE sanitize_interface)
if(SANITIZERS)
  string(REGEX REPLACE "(^|,)fuzzer($|,)" "\\1fuzzer-no-link\\2" sanitize_opts "${SANITIZERS}")
  set(fuzz_flag "")
  if(NOT sanitize_opts STREQUAL SANITIZERS)
    set(fuzz_flag "-fsanitize=fuzzer")
  endif()

  try_append_cxx_flags("-fsanitize=${sanitize_opts}" TARGET sanitize_interface
    RESULT_VAR cxx_supports_sanitizers
    SKIP_LINK
  )
  if(NOT cxx_supports_sanitizers)
    message(FATAL_ERROR "Compiler did not accept requested flags.")
  endif()

  try_append_linker_flag("-fsanitize=${sanitize_opts}" VAR SANITIZER_LDFLAGS
    SOURCE "
      #include <cstdint>
      #include <cstddef>
      extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { return 0; }
      int main() { return 0; }
    "
    RESULT_VAR linker_supports_sanitizers
    NO_CACHE_IF_FAILED
  )
  if(NOT linker_supports_sanitizers)
    message(FATAL_ERROR "Linker did not accept requested flags, you are missing required libraries.")
  endif()
endif()
target_link_options(sanitize_interface INTERFACE ${SANITIZER_LDFLAGS})

if(BUILD_FUZZ_BINARY)
  include(CheckSourceCompilesWithFlags)
  check_cxx_source_compiles_with_flags("
      #include <cstdint>
      #include <cstddef>
      extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { return 0; }
    " FUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION
    LDFLAGS ${SANITIZER_LDFLAGS} ${fuzz_flag}
    LINK_LIBRARIES ${FUZZ_LIBS}
  )
  add_library(fuzzer_interface INTERFACE)
  target_link_options(fuzzer_interface INTERFACE ${fuzz_flag})
  target_link_libraries(fuzzer_interface INTERFACE ${FUZZ_LIBS})
endif()

include(AddBoostIfNeeded)
add_boost_if_needed()

if(BUILD_DAEMON OR BUILD_CLI OR BUILD_STAKER OR BUILD_TESTS OR BUILD_BENCH OR BUILD_FUZZ_BINARY)
  find_package(Libevent 2.1.8 MODULE REQUIRED)
endif()

include(cmake/introspection.cmake)
include(cmake/ccache.cmake)

add_library(warn_interface INTERFACE)
target_link_libraries(core_interface INTERFACE warn_interface)
if(MSVC)
  try_append_cxx_flags("/W3" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4018" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4146" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4244" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4267" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4715" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("/wd4805" TARGET warn_interface SKIP_LINK)
  target_compile_definitions(warn_interface INTERFACE
    _CRT_SECURE_NO_WARNINGS
    _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
  )
else()
  try_append_cxx_flags("-Wall" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wextra" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wgnu" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wformat -Wformat-security" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wvla" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wshadow-field" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wthread-safety" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wloop-analysis" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wredundant-decls" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wunused-member-function" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wdate-time" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wconditional-uninitialized" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wduplicated-branches" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wduplicated-cond" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wlogical-op" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Woverloaded-virtual" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wsuggest-override" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wimplicit-fallthrough" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wunreachable-code" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wdocumentation" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wself-assign" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wbidi-chars=any" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wundef" TARGET warn_interface SKIP_LINK)
  try_append_cxx_flags("-Wunused-parameter" TARGET warn_interface SKIP_LINK
    IF_CHECK_PASSED "-Wno-unused-parameter"
  )
endif()

configure_file(cmake/script/Coverage.cmake Coverage.cmake USE_SOURCE_PERMISSIONS COPYONLY)
configure_file(cmake/script/CoverageFuzz.cmake CoverageFuzz.cmake USE_SOURCE_PERMISSIONS COPYONLY)
configure_file(cmake/script/CoverageInclude.cmake.in CoverageInclude.cmake USE_SOURCE_PERMISSIONS @ONLY)
configure_file(cmake/script/cov_tool_wrapper.sh.in cov_tool_wrapper.sh.in USE_SOURCE_PERMISSIONS COPYONLY)

try_append_cxx_flags("-fno-extended-identifiers" TARGET core_interface SKIP_LINK)

try_append_cxx_flags("-fmacro-prefix-map=A=B" TARGET core_interface SKIP_LINK
  IF_CHECK_PASSED "-fmacro-prefix-map=${PROJECT_SOURCE_DIR}/src=."
)

try_append_cxx_flags("-fstack-reuse=none" TARGET core_interface)

if(MSVC)
  try_append_linker_flag("/DYNAMICBASE" TARGET core_interface)
  try_append_linker_flag("/HIGHENTROPYVA" TARGET core_interface)
  try_append_linker_flag("/NXCOMPAT" TARGET core_interface)
else()
  try_append_cxx_flags("-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
    RESULT_VAR cxx_supports_fortify_source
    SOURCE "int main() {
            # if !defined __OPTIMIZE__ || __OPTIMIZE__ <= 0
              #error
            #endif
            }"
  )
  if(cxx_supports_fortify_source)
    target_compile_options(core_interface INTERFACE
      -U_FORTIFY_SOURCE
      -D_FORTIFY_SOURCE=3
    )
  endif()
  unset(cxx_supports_fortify_source)

  try_append_cxx_flags("-Wstack-protector" TARGET core_interface SKIP_LINK)
  try_append_cxx_flags("-fstack-protector-all" TARGET core_interface)
  try_append_cxx_flags("-fcf-protection=full" TARGET core_interface)

  if(NOT MINGW)
    try_append_cxx_flags("-fstack-clash-protection" TARGET core_interface)
  endif()

  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
      try_append_cxx_flags("-mbranch-protection=bti" TARGET core_interface SKIP_LINK)
    else()
      try_append_cxx_flags("-mbranch-protection=standard" TARGET core_interface SKIP_LINK)
    endif()
  endif()

  try_append_linker_flag("-Wl,--enable-reloc-section" TARGET core_interface)
  try_append_linker_flag("-Wl,--dynamicbase" TARGET core_interface)
  try_append_linker_flag("-Wl,--nxcompat" TARGET core_interface)
  try_append_linker_flag("-Wl,--high-entropy-va" TARGET core_interface)
  try_append_linker_flag("-Wl,-z,relro" TARGET core_interface)
  try_append_linker_flag("-Wl,-z,now" TARGET core_interface)
  try_append_linker_flag("-Wl,-z,separate-code" TARGET core_interface)
  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    try_append_linker_flag("-Wl,-fixup_chains" TARGET core_interface)
  endif()
endif()

if(REDUCE_EXPORTS)
  set(CMAKE_CXX_VISIBILITY_PRESET hidden)
  try_append_linker_flag("-Wl,--exclude-libs,ALL" TARGET core_interface)
  try_append_linker_flag("-Wl,-no_exported_symbols" VAR CMAKE_EXE_LINKER_FLAGS)
endif()

set(Python3_FIND_FRAMEWORK LAST CACHE STRING "")
set(Python3_FIND_UNVERSIONED_NAMES FIRST CACHE STRING "")
mark_as_advanced(Python3_FIND_FRAMEWORK Python3_FIND_UNVERSIONED_NAMES)
find_package(Python3 3.10 COMPONENTS Interpreter)
if(NOT TARGET Python3::Interpreter)
  list(APPEND configure_warnings "Minimum required Python not found.")
endif()

target_compile_definitions(core_interface INTERFACE ${DEPENDS_COMPILE_DEFINITIONS})
target_compile_definitions(core_interface_relwithdebinfo INTERFACE ${DEPENDS_COMPILE_DEFINITIONS_RELWITHDEBINFO})
target_compile_definitions(core_interface_debug INTERFACE ${DEPENDS_COMPILE_DEFINITIONS_DEBUG})

if(DEFINED ENV{CXXFLAGS})
  deduplicate_flags(CMAKE_CXX_FLAGS)
endif()
if(DEFINED ENV{LDFLAGS})
  deduplicate_flags(CMAKE_EXE_LINKER_FLAGS)
endif()

if(BUILD_TESTS)
  enable_testing()
endif()

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.29)
  set(CMAKE_SKIP_TEST_ALL_DEPENDENCY FALSE)
endif()

add_subdirectory(doc)
add_subdirectory(src)

include(Maintenance)
setup_split_debug_script()
add_windows_deploy_target()
add_macos_deploy_target()

message("\n")
message("Configure summary")
message("=================")
message("Executables:")
message("  naviod .............................. ${BUILD_DAEMON}")
message("  navio-cli ........................... ${BUILD_CLI}")
message("  navio-staker ........................ ${BUILD_STAKER}")
message("  navio-tx ............................ ${BUILD_TX}")
message("  navio-util .......................... ${BUILD_UTIL}")
message("  navio-wallet ........................ ${BUILD_WALLET_TOOL}")
message("  navio-chainstate (experimental) ..... ${BUILD_UTIL_CHAINSTATE}")
message("  libnaviokernel (experimental) ....... ${BUILD_KERNEL_LIB}")
message("Libraries:")
message("  libblsct only ....................... ${BUILD_LIBBLSCT_ONLY}")
message("Optional features:")
message("  wallet support ...................... ${ENABLE_WALLET}")
message("  external signer ..................... ${ENABLE_EXTERNAL_SIGNER}")
message("  ZeroMQ .............................. ${WITH_ZMQ}")
message("  USDT tracing ........................ ${WITH_USDT}")
message("Tests:")
message("  test_navio .......................... ${BUILD_TESTS}")
message("  bench_navio ......................... ${BUILD_BENCH}")
message("  fuzz binary ......................... ${BUILD_FUZZ_BINARY}")
message("")
if(CMAKE_CROSSCOMPILING)
  set(cross_status "TRUE, for ${CMAKE_SYSTEM_NAME}, ${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(cross_status "FALSE")
endif()
message("Cross compiling ....................... ${cross_status}")
message("C++ compiler .......................... ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}, ${CMAKE_CXX_COMPILER}")
include(FlagsSummary)
flags_summary()
message("Treat compiler warnings as errors ..... ${CMAKE_COMPILE_WARNING_AS_ERROR}")
message("Use ccache for compiling .............. ${WITH_CCACHE}")
message("\n")
if(configure_warnings)
  message("  ******\n")
  foreach(warning IN LISTS configure_warnings)
    message(WARNING "${warning}")
  endforeach()
  message("  ******\n")
  message(AUTHOR_WARNING "Warnings have been encountered!")
endif()

include(WarnAboutGlobalProperties)
