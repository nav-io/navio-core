# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Build the vendored supranational/blst (src/blst, v0.3.17) that provides the
# BLS12-381 arithmetic behind BLSCT. blst is one C translation unit plus one
# assembly file with pre-generated x86_64 / ARM64 code for every ABI
# (build/assembly.S picks the right flavour from the preprocessor), so it is
# compiled directly here — no sub-make, no network, no in-source objects.
#
# Architecture handling mirrors upstream build.sh:
#   x86_64 / aarch64  -> assembly. BLST_PORTABLE (default ON on x86_64)
#                        additionally compiles the non-ADX x86_64 paths next
#                        to the ADX ones and selects at runtime via CPUID
#                        (-D__BLST_PORTABLE__); required for binaries that are
#                        distributed. OFF builds only the non-ADX path, which
#                        is what build.sh does on a host without ADX.
#   everything else   -> blst's portable C implementation (-D__BLST_NO_ASM__,
#                        32-bit limbs). There is no C fallback on the two
#                        64-bit assembly targets (vect.h), so this is not an
#                        option there.

set(BLST_SRC_DIR ${PROJECT_SOURCE_DIR}/src/blst)

set(_blst_is_x86_64 FALSE)
set(_blst_is_arm64 FALSE)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
  set(_blst_is_x86_64 TRUE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  set(_blst_is_arm64 TRUE)
endif()
if(_blst_is_x86_64 OR _blst_is_arm64)
  set(_blst_use_asm TRUE)
else()
  set(_blst_use_asm FALSE)
endif()

option(BLST_PORTABLE "blst: build ADX and non-ADX x86_64 code paths with runtime dispatch" ${_blst_is_x86_64})

if(NOT _blst_use_asm)
  add_library(blst STATIC ${BLST_SRC_DIR}/src/server.c)
  target_compile_definitions(blst PRIVATE __BLST_NO_ASM__)
elseif(MSVC)
  # Upstream build.bat's static library: server.c plus the MASM / armasm64
  # translations in build/win64. dll.c (DllMain + local memcpy/memset) is
  # only for the DLL build and must not go into a static library.
  if(_blst_is_arm64)
    enable_language(ASM_MARMASM)
    file(GLOB _blst_asm ${BLST_SRC_DIR}/build/win64/*-armv8.asm)
  else()
    enable_language(ASM_MASM)
    file(GLOB _blst_asm ${BLST_SRC_DIR}/build/win64/*-x86_64.asm)
  endif()
  add_library(blst STATIC ${BLST_SRC_DIR}/src/server.c ${_blst_asm})
else()
  enable_language(ASM)
  add_library(blst STATIC ${BLST_SRC_DIR}/src/server.c ${BLST_SRC_DIR}/build/assembly.S)
  # Mirrors build.sh: -O2 -fno-builtin -fPIC; -mno-avx avoids costly AVX/SSE
  # transitions around the SSE2 assembly. -O2 is deliberate (it overrides the
  # configuration's -O3): see the performance note in doc/blsct-blst-evaluation.md.
  target_compile_options(blst PRIVATE -O2 -fno-builtin)
  if(_blst_is_x86_64)
    target_compile_options(blst PRIVATE -mno-avx)
  endif()
endif()

if(_blst_use_asm AND _blst_is_x86_64 AND BLST_PORTABLE)
  target_compile_definitions(blst PRIVATE __BLST_PORTABLE__)
endif()

target_include_directories(blst PUBLIC ${BLST_SRC_DIR}/bindings)
# The archive output directory is set by src/CMakeLists.txt after this file
# is included and is captured at target creation, so pin it explicitly:
# ci's libblsct symbol check reads build/lib/libblst.a.
set_target_properties(blst PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib
)

# Interface target for consumers.
add_library(blst_interface INTERFACE)
target_include_directories(blst_interface INTERFACE ${BLST_SRC_DIR}/bindings)
target_link_libraries(blst_interface INTERFACE blst)
