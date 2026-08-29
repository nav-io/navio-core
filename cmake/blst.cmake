# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Optional supranational/blst backend for the BLSCT arithmetic layer
# (evaluation of the mcl -> blst migration, see doc/blsct-blst-evaluation.md).
#
# OFF by default: nothing in the default build changes. With WITH_BLST=ON the
# pinned blst release is fetched at configure time, built with its own
# build.sh (C + assembly, no external deps), and exposed as `blst_interface`.
# The blsct libraries then also compile the `Blst` arith backend and the
# gated `template ... <Blst>` instantiations, and bench_navio gains the
# BLSCT_BlstVsMcl_* benchmarks.

option(WITH_BLST "Build the supranational/blst BLSCT arith backend + comparison benchmarks" OFF)
set(BLST_GIT_TAG "v0.3.17" CACHE STRING "supranational/blst tag to fetch when WITH_BLST=ON")

if(WITH_BLST)
  if(MSVC)
    message(FATAL_ERROR "WITH_BLST is not wired for MSVC builds (blst ships build.bat; not integrated)")
  endif()

  include(FetchContent)
  FetchContent_Declare(blst_src
    GIT_REPOSITORY https://github.com/supranational/blst.git
    GIT_TAG        ${BLST_GIT_TAG}
    GIT_SHALLOW    TRUE
  )
  FetchContent_GetProperties(blst_src)
  if(NOT blst_src_POPULATED)
    FetchContent_Populate(blst_src)
  endif()

  set(BLST_LIB_PATH ${blst_src_BINARY_DIR}/libblst.a)
  # blst's build.sh honours CC / CFLAGS from the environment. It drops the
  # archive in the working directory, so run it from the binary dir.
  add_custom_command(
    OUTPUT ${BLST_LIB_PATH}
    COMMAND ${CMAKE_COMMAND} -E env "CC=${CMAKE_C_COMPILER}" sh ${blst_src_SOURCE_DIR}/build.sh
    WORKING_DIRECTORY ${blst_src_BINARY_DIR}
    DEPENDS ${blst_src_SOURCE_DIR}/build.sh
    COMMENT "Building supranational/blst ${BLST_GIT_TAG}"
    VERBATIM
  )
  add_custom_target(blst_build DEPENDS ${BLST_LIB_PATH})

  add_library(blst STATIC IMPORTED GLOBAL)
  set_target_properties(blst PROPERTIES IMPORTED_LOCATION ${BLST_LIB_PATH})
  add_dependencies(blst blst_build)

  add_library(blst_interface INTERFACE)
  target_include_directories(blst_interface INTERFACE ${blst_src_SOURCE_DIR}/bindings)
  target_compile_definitions(blst_interface INTERFACE NAVIO_BLSCT_ARITH_BLST=1)
  target_link_libraries(blst_interface INTERFACE blst)
  # Every bls consumer gets the blst include path + NAVIO_BLSCT_ARITH_BLST.
  target_link_libraries(bls_interface INTERFACE blst_interface)
endif()
