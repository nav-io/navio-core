# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Build herumi/mcl and herumi/bls static libraries.
#
# Unix/Linux/macOS: use the existing GNU Makefiles via ExternalProject_Add.
# MSVC (Windows): GNU Makefiles do not support cl.exe; compile fp.cpp,
# bn_c384_256.cpp, and bls_c384_256.cpp directly as cmake targets.

option(WITH_GMP "Build mcl with libgmp (faster bignum)" OFF)
option(WITH_MCL_OPENMP "Build mcl with OpenMP MSM" OFF)

set(BLS_SRC_DIR ${PROJECT_SOURCE_DIR}/src/bls)
set(MCL_SRC_DIR ${BLS_SRC_DIR}/mcl)

if(MSVC)
  # -----------------------------------------------------------------
  # MSVC path: compile mcl/bls source files directly.
  # No GMP (uses MCL_USE_VINT instead), no OpenSSL, no LLVM/Xbyak.
  # -----------------------------------------------------------------

  # mcl gates its LLVM-asm code paths on `#ifdef MCL_USE_LLVM` (defined,
  # not value), so a `-DMCL_USE_LLVM=0` would still pull in references
  # to mcl_fp_addPre6L / mcl_fpDbl_mod_NIST_P192L / ... that we never
  # build on MSVC. Leave the macro undefined — matches the mcl GNU
  # Makefile's mingw/cygwin path, which sets MCL_USE_LLVM=0 in make
  # but doesn't pass -DMCL_USE_LLVM=1 to the compiler.
  set(_MCL_DEFS
    MCL_USE_VINT
    MCL_VINT_FIXED_BUFFER
    MCL_DONT_USE_OPENSSL
    MCL_DONT_USE_XBYAK
    MCL_NO_AUTOLINK
    MCLBN_NO_AUTOLINK
    MCLBN_DONT_EXPORT
    BLS_DONT_EXPORT
    NOMINMAX
  )

  add_library(mcl STATIC ${MCL_SRC_DIR}/src/fp.cpp)
  target_compile_definitions(mcl PUBLIC ${_MCL_DEFS})
  target_include_directories(mcl PUBLIC
    ${MCL_SRC_DIR}/include
    ${MCL_SRC_DIR}/src
  )
  set_target_properties(mcl PROPERTIES POSITION_INDEPENDENT_CODE ON)

  # mclbn384_256: the C-binding layer that bls_c384_256.cpp calls into.
  add_library(mclbn384_256_inner STATIC ${MCL_SRC_DIR}/src/bn_c384_256.cpp)
  target_compile_definitions(mclbn384_256_inner PUBLIC ${_MCL_DEFS})
  target_include_directories(mclbn384_256_inner PUBLIC
    ${MCL_SRC_DIR}/include
    ${MCL_SRC_DIR}/src
  )
  target_link_libraries(mclbn384_256_inner PUBLIC mcl)
  set_target_properties(mclbn384_256_inner PROPERTIES POSITION_INDEPENDENT_CODE ON)

  # bls384_256: the BLS C library (BLS_ETH=1 for Ethereum 2 spec).
  add_library(bls384_256 STATIC ${BLS_SRC_DIR}/src/bls_c384_256.cpp)
  target_compile_definitions(bls384_256 PUBLIC
    ${_MCL_DEFS}
    BLS_ETH=1
    BLS_NO_AUTOLINK
  )
  target_include_directories(bls384_256 PUBLIC
    ${BLS_SRC_DIR}/include
    ${MCL_SRC_DIR}/include
    ${MCL_SRC_DIR}/src
  )
  target_link_libraries(bls384_256 PUBLIC mclbn384_256_inner mcl)
  set_target_properties(bls384_256 PROPERTIES POSITION_INDEPENDENT_CODE ON)

  if(WITH_GMP)
    message(WARNING "WITH_GMP is ignored for MSVC builds (no libgmp/mpir configured)")
  endif()

else()
  # -----------------------------------------------------------------
  # Unix path: use GNU Makefiles via ExternalProject_Add.
  # -----------------------------------------------------------------

  include(ExternalProject)

  # mcl/bls ship GNU Makefiles, so we need real make even when the top-level
  # generator is Ninja (CMAKE_MAKE_PROGRAM would otherwise point at ninja).
  find_program(GNU_MAKE_EXECUTABLE NAMES gmake make REQUIRED)

  if(WITH_GMP)
    set(MCL_USE_GMP_FLAG MCL_USE_GMP=1)
  else()
    set(MCL_USE_GMP_FLAG MCL_USE_GMP=0)
  endif()
  if(WITH_MCL_OPENMP)
    set(MCL_USE_OMP_FLAG MCL_USE_OMP=1)
  else()
    set(MCL_USE_OMP_FLAG MCL_USE_OMP=0)
  endif()

  set(LIBMCL_PATH ${MCL_SRC_DIR}/lib/libmcl.a)
  set(LIBBLS_PATH ${BLS_SRC_DIR}/lib/libbls384_256.a)

  ExternalProject_Add(mcl_build
    SOURCE_DIR  ${MCL_SRC_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
      ${GNU_MAKE_EXECUTABLE}
      MCL_USE_LLVM=0
      ${MCL_USE_GMP_FLAG}
      ${MCL_USE_OMP_FLAG}
      ARCH=${CMAKE_SYSTEM_PROCESSOR}
      CC=${CMAKE_C_COMPILER}
      CXX=${CMAKE_CXX_COMPILER}
      # mcl/bls Makefiles only consult CFLAGS for both C and C++ compilation,
      # so CMAKE_CXX_FLAGS gets merged in here to propagate things like
      # -stdlib=libc++ that would otherwise be lost between cmake and make.
      "CFLAGS_USER=${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}"
      "LDFLAGS=${CMAKE_EXE_LINKER_FLAGS}"
      -C ${MCL_SRC_DIR}
      lib/libmcl.a
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${LIBMCL_PATH}
  )

  ExternalProject_Add(bls_build
    SOURCE_DIR  ${BLS_SRC_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
      ${GNU_MAKE_EXECUTABLE}
      BLS_ETH=1
      ${MCL_USE_GMP_FLAG}
      ${MCL_USE_OMP_FLAG}
      ARCH=${CMAKE_SYSTEM_PROCESSOR}
      CC=${CMAKE_C_COMPILER}
      CXX=${CMAKE_CXX_COMPILER}
      # mcl/bls Makefiles only consult CFLAGS for both C and C++ compilation,
      # so CMAKE_CXX_FLAGS gets merged in here to propagate things like
      # -stdlib=libc++ that would otherwise be lost between cmake and make.
      "CFLAGS_USER=${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}"
      "LDFLAGS=${CMAKE_EXE_LINKER_FLAGS}"
      -C ${BLS_SRC_DIR}
      lib/libbls384_256.a
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${LIBBLS_PATH}
    DEPENDS mcl_build
  )

  add_library(mcl STATIC IMPORTED GLOBAL)
  set_target_properties(mcl PROPERTIES IMPORTED_LOCATION ${LIBMCL_PATH})
  add_dependencies(mcl mcl_build)

  add_library(bls384_256 STATIC IMPORTED GLOBAL)
  set_target_properties(bls384_256 PROPERTIES IMPORTED_LOCATION ${LIBBLS_PATH})
  add_dependencies(bls384_256 bls_build)
  target_link_libraries(bls384_256 INTERFACE mcl)

  if(WITH_GMP)
    find_library(GMP_LIBRARY NAMES gmp REQUIRED)
    find_library(GMPXX_LIBRARY NAMES gmpxx REQUIRED)
  endif()
endif()

# Interface target for consumers: links bls + mcl, sets include paths.
# Defined outside the if/else so the target name is always the same.
add_library(bls_interface INTERFACE)
target_include_directories(bls_interface INTERFACE
  ${BLS_SRC_DIR}/include
  ${MCL_SRC_DIR}/include
  ${MCL_SRC_DIR}/src
)
target_compile_definitions(bls_interface INTERFACE BLS_ETH=1)
target_link_libraries(bls_interface INTERFACE bls384_256)
if(WITH_GMP AND NOT MSVC)
  target_link_libraries(bls_interface INTERFACE ${GMPXX_LIBRARY} ${GMP_LIBRARY})
endif()
