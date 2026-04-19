# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Build herumi/mcl and herumi/bls static libraries using their existing
# Makefiles. The autotools build passes MCL_USE_LLVM=0 and BLS_ETH=1 to match
# what the CI env expects. Output paths mirror what the Makefiles produce.

include(ExternalProject)

set(BLS_SRC_DIR ${PROJECT_SOURCE_DIR}/src/bls)
set(MCL_SRC_DIR ${BLS_SRC_DIR}/mcl)

set(LIBMCL_PATH ${MCL_SRC_DIR}/lib/libmcl.a)
set(LIBBLS_PATH ${BLS_SRC_DIR}/lib/libbls384_256.a)

ExternalProject_Add(mcl_build
  SOURCE_DIR  ${MCL_SRC_DIR}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND
    ${CMAKE_MAKE_PROGRAM}
    MCL_USE_LLVM=0
    ARCH=${CMAKE_SYSTEM_PROCESSOR}
    CC=${CMAKE_C_COMPILER}
    CXX=${CMAKE_CXX_COMPILER}
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
    ${CMAKE_MAKE_PROGRAM}
    BLS_ETH=1
    ARCH=${CMAKE_SYSTEM_PROCESSOR}
    CC=${CMAKE_C_COMPILER}
    CXX=${CMAKE_CXX_COMPILER}
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

# Interface target for consumers: links bls + mcl, sets include paths
add_library(bls_interface INTERFACE)
target_include_directories(bls_interface INTERFACE
  ${BLS_SRC_DIR}/include
  ${MCL_SRC_DIR}/include
  ${MCL_SRC_DIR}/src
)
target_compile_definitions(bls_interface INTERFACE BLS_ETH=1)
target_link_libraries(bls_interface INTERFACE bls384_256)
