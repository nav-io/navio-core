# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

add_library(univalue STATIC EXCLUDE_FROM_ALL
  lib/univalue.cpp
  lib/univalue_get.cpp
  lib/univalue_read.cpp
  lib/univalue_write.cpp
)

target_include_directories(univalue
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# core_interface carries the project-wide compile definitions (Debug-mode
# _GLIBCXX_DEBUG, _LIBCPP_ENABLE_DEBUG_MODE=1, etc) propagated from depends.
# Without this link, univalue.cpp compiles with vanilla std::map while every
# consumer that pulls in core_interface (directly or transitively) compiles
# with std::__debug::map — yielding LNK errors on UniValue::checkObject and
# any other API that takes std::map by reference. Matches upstream Bitcoin
# Core's src/univalue/CMakeLists.txt.
target_link_libraries(univalue PRIVATE core_interface)
