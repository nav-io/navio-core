# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
#
# Required input variables (set via -D):
#   RAW_SOURCE_PATH - absolute path to the input .raw file
#   HEADER_PATH     - absolute path to write the .raw.h output
# Optional:
#   RAW_NAMESPACE   - when set, emit upstream-style namespaced std::byte +
#                     std::span. When empty/undefined, emit the legacy
#                     autotools-compatible "static unsigned const char
#                     <basename>_raw[] = { ... };" array (used by
#                     src/bench/data.cpp).

cmake_path(GET RAW_SOURCE_PATH STEM raw_source_basename)

file(READ ${RAW_SOURCE_PATH} hex_content HEX)
string(REGEX REPLACE "................" "\\0\n" formatted_bytes "${hex_content}")

if(RAW_NAMESPACE)
  string(REGEX REPLACE "[^\n][^\n]" "std::byte{0x\\0}," formatted_bytes "${formatted_bytes}")
  set(header_content
"#include <cstddef>
#include <span>

namespace ${RAW_NAMESPACE} {
inline constexpr std::byte detail_${raw_source_basename}_raw[] {
${formatted_bytes}
};

inline constexpr std::span ${raw_source_basename}{detail_${raw_source_basename}_raw};
}")
else()
  string(REGEX REPLACE "[^\n][^\n]" "0x\\0, " formatted_bytes "${formatted_bytes}")
  set(header_content
"static unsigned const char ${raw_source_basename}_raw[] = {
${formatted_bytes}
};
")
endif()

file(WRITE ${HEADER_PATH} "${header_content}")
