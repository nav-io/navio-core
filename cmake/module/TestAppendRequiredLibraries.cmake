# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include_guard(GLOBAL)

# Illumos/SmartOS requires linking with -lsocket if
# using getifaddrs & freeifaddrs.
# See:
# - https://github.com/bitcoin/bitcoin/pull/21486
# - https://smartos.org/man/3socket/getifaddrs
function(test_append_socket_library target)
  if (NOT TARGET ${target})
    message(FATAL_ERROR "${CMAKE_CURRENT_FUNCTION}() called with non-existent target \"${target}\".")
  endif()

  set(check_socket_source "
    #include <sys/types.h>
    #include <ifaddrs.h>

    int main() {
      struct ifaddrs* ifaddr;
      getifaddrs(&ifaddr);
      freeifaddrs(ifaddr);
    }
  ")

  include(CheckCXXSourceCompiles)
  check_cxx_source_compiles("${check_socket_source}" IFADDR_LINKS_WITHOUT_LIBSOCKET)
  if(NOT IFADDR_LINKS_WITHOUT_LIBSOCKET)
    include(CheckSourceCompilesWithFlags)
    check_cxx_source_compiles_with_flags("${check_socket_source}" IFADDR_NEEDS_LINK_TO_LIBSOCKET
      LINK_LIBRARIES socket
    )
    if(IFADDR_NEEDS_LINK_TO_LIBSOCKET)
      target_link_libraries(${target} INTERFACE socket)
    else()
      message(FATAL_ERROR "Cannot figure out how to use getifaddrs/freeifaddrs.")
    endif()
  endif()
  set(HAVE_IFADDRS TRUE PARENT_SCOPE)
endfunction()

# Clang, when building for 32-bit,
# and linking against libstdc++, requires linking with
# -latomic if using the C++ atomic library.
# Can be tested with: clang++ -std=c++20 test.cpp -m32
#
# Sourced from http://bugs.debian.org/797228
function(test_append_atomic_library target)
  if (NOT TARGET ${target})
    message(FATAL_ERROR "${CMAKE_CURRENT_FUNCTION}() called with non-existent target \"${target}\".")
  endif()

  set(check_atomic_source "
    #include <atomic>
    #include <cstdint>
    #include <chrono>

    using namespace std::chrono_literals;

    int main() {
      std::atomic<bool> lock{true};
      lock.exchange(false);

      std::atomic<std::chrono::seconds> t{0s};
      t.store(2s);
      auto t1 = t.load();
      t.compare_exchange_strong(t1, 3s);

      std::atomic<double> d{};
      d.store(3.14);
      auto d1 = d.load();

      std::atomic<int64_t> a{};
      int64_t v = 5;
      int64_t r = a.fetch_add(v);
      return static_cast<int>(r);
    }
  ")

  # In single-config Debug builds, libstdc++'s _GLIBCXX_DEBUG mode routes
  # std::atomic<int64_t>/<chrono::seconds>/<double> through the generic
  # __atomic_load/__atomic_store/__atomic_compare_exchange entry points
  # (rather than the size-specific _N intrinsics), which the compiler
  # cannot inline and so require libatomic at link time — even on i386
  # where the SSE2/cmpxchg8b paths would otherwise resolve the _8
  # intrinsics inline. Surface that path in the configure-time probe by
  # propagating the same _GLIBCXX_DEBUG family of defs that
  # core_interface_debug attaches in CMakeLists.txt (set from
  # DEPENDS_COMPILE_DEFINITIONS_DEBUG via depends/toolchain.cmake.in).
  set(_saved_required_defs "${CMAKE_REQUIRED_DEFINITIONS}")
  if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND DEFINED DEPENDS_COMPILE_DEFINITIONS_DEBUG)
    foreach(_def IN LISTS DEPENDS_COMPILE_DEFINITIONS_DEBUG)
      if(_def MATCHES "^-D")
        list(APPEND CMAKE_REQUIRED_DEFINITIONS "${_def}")
      else()
        list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D${_def}")
      endif()
    endforeach()
  endif()

  include(CheckCXXSourceCompiles)
  check_cxx_source_compiles("${check_atomic_source}" STD_ATOMIC_LINKS_WITHOUT_LIBATOMIC)
  if(NOT STD_ATOMIC_LINKS_WITHOUT_LIBATOMIC)
    include(CheckSourceCompilesWithFlags)
    check_cxx_source_compiles_with_flags("${check_atomic_source}" STD_ATOMIC_NEEDS_LINK_TO_LIBATOMIC
      LINK_LIBRARIES atomic
    )
    if(STD_ATOMIC_NEEDS_LINK_TO_LIBATOMIC)
      target_link_libraries(${target} INTERFACE atomic)
    else()
      message(FATAL_ERROR "Cannot figure out how to use std::atomic.")
    endif()
  endif()
  set(CMAKE_REQUIRED_DEFINITIONS "${_saved_required_defs}")
endfunction()
