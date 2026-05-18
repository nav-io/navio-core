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

  # On 32-bit targets, std::atomic<int64_t>/<chrono::seconds>/<double>
  # codegen is sensitive to optimization level and the
  # _GLIBCXX_DEBUG family of defs that the project attaches to
  # core_interface_debug. With -O2 (and without _GLIBCXX_DEBUG) the
  # compiler resolves the 8-byte ops inline via cmpxchg8b; with -O0 +
  # _GLIBCXX_DEBUG (the real i686 Debug build) the same ops route
  # through the generic __atomic_load/__atomic_store/
  # __atomic_compare_exchange entry points which require libatomic at
  # link time. The configure-time probe below compiles at release-style
  # defaults and so reports STD_ATOMIC_LINKS_WITHOUT_LIBATOMIC=Success
  # for both the eventually-linkable and eventually-broken cases. Skip
  # the probe and unconditionally attach libatomic when the host
  # pointer is 32-bit — libatomic is part of every modern GCC/Clang
  # libstdc++ install on i386/armv7/etc, and the linker will silently
  # drop it if no __atomic_* references survive.
  if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_link_libraries(${target} INTERFACE atomic)
    return()
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
endfunction()
