OSX_MIN_VERSION=11.0
OSX_SDK_VERSION=14.0
XCODE_VERSION=15.0
XCODE_BUILD_ID=15A240d
LLD_VERSION=711

OSX_SDK=$(SDK_PATH)/Xcode-$(XCODE_VERSION)-$(XCODE_BUILD_ID)-extracted-SDK-with-libcxx-headers

# clang + llvm-* come from the build environment's PATH (clang-toolchain
# from contrib/guix/manifest.scm's darwin branch). The old depends-managed
# chain — native_llvm fetches a prebuilt Ubuntu clang, then native_libtapi
# + native_cctools build on top of it — was retired here when navio moved
# to upstream's modernized darwin path: the prebuilt clang's interp
# (/lib64/ld-linux-x86-64.so.2) doesn't exist inside the guix container,
# and the matching cctools tools are no longer needed once we use lld and
# llvm-* for binutils.
clang_prog=$(shell command -v clang)
clangxx_prog=$(shell command -v clang++)

darwin_AR=$(shell command -v llvm-ar)
darwin_NM=$(shell command -v llvm-nm)
darwin_OBJCOPY=$(shell command -v llvm-objcopy)
darwin_OBJDUMP=$(shell command -v llvm-objdump)
darwin_RANLIB=$(shell command -v llvm-ranlib)
darwin_STRIP=$(shell command -v llvm-strip)
# Needed by CMake's darwin binutils detection (e.g. when building Boost's
# compiled libraries for the bundled i2pd). llvm-install-name-tool / llvm-otool
# are multicall aliases of llvm-objcopy/llvm-objdump and are not always
# symlinked unversioned (e.g. Debian's llvm package). Resolve them from the llvm
# bindir derived from llvm-objcopy (wired above), which is version-agnostic.
darwin_llvm_bindir=$(shell dirname $(shell readlink -f $(shell command -v llvm-objcopy)))
darwin_INSTALL_NAME_TOOL=$(darwin_llvm_bindir)/llvm-install-name-tool
darwin_OTOOL=$(darwin_llvm_bindir)/llvm-otool

# Flag explanations:
#
#     -mlinker-version
#
#         Ensures that modern linker features are enabled. See here for more
#         details: https://github.com/bitcoin/bitcoin/pull/19407.
#
#     -isysroot$(OSX_SDK) -nostdlibinc
#
#         Disable default include paths built into the compiler as well as
#         those normally included for libc and libc++. The only path that
#         remains implicitly is the clang resource dir.
#
#     -iwithsysroot / -iframeworkwithsysroot
#
#         Adds the desired paths from the SDK
#
#     -platform_version
#
#         Indicate to the linker the platform, the oldest supported version,
#         and the SDK used.
#
#     -no_adhoc_codesign
#
#         Disable adhoc codesigning (for now) when using LLVM tooling, to avoid
#         non-determinism issues with the Identifier field.

# `env -u …` strips the build-side C/C++ include path that
# contrib/guix/libexec/build.sh exports so the native gmp gen-* helpers
# can find linux-libre-headers. clang targeting darwin must NOT see those
# Linux include paths — it has its own SDK sysroot via -isysroot.
darwin_CC=env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
              -u OBJC_INCLUDE_PATH -u OBJCPLUS_INCLUDE_PATH -u CPATH \
              -u LIBRARY_PATH \
              $(clang_prog) --target=$(host) \
              -isysroot$(OSX_SDK) -nostdlibinc \
              -iwithsysroot/usr/include -iframeworkwithsysroot/System/Library/Frameworks

darwin_CXX=env -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
               -u OBJC_INCLUDE_PATH -u OBJCPLUS_INCLUDE_PATH -u CPATH \
               -u LIBRARY_PATH \
               $(clangxx_prog) --target=$(host) \
               -isysroot$(OSX_SDK) -nostdlibinc \
               -iwithsysroot/usr/include/c++/v1 \
               -iwithsysroot/usr/include -iframeworkwithsysroot/System/Library/Frameworks

darwin_CFLAGS=-pipe -std=$(C_STANDARD) -mmacosx-version-min=$(OSX_MIN_VERSION)
darwin_CXXFLAGS=-pipe -std=$(CXX_STANDARD) -mmacosx-version-min=$(OSX_MIN_VERSION)
darwin_LDFLAGS=-Wl,-platform_version,macos,$(OSX_MIN_VERSION),$(OSX_SDK_VERSION)

ifneq ($(build_os),darwin)
# -fuse-ld=lld appears in *FLAGS (not just LDFLAGS) so it reaches
# gmp's AC_PROG_CC sanity check — gmp's configure compiles+links a
# conftest with CC + CFLAGS only (no LDFLAGS), and without
# -fuse-ld=lld clang falls back to /usr/bin/ld (GNU ld), which
# rejects darwin's Mach-O-flavored linker args with "unrecognised
# emulation mode: llvm" and the probe fails with "could not find a
# working compiler".
darwin_CFLAGS += -mlinker-version=$(LLD_VERSION) -fuse-ld=lld
darwin_CXXFLAGS += -mlinker-version=$(LLD_VERSION) -fuse-ld=lld
darwin_LDFLAGS += -Wl,-no_adhoc_codesign -fuse-ld=lld
endif

darwin_release_CFLAGS=-O2
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O1
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)

darwin_cmake_system_name=Darwin
darwin_cmake_system_version=20.1
