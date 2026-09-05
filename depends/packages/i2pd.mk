package=i2pd
$(package)_version=2.60.0
$(package)_download_path=https://github.com/PurpleI2P/i2pd/archive/refs/tags/
# GitHub serves the source archive as <tag>.tar.gz; save it under a
# project-prefixed name locally.
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=ef32100c5ffdf4d23dfe78a2f6c08f65574fd79f992eb2ac8cfea0b6440deabd
$(package)_dependencies=boost openssl zlib
# i2pd's CMake project lives in the build/ subdirectory; configure out-of-source.
$(package)_build_subdir=navio-build

# Client/router daemon only (no static lib, no UPnP, no GUI). Dependencies are
# linked statically (only .a are staged by depends); mirror naviod's static
# strategy for the runtime libs: -static on Windows, -static-libstdc++/libgcc on
# Linux (glibc stays dynamic so NSS/DNS keeps working), dynamic on macOS. We do
# NOT use i2pd's WITH_STATIC (full -static) precisely because it would break
# glibc name resolution.
define $(package)_set_vars
$(package)_config_opts=-DWITH_BINARY=ON -DWITH_LIBRARY=OFF -DWITH_UPNP=OFF
$(package)_config_opts+=-DBUILD_SHARED_LIBS=OFF
$(package)_config_opts+=-DBoost_USE_STATIC_LIBS=ON -DOPENSSL_USE_STATIC_LIBS=ON
$(package)_config_opts+=-DCMAKE_PREFIX_PATH=$(host_prefix)
$(package)_config_opts+=-DCMAKE_FIND_ROOT_PATH=$(host_prefix)
# WITH_STATIC is i2pd's own "link everything statically" switch. It stays at its
# OFF default everywhere except Windows: its non-MSVC branch forces a
# whole-binary -static, which statically links glibc and breaks NSS name
# resolution.
#
# Windows has no glibc, and this recipe already passes -static below, so that
# objection does not apply -- and leaving it off there actively breaks the
# build. With WITH_STATIC off, i2pd's else-branch runs
# `set(Boost_USE_STATIC_LIBS OFF)` for WIN32 (build/CMakeLists.txt). That is a
# normal variable, so it shadows the -DBoost_USE_STATIC_LIBS=ON above rather
# than being overridden by it, and the following find_package asks for a shared
# Boost. depends installs Boost static-only, so its config reports itself
# unsuitable ("1.90.0 (static)") and configuration fails. The same branch also
# adds -DBOOST_*_DYN_LINK, which would mark those static archives
# __declspec(dllimport) even if the lookup had succeeded.
$(package)_config_opts_mingw32+=-DWITH_STATIC=ON

# The mingw toolchain depends selects is the POSIX-threads variant, so libgcc's
# emutls and libstdc++'s chrono reference pthread_* and clock_gettime64 -- both
# live in libwinpthread. The compiler driver appends libstdc++ after everything
# on the command line, so a -lwinpthread placed in the linker FLAGS (which CMake
# emits before the objects) is consumed too early and those references stay
# undefined. CMAKE_CXX_STANDARD_LIBRARIES is the one slot CMake puts after the
# target's libraries, so terminate the line with libstdc++ followed by
# libwinpthread. The leading entries are CMake's own mingw default for this
# variable, repeated because setting it replaces rather than appends.
$(package)_config_opts_mingw32+=-DCMAKE_CXX_STANDARD_LIBRARIES="-lkernel32 -luser32 -lgdi32 -lwinspool -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -ladvapi32 -lstdc++ -lwinpthread"
ifeq ($(host_os),mingw32)
$(package)_ldflags+=-static
else ifneq ($(host_os),darwin)
$(package)_ldflags+=-static-libstdc++ -static-libgcc
endif
endef

define $(package)_config_cmds
  $($(package)_cmake) -S ../build -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

ifeq ($(host_os),mingw32)
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/bin && \
  cp i2pd.exe $($(package)_staging_dir)$(host_prefix)/bin/
endef
else
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/bin && \
  cp i2pd $($(package)_staging_dir)$(host_prefix)/bin/
endef
endif
