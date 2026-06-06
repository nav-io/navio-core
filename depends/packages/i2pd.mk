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
$(package)_config_opts+=-DWITH_STATIC=OFF -DBUILD_SHARED_LIBS=OFF
$(package)_config_opts+=-DBoost_USE_STATIC_LIBS=ON -DOPENSSL_USE_STATIC_LIBS=ON
$(package)_config_opts+=-DCMAKE_PREFIX_PATH=$(host_prefix)
$(package)_config_opts+=-DCMAKE_FIND_ROOT_PATH=$(host_prefix)
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
