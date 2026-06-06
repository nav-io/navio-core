package=zlib
$(package)_version=1.3.1
$(package)_download_path=https://github.com/madler/zlib/releases/download/v$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

define $(package)_set_vars
$(package)_config_env=CC="$($(package)_cc)" CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
$(package)_config_env+=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)"
$(package)_build_env=CC="$($(package)_cc)" CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
$(package)_build_env+=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)"
endef

# zlib's ./configure does not understand cross-compilation triplets; on mingw we
# build with its dedicated win32 GNU makefile instead. That makefile relies on
# make's builtin .c.o suffix rules, so clear MAKEFLAGS (depends sets
# --no-builtin-rules globally, which would otherwise leave the objects
# uncompiled and `ar` failing on missing .o files).
ifeq ($(host_os),mingw32)
define $(package)_build_cmds
  unset MAKEFLAGS && $(MAKE) -f win32/Makefile.gcc PREFIX="$(host)-" CC="$($(package)_cc)" AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CFLAGS="$($(package)_cflags) $($(package)_cppflags)" libz.a
endef
define $(package)_stage_cmds
  unset MAKEFLAGS && $(MAKE) -f win32/Makefile.gcc install DESTDIR="$($(package)_staging_dir)/" BINARY_PATH="$(host_prefix)/bin" INCLUDE_PATH="$(host_prefix)/include" LIBRARY_PATH="$(host_prefix)/lib"
endef
else
define $(package)_config_cmds
  ./configure --static --prefix=$(host_prefix)
endef
define $(package)_build_cmds
  $(MAKE) libz.a
endef
define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
endif

define $(package)_postprocess_cmds
  rm -rf share lib/pkgconfig
endef
