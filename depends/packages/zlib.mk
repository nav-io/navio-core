package=zlib
$(package)_version=1.3.2
$(package)_download_path=https://github.com/madler/zlib/releases/download/v$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16

define $(package)_set_vars
$(package)_config_env=CC="$($(package)_cc)" CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
$(package)_config_env+=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)"
$(package)_build_env=CC="$($(package)_cc)" CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC"
$(package)_build_env+=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)"
endef

# zlib is linked into the i2pd binary that is shipped, so its license goes
# where that binary's third-party licenses are installed from.
zlib_stage_license = mkdir -p $($(package)_staging_dir)$(host_prefix)/share/i2pd/licenses && \
  cp LICENSE $($(package)_staging_dir)$(host_prefix)/share/i2pd/licenses/zlib-LICENSE.txt

# zlib's ./configure does not understand cross-compilation triplets; on mingw we
# build with its dedicated win32 GNU makefile instead. That makefile relies on
# make's builtin .c.o suffix rules, so clear MAKEFLAGS (depends sets
# --no-builtin-rules globally, which would otherwise leave the objects
# uncompiled and `ar` failing on missing .o files).
ifeq ($(host_os),mingw32)
define $(package)_build_cmds
  unset MAKEFLAGS && $(MAKE) -f win32/Makefile.gcc PREFIX="$(host)-" CC="$($(package)_cc)" AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CFLAGS="$($(package)_cflags) $($(package)_cppflags)" libz.a
endef
# Stage only the static lib + headers by hand; the makefile's `install` target
# also builds the DLL's resource via an unprefixed `windres`, which we neither
# have nor need.
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/lib $($(package)_staging_dir)$(host_prefix)/include && \
  cp libz.a $($(package)_staging_dir)$(host_prefix)/lib/ && \
  cp zlib.h zconf.h $($(package)_staging_dir)$(host_prefix)/include/ && \
  $(zlib_stage_license)
endef
else
define $(package)_config_cmds
  ./configure --static --prefix=$(host_prefix)
endef
define $(package)_build_cmds
  $(MAKE) libz.a
endef
define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install && \
  $(zlib_stage_license)
endef
endif

define $(package)_postprocess_cmds
  rm -rf share/man lib/pkgconfig
endef
