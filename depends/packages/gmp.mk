package=gmp
$(package)_version=6.3.0
$(package)_download_path=https://mirrors.kernel.org/gnu/gmp/
$(package)_file_name=gmp-$($(package)_version).tar.xz
$(package)_sha256_hash=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898

define $(package)_set_vars
$(package)_config_opts=--enable-cxx --with-pic --disable-shared
$(package)_config_opts+=--disable-dependency-tracking
# --enable-fat enables x86 runtime CPU dispatching; reject by gmp on non-x86.
# Skip under MSan: __gmpn_cpuvec_init reads uninitialized scratch in
# mpn/fat.c, which trips MSan's use-of-uninitialized-value check before
# the source-path blacklist can intercept it (relative compile paths in
# depends do not match absolute glob patterns).
ifeq (,$(findstring sanitize=memory,$(CFLAGS) $(CXXFLAGS)))
$(package)_config_opts_x86_64=--enable-fat
$(package)_config_opts_i686=--enable-fat
endif
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub .
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share lib/pkgconfig
endef
