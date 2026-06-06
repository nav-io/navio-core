package=tor
$(package)_version=0.4.9.9
$(package)_download_path=https://dist.torproject.org/
$(package)_file_name=tor-$($(package)_version).tar.gz
$(package)_sha256_hash=bd75ba7fd68f607c7806fcf70156a300aa926e9ad69a5e56a8e6414f5227e833
$(package)_dependencies=libevent openssl zlib

# Client-only Tor: no public-relay or dir-authority modules (smaller binary,
# less attack surface); onion services live in the client and are kept. The
# three deps are linked statically so the shipped `tor` binary only needs libc
# (plus the standard Win32 system DLLs on mingw).
define $(package)_set_vars
# depends' global CFLAGS pass -std=c11, which disables GNU keywords Tor relies
# on (typeof); -std=gnu11 (appended last) restores them and POSIX prototypes.
$(package)_cflags+=-std=gnu11
# Match naviod's static-link strategy: deps are linked static (below); on
# Windows go fully static (-static, like CMakeLists.txt's MINGW branch), on
# Linux bake in libgcc but keep glibc dynamic (NSS/DNS needs it), on macOS
# leave the system libs dynamic.
ifeq ($(host_os),mingw32)
$(package)_ldflags+=-static
else ifneq ($(host_os),darwin)
$(package)_ldflags+=-static-libgcc
endif
$(package)_config_opts=--disable-asciidoc --disable-manpage --disable-html-manual
$(package)_config_opts+=--disable-unittests --disable-system-torrc
$(package)_config_opts+=--disable-zstd --disable-lzma --disable-seccomp --disable-libscrypt
$(package)_config_opts+=--disable-module-relay --disable-module-dirauth
$(package)_config_opts+=--enable-static-libevent --with-libevent-dir=$(host_prefix)
$(package)_config_opts+=--enable-static-openssl --with-openssl-dir=$(host_prefix)
$(package)_config_opts+=--enable-static-zlib --with-zlib-dir=$(host_prefix)
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) src/app/tor
endef

ifeq ($(host_os),mingw32)
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/bin && \
  cp src/app/tor.exe $($(package)_staging_dir)$(host_prefix)/bin/
endef
else
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/bin && \
  cp src/app/tor $($(package)_staging_dir)$(host_prefix)/bin/
endef
endif
