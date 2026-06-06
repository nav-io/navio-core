package=openssl
$(package)_version=3.0.20
$(package)_download_path=https://github.com/openssl/openssl/releases/download/openssl-$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=c80a01dfc70ece4dc21168932c37739042d404d46ccc81a5986dd75314ecda6f

# Static libssl/libcrypto for the bundled Tor daemon only; navio itself does not
# link OpenSSL. Kept minimal: no shared libs, no engines/tests/zlib.
define $(package)_set_vars
$(package)_config_env=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CC="$($(package)_cc)" CROSS_COMPILE=
# On mingw the openssl app builds a windres resource; set CROSS_COMPILE so
# OpenSSL finds the prefixed windres ($(host)-windres) rather than a bare one.
$(package)_config_env_mingw32=CROSS_COMPILE=$(host)-
$(package)_config_opts=no-shared no-dso no-engine no-tests no-zlib
$(package)_config_opts+=--prefix=$(host_prefix) --openssldir=$(host_prefix)/etc/openssl --libdir=lib
# depends' global CFLAGS pass -std=c11, which disables the `asm` keyword
# OpenSSL's bignum code needs and hides POSIX prototypes (usleep). Append
# -std=gnu11 last so it overrides the inherited -std=c11 (gnu11 also enables
# _DEFAULT_SOURCE, declaring usleep). clang 19 (darwin cross) promotes
# implicit-function-declaration / int-conversion to hard errors, which the
# older OpenSSL 3.0.20 sources trip; keep them as warnings so the build
# matches gcc's behaviour on the other hosts.
$(package)_config_opts+=$($(package)_cflags) $($(package)_cppflags) -std=gnu11
$(package)_config_opts+=-Wno-error=implicit-function-declaration -Wno-error=int-conversion
$(package)_config_opts_linux=-fPIC -Wa,--noexecstack
$(package)_config_opts_x86_64_linux=linux-x86_64
$(package)_config_opts_aarch64_linux=linux-aarch64
$(package)_config_opts_arm_linux=linux-armv4
# 32-bit needs libatomic for the 8-byte atomics used by the openssl app.
$(package)_config_opts_i686_linux=linux-x86 -latomic
$(package)_config_opts_riscv64_linux=linux64-riscv64
$(package)_config_opts_x86_64_mingw32=mingw64
$(package)_config_opts_i686_mingw32=mingw
$(package)_config_opts_x86_64_darwin=darwin64-x86_64-cc
$(package)_config_opts_arm64_darwin=darwin64-arm64-cc
endef

define $(package)_config_cmds
  ./Configure $($(package)_config_opts)
endef

# build_sw/install_sw skip docs and man pages (avoids needing pod2man).
define $(package)_build_cmds
  $(MAKE) build_sw
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install_sw
endef

define $(package)_postprocess_cmds
  rm -rf share etc bin lib/pkgconfig
endef
