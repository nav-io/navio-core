package=openssl
$(package)_version=3.5.9
$(package)_download_path=https://github.com/openssl/openssl/releases/download/openssl-$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

# Static libssl/libcrypto for the bundled i2pd router only; navio itself does
# not link OpenSSL. Kept minimal: no shared libs, no engines/tests/zlib. The 3.5
# LTS line also gives i2pd its post-quantum (ML-KEM) NTCP2/SSU2 transports,
# which it only enables when built against OpenSSL >= 3.5.0.
define $(package)_set_vars
$(package)_config_env=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CC="$($(package)_cc)" CROSS_COMPILE=
# On mingw the openssl app compiles a windres resource. Point RC at the
# prefixed windres directly (do NOT use CROSS_COMPILE: OpenSSL would also
# prepend it to the already-prefixed CC, doubling the prefix).
$(package)_config_env_mingw32=RC="$(host)-windres"
$(package)_config_opts=no-shared no-dso no-engine no-tests no-zlib
$(package)_config_opts+=--prefix=$(host_prefix) --openssldir=$(host_prefix)/etc/openssl --libdir=lib
# depends' global CFLAGS pass -std=c11, which disables the `asm` keyword
# OpenSSL's bignum code needs and hides POSIX prototypes (usleep). Append
# -std=gnu11 last so it overrides the inherited -std=c11 (gnu11 also enables
# _DEFAULT_SOURCE, declaring usleep). clang 19 (darwin cross) promotes
# implicit-function-declaration / int-conversion to hard errors, which the
# OpenSSL 3.0.x sources tripped; keep them as warnings so the build matches
# gcc's behaviour on the other hosts.
$(package)_config_opts+=$($(package)_cflags) $($(package)_cppflags) -std=gnu11
$(package)_config_opts+=-Wno-error=implicit-function-declaration -Wno-error=int-conversion
$(package)_config_opts_linux=-fPIC -Wa,--noexecstack
$(package)_config_opts_x86_64_linux=linux-x86_64
$(package)_config_opts_aarch64_linux=linux-aarch64
$(package)_config_opts_arm_linux=linux-armv4
$(package)_config_opts_i686_linux=linux-x86
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

# OpenSSL >= 3.3 also installs a CMake package config under lib/cmake. i2pd
# finds OpenSSL through CMake's FindOpenSSL module, so drop it with the
# pkg-config files rather than leave a second, unused discovery path.
define $(package)_postprocess_cmds
  rm -rf share etc bin lib/pkgconfig lib/cmake
endef
