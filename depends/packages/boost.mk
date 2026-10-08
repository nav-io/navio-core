package=boost
$(package)_version = 1.90.0
$(package)_download_path = https://github.com/boostorg/boost/releases/download/boost-$($(package)_version)
$(package)_file_name = boost-$($(package)_version)-cmake.tar.gz
$(package)_sha256_hash = 913ca43d49e93d1b158c9862009add1518a4c665e7853b349a6492d158b036d4
$(package)_build_subdir = build

# i2pd needs these Boost components built as (static) libraries. Only add them
# when the bundled I2P router is enabled (I2P=1), so other builds keep Boost
# header-only as before.
# These are every Boost library whose headers the compiled i2pd sources
# (libi2pd, libi2pd_client, i18n, daemon, Win32) include directly; filesystem,
# program_options, atomic and system are compiled, the rest header-only. Only
# the listed libraries and what they depend on are installed, so one missing
# here fails the i2pd build, though a system Boost on the build host can hide
# that. (shared_ptr.hpp comes from smart_ptr.) Recheck on every i2pd bump.
ifeq ($(I2P),1)
# These options are computed rather than written in this file, so they have to
# reach the package ID explicitly, or a header-only Boost cached by a non-I2P
# build would be reused here (and the reverse).
$(package)_build_id_options = I2P=1
boost_i2p_libs = ;filesystem;program_options;atomic;system;asio;algorithm;dynamic_bitset;lexical_cast;property_tree;smart_ptr;static_assert
# Asio's dependency closure drags in Boost.Context/Coroutine/Fiber, which have
# per-arch assembly that mis-detects on cross targets (picks i386 asm for arm).
# i2pd uses none of them (header-only Asio only), so exclude them.
boost_i2p_exclude = -DBOOST_EXCLUDE_LIBRARIES="context;coroutine;fiber"
# Building the compiled components for darwin needs install_name_tool/otool;
# point CMake at the depends-provided (llvm) ones so its binutils detection
# succeeds (the plain-named tools do not exist in the cross environment).
boost_i2p_darwin_opts = -DCMAKE_INSTALL_NAME_TOOL=$(host_INSTALL_NAME_TOOL) -DCMAKE_OTOOL=$(host_OTOOL)
endif

define $(package)_set_vars
  $(package)_config_opts = -DBOOST_INCLUDE_LIBRARIES="multi_index;test$(boost_i2p_libs)"
  $(package)_config_opts += $(boost_i2p_exclude)
  $(package)_config_opts += -DBOOST_TEST_HEADERS_ONLY=ON
  $(package)_config_opts += -DBOOST_ENABLE_MPI=OFF
  $(package)_config_opts += -DBOOST_ENABLE_PYTHON=OFF
  $(package)_config_opts += -DBOOST_INSTALL_LAYOUT=system
  $(package)_config_opts += -DBUILD_TESTING=OFF
  $(package)_config_opts += -DCMAKE_DISABLE_FIND_PACKAGE_ICU=ON
  # Install to a unique path to prevent accidental inclusion via other dependencies' -I flags.
  $(package)_config_opts += -DCMAKE_INSTALL_INCLUDEDIR=$(package)/include
  $(package)_config_opts_darwin = $(boost_i2p_darwin_opts)
endef

define $(package)_config_cmds
  $($(package)_cmake) -S .. -B .
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share
endef
