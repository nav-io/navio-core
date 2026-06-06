package=boost
$(package)_version = 1.90.0
$(package)_download_path = https://github.com/boostorg/boost/releases/download/boost-$($(package)_version)
$(package)_file_name = boost-$($(package)_version)-cmake.tar.gz
$(package)_sha256_hash = 913ca43d49e93d1b158c9862009add1518a4c665e7853b349a6492d158b036d4
$(package)_build_subdir = build

# i2pd needs these Boost components built as (static) libraries. Only add them
# when the bundled I2P router is enabled (NO_I2P unset), so non-I2P builds keep
# Boost header-only as before.
ifeq ($(NO_I2P),)
boost_i2p_libs = ;filesystem;program_options;atomic
endif

define $(package)_set_vars
  $(package)_config_opts = -DBOOST_INCLUDE_LIBRARIES="multi_index;test$(boost_i2p_libs)"
  $(package)_config_opts += -DBOOST_TEST_HEADERS_ONLY=ON
  $(package)_config_opts += -DBOOST_ENABLE_MPI=OFF
  $(package)_config_opts += -DBOOST_ENABLE_PYTHON=OFF
  $(package)_config_opts += -DBOOST_INSTALL_LAYOUT=system
  $(package)_config_opts += -DBUILD_TESTING=OFF
  $(package)_config_opts += -DCMAKE_DISABLE_FIND_PACKAGE_ICU=ON
  # Install to a unique path to prevent accidental inclusion via other dependencies' -I flags.
  $(package)_config_opts += -DCMAKE_INSTALL_INCLUDEDIR=$(package)/include
  # Building the compiled components for darwin needs install_name_tool; point
  # CMake at the depends-provided (llvm) one so its binutils detection succeeds.
  $(package)_config_opts_darwin += -DCMAKE_INSTALL_NAME_TOOL=$(host_INSTALL_NAME_TOOL)
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
