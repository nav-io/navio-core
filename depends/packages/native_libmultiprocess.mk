package=native_libmultiprocess
$(package)_version=3c69d125a175084e4056ec9db8badb625e5f31d8
$(package)_download_path=https://github.com/bitcoin-core/libmultiprocess/archive
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=456c176eedffd1692f9b3a43bb5fe75b271d313e9d6e7a7eb82fee756763b397
$(package)_dependencies=native_capnp

define $(package)_config_cmds
  $($(package)_cmake) .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install-bin
endef
