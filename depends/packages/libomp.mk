package=libomp
$(package)_version=17.0.6
$(package)_download_path=https://github.com/llvm/llvm-project/releases/download/llvmorg-$($(package)_version)
$(package)_file_name=openmp-$($(package)_version).src.tar.xz
$(package)_sha256_hash=74334cbb4dc8b73a768448a7561d5a3540404940b2267b1fb9813a6464b320de

# LLVM's openmp standalone build refers to ../cmake for shared LLVM CMake
# helpers (e.g. ExtendPath), so we also fetch the matching cmake module
# tarball and arrange it as a sibling directory of the openmp source tree
# inside the extract dir.
$(package)_cmake_utils_file_name=cmake-$($(package)_version).src.tar.xz
$(package)_cmake_utils_sha256_hash=807f069c54dc20cb47b21c1f6acafdd9c649f3ae015609040d6182cab01140f4
$(package)_extra_sources=$($(package)_cmake_utils_file_name)
# Fallback when GitHub is unavailable (502) and bitcoincore.org does not mirror the cmake subtree tarball (404).
# Same bytes as upstream; checksum above must remain valid.
$(package)_cmake_utils_gh_mirror_base=https://ghfast.top/https://github.com/llvm/llvm-project/releases/download/llvmorg-$($(package)_version)

# Build cmake out of the openmp/ subtree so that ${CMAKE_CURRENT_SOURCE_DIR}/../cmake
# inside openmp's CMakeLists.txt resolves to the LLVM cmake helpers we drop
# next to it.
$(package)_build_subdir=openmp

define $(package)_set_vars
  $(package)_config_opts := -DOPENMP_STANDALONE_BUILD=ON
  $(package)_config_opts += -DOPENMP_ENABLE_LIBOMPTARGET=OFF
  $(package)_config_opts += -DOPENMP_ENABLE_OMPT_TOOLS=OFF
  $(package)_config_opts += -DLIBOMP_ENABLE_SHARED=OFF
  $(package)_config_opts += -DLIBOMP_OMPT_SUPPORT=OFF
  $(package)_config_opts += -DLIBOMP_USE_HWLOC=OFF
  $(package)_config_opts += -DLIBOMP_INSTALL_ALIASES=ON
  $(package)_config_opts += -DCMAKE_INSTALL_LIBDIR=lib
  $(package)_config_opts += -DCMAKE_BUILD_TYPE=Release
  $(package)_config_opts += -DCMAKE_POSITION_INDEPENDENT_CODE=ON
endef

# Cross-compiling to macOS ($(host) != $(build)): host CC is a multi-word
# command starting with env (hosts/darwin.mk). CMake's ASM language then treats
# "env" as the compiler and prepends -I flags to it, failing with
# "env: invalid option -- 'I'".
# Emit a toolchain snippet that selects clang directly and mirrors darwin_CC's
# driver flags — Makefile cannot reliably pass spaced CMAKE_ASM_FLAGS in one -D.
ifneq ($(host),$(build))
ifeq ($(host_os),darwin)

define libomp_preprocess_cmds
	printf '%s\n' \
	  'set(CMAKE_ASM_COMPILER "$(build_prefix)/bin/clang")' \
	  'set(CMAKE_ASM_COMPILER_TARGET "$(host)")' \
	  'set(CMAKE_ASM_FLAGS "-B$(build_prefix)/bin -isysroot$(OSX_SDK) -nostdlibinc -iwithsysroot/usr/include -iframeworkwithsysroot/System/Library/Frameworks")' \
	  > $$(@D)/libomp_cross_asm.cmake || exit 1
endef

libomp_config_opts_darwin += -DCMAKE_TOOLCHAIN_FILE=../libomp_cross_asm.cmake

endif
endif

define $(package)_fetch_cmds
  $(call fetch_file,$(package),$($(package)_download_path),$($(package)_file_name),$($(package)_file_name),$($(package)_sha256_hash)) && \
  ( $(call fetch_file_inner,$(package),$($(package)_download_path),$($(package)_cmake_utils_file_name),$($(package)_cmake_utils_file_name),$($(package)_cmake_utils_sha256_hash)) || \
    $(call fetch_file_inner,$(package),$(FALLBACK_DOWNLOAD_PATH),$($(package)_cmake_utils_file_name),$($(package)_cmake_utils_file_name),$($(package)_cmake_utils_sha256_hash)) || \
    $(call fetch_file_inner,$(package),$($(package)_cmake_utils_gh_mirror_base),$($(package)_cmake_utils_file_name),$($(package)_cmake_utils_file_name),$($(package)_cmake_utils_sha256_hash)) )
endef

define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source_dir)/$($(package)_file_name)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_cmake_utils_sha256_hash)  $($(package)_source_dir)/$($(package)_cmake_utils_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  mkdir -p $($(package)_extract_dir)/openmp $($(package)_extract_dir)/cmake && \
  $(build_TAR) --no-same-owner --strip-components=1 -C $($(package)_extract_dir)/openmp -xf $($(package)_source_dir)/$($(package)_file_name) && \
  $(build_TAR) --no-same-owner --strip-components=1 -C $($(package)_extract_dir)/cmake -xf $($(package)_source_dir)/$($(package)_cmake_utils_file_name)
endef

define $(package)_config_cmds
  $($(package)_cmake) .
endef

define $(package)_build_cmds
  $(MAKE) omp
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
