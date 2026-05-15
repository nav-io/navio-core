package=boost
$(package)_version=1.81.0
# JFrog CDN is retired; Boost hosts releases on archives.boost.io.
$(package)_download_path=https://archives.boost.io/release/$($(package)_version)/source/
$(package)_file_name=boost_$(subst .,_,$($(package)_version)).tar.bz2
$(package)_sha256_hash=71feeed900fbccca04a3b4f2f84a7c217186f28a940ed8b7ed4725986baf99fa
$(package)_patches=process_macos_sdk.patch

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/process_macos_sdk.patch
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include && \
  cp -r boost $($(package)_staging_prefix_dir)/include && \
  mkdir -p $($(package)_staging_prefix_dir)/lib/cmake/Boost-$($(package)_version) && \
  printf '%s\n' \
    'set(Boost_FOUND TRUE)' \
    'set(Boost_VERSION $($(package)_version))' \
    'set(Boost_VERSION_STRING $($(package)_version))' \
    'get_filename_component(_boost_prefix "$$$${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)' \
    'if(NOT TARGET Boost::headers)' \
    '  add_library(Boost::headers INTERFACE IMPORTED)' \
    '  set_target_properties(Boost::headers PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "$$$${_boost_prefix}/include")' \
    'endif()' \
    'unset(_boost_prefix)' \
    'set(boost_headers_DIR "$$$${CMAKE_CURRENT_LIST_DIR}")' \
    > $($(package)_staging_prefix_dir)/lib/cmake/Boost-$($(package)_version)/BoostConfig.cmake && \
  printf '%s\n' \
    'set(PACKAGE_VERSION $($(package)_version))' \
    'if(PACKAGE_FIND_VERSION VERSION_LESS_EQUAL PACKAGE_VERSION)' \
    '  set(PACKAGE_VERSION_COMPATIBLE TRUE)' \
    '  if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)' \
    '    set(PACKAGE_VERSION_EXACT TRUE)' \
    '  endif()' \
    'endif()' \
    > $($(package)_staging_prefix_dir)/lib/cmake/Boost-$($(package)_version)/BoostConfigVersion.cmake
endef
