# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

add_library(navio_crypto STATIC EXCLUDE_FROM_ALL
  aes.cpp
  chacha20.cpp
  chacha20poly1305.cpp
  hkdf_sha256_32.cpp
  hmac_sha256.cpp
  hmac_sha512.cpp
  muhash.cpp
  pkcs5_pbkdf2.cpp
  poly1305.cpp
  ripemd160.cpp
  sha1.cpp
  sha256.cpp
  sha256_sse4.cpp
  sha3.cpp
  sha512.cpp
  siphash.cpp
)
target_link_libraries(navio_crypto
  PRIVATE
    core_interface
)

if(HAVE_SSE41)
  target_compile_definitions(navio_crypto PRIVATE ENABLE_SSE41)
  target_sources(navio_crypto PRIVATE sha256_sse41.cpp)
  set_property(SOURCE sha256_sse41.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS}
  )
endif()

if(HAVE_AVX2)
  target_compile_definitions(navio_crypto PRIVATE ENABLE_AVX2)
  target_sources(navio_crypto PRIVATE sha256_avx2.cpp)
  set_property(SOURCE sha256_avx2.cpp PROPERTY
    COMPILE_OPTIONS ${AVX2_CXXFLAGS}
  )
endif()

if(HAVE_SSE41 AND HAVE_X86_SHANI)
  target_compile_definitions(navio_crypto PRIVATE ENABLE_SSE41 ENABLE_X86_SHANI)
  target_sources(navio_crypto PRIVATE sha256_x86_shani.cpp)
  set_property(SOURCE sha256_x86_shani.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS} ${X86_SHANI_CXXFLAGS}
  )
endif()

if(HAVE_ARM_SHANI)
  target_compile_definitions(navio_crypto PRIVATE ENABLE_ARM_SHANI)
  target_sources(navio_crypto PRIVATE sha256_arm_shani.cpp)
  set_property(SOURCE sha256_arm_shani.cpp PROPERTY
    COMPILE_OPTIONS ${ARM_SHANI_CXXFLAGS}
  )
endif()
