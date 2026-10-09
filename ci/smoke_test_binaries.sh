#!/usr/bin/env bash
# Copyright (c) 2026-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Smoke test: run -version on every built navio binary, and --version on the
# bundled i2pd router when the build has one.
#
# Catches load-time failures (missing rpath, unresolved runtime deps, ABI
# mismatches) that the unit / functional test suites can miss, because
# ctest only exercises test_navio — not the production naviod / navio-cli
# / navio-wallet / navio-staker / navio-tx / navio-util binaries.
#
# Cross-compile aware:
#   - If CMAKE_CROSSCOMPILING_EMULATOR is set (e.g. wine for the Win64
#     cross matrix entry), invoke each binary through it.
#   - If NAVIO_SMOKE_NO_EXEC is set (e.g. for the mac-cross matrix
#     entry on a Linux runner) or the target binary's format does not
#     match the host kernel, fall back to a `file` shape check so the
#     smoke step still asserts something useful without tripping
#     "Exec format error".
#   - Otherwise execute the binary directly.
#   - If NAVIO_SMOKE_REQUIRE_I2PD is set (builds with depends I2P=1), a
#     missing i2pd fails the run instead of being skipped.

export LC_ALL=C

set -euo pipefail

BUILD_DIR="${1:-build}"
BIN_DIR="${BUILD_DIR}/bin"
EMULATOR="${CMAKE_CROSSCOMPILING_EMULATOR:-}"
REQUIRE_I2PD="${NAVIO_SMOKE_REQUIRE_I2PD:-}"
NO_EXEC="${NAVIO_SMOKE_NO_EXEC:-}"

if [ ! -d "${BIN_DIR}" ]; then
  echo "::error::No ${BIN_DIR} directory — did the build run?"
  exit 1
fi

# Match a binary's format (via `file -b`) against the host kernel so we
# don't try to exec a Mach-O on Linux (the +x bit is set but the kernel
# returns ENOEXEC). Returns 0 if exec is safe, 1 otherwise.
host_kernel="$(uname -s)"
is_native_format() {
  local probe
  probe="$(file -b "$1" 2>/dev/null || true)"
  case "${host_kernel}" in
    Linux)        [[ "${probe}" == ELF* ]] ;;
    Darwin)       [[ "${probe}" == Mach-O* ]] ;;
    MINGW*|MSYS*|CYGWIN*) [[ "${probe}" == PE32* ]] ;;
    *) return 1 ;;
  esac
}

# Detect output suffix (.exe on mingw / MSVC builds, empty otherwise) by
# probing for naviod first since every navio config produces it (except
# libblsct-only / fuzz-only builds, which this script is not wired into).
suffix=""
for cand in naviod naviod.exe; do
  if [ -e "${BIN_DIR}/${cand}" ]; then
    case "${cand}" in *.exe) suffix=".exe" ;; esac
    break
  fi
done

# i2pd is the bundled I2P router, present only in builds made with depends
# I2P=1. It is not a navio binary and spells the flag --version.
binaries=(naviod navio-cli navio-tx navio-util navio-wallet navio-staker i2pd)
fail=0
ran=0

for base in "${binaries[@]}"; do
  bin="${BIN_DIR}/${base}${suffix}"
  if [ ! -e "${bin}" ]; then
    if [ "${base}" = i2pd ] && [ -n "${REQUIRE_I2PD}" ]; then
      echo "::error::${bin} missing from a build made with depends I2P=1"
      fail=1
      continue
    fi
    echo "skip: ${bin} not built"
    continue
  fi
  ran=$((ran + 1))
  flag="-version"
  [ "${base}" = i2pd ] && flag="--version"
  echo "::group::${base}${suffix} ${flag}"
  if [ -n "${EMULATOR}" ]; then
    if ! ${EMULATOR} "${bin}" "${flag}"; then
      echo "::error::${base}${suffix} ${flag} failed under ${EMULATOR}"
      fail=1
    fi
  elif [ -z "${NO_EXEC}" ] && [ -x "${bin}" ] && is_native_format "${bin}"; then
    if ! "${bin}" "${flag}"; then
      echo "::error::${base}${suffix} ${flag} failed"
      fail=1
    fi
  else
    # Non-runnable on this host (cross-compiled darwin Mach-O on Linux
    # with no emulator, or NAVIO_SMOKE_NO_EXEC set). Drop to a shape
    # check so the binary at least exists in a recognizable format.
    if ! file -b "${bin}"; then
      echo "::error::file probe failed for ${bin}"
      fail=1
    fi
  fi
  echo "::endgroup::"
done

if [ "${ran}" -eq 0 ]; then
  echo "::error::No navio binaries found in ${BIN_DIR}; nothing to smoke-test"
  exit 1
fi

exit "${fail}"
