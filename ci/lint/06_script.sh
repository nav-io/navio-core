#!/usr/bin/env bash
#
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

set -ex

if [ -n "$LOCAL_BRANCH" ]; then
  # To faithfully recreate CI linting locally, specify all commits on the current
  # branch.
  COMMIT_RANGE="$(git merge-base HEAD master)..HEAD"
elif [ -n "$CIRRUS_PR" ]; then
  COMMIT_RANGE="HEAD~..HEAD"
  echo
  git log --no-merges --oneline "$COMMIT_RANGE"
  echo
  test/lint/commit-script-check.sh "$COMMIT_RANGE"
else
  COMMIT_RANGE="SKIP_EMPTY_NOT_A_PR"
fi
export COMMIT_RANGE

RUST_BACKTRACE=1 "${LINT_RUNNER_PATH}/test_runner"
