#!/usr/bin/env bash
# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# In-container driver for the guix release build (see
# .github/workflows/guix.yml). Runs as root inside a Debian sid
# container: installs the distro guix, starts guix-daemon, authorizes the
# substitute servers, then runs ./contrib/guix/guix-build with a retry/clean
# loop. Not meant to be run on a developer host — use contrib/guix/guix-build
# directly there.
#
# Expects these to be set by the workflow:
#   GITHUB_WORKSPACE, HOSTS, SOURCES_PATH, BASE_CACHE, MAX_JOBS,
#   SDK_PATH (darwin only), ADDITIONAL_GUIX_TIMEMACHINE_FLAGS.

export LC_ALL=C
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# guix-build's prelude checks for these host tools (see
# contrib/guix/guix-build: `check_tools cat mkdir make getent curl git guix`).
# The minimal Debian base image is missing make + curl; coreutils, git and
# getent (libc-bin) are already present. passwd provides useradd/groupadd.
apt-get update
apt-get install -y --no-install-recommends \
    guix git make curl ca-certificates xz-utils passwd locales

# guix-daemon needs a pool of unprivileged build users. Debian's package
# does not create them in a minimal container (and without systemd it does
# not start guix-daemon either). Reuse an existing build-users group if the
# package made one, otherwise create the canonical `guixbuild` group + 10
# builder users, mirroring the official guix-install.sh.
group="$(getent group | awk -F: '/[Gg]uix/ {print $1; exit}')"
if [ -z "${group}" ]; then
    echo "No guix build-users group found; creating guixbuild + builders"
    groupadd --system guixbuild
    nologin_sh="$(command -v nologin || echo /usr/sbin/nologin)"
    for i in $(seq -w 1 10); do
        useradd -g guixbuild -G guixbuild -d /var/empty \
            -s "${nologin_sh}" --system "guixbuilder${i}" || true
    done
    group=guixbuild
fi
echo "guix build-users group: ${group}"
# Launch the daemon with a UTF-8 locale so its child substituter (guile)
# can decode non-ASCII bytes in store archives. The rest of this script
# (and prelude.bash / guix-build / build.sh) keeps LC_ALL=C for deterministic
# tool output — only the daemon and its descendants need UTF-8.
LC_ALL=C.UTF-8 LANG=C.UTF-8 guix-daemon --build-users-group="${group}" &

# Wait for the daemon socket to answer.
for _ in $(seq 1 30); do
    if guix gc --list-roots >/dev/null 2>&1; then break; fi
    sleep 1
done
guix --version

# Authorize the official substitute servers so we pull prebuilt store items
# instead of building the world. The distro ships the public keys under
# /usr/share/guix; tolerate absence (guix-build still works, just slower).
for key in \
    /usr/share/guix/ci.guix.gnu.org.pub \
    /usr/share/guix/bordeaux.guix.gnu.org.pub; do
    if [ -f "${key}" ]; then
        guix archive --authorize < "${key}" || true
    fi
done

# guix shell --container (used internally by guix-build for build isolation)
# spawns an inner user namespace that drops DAC_OVERRIDE, so it cannot
# traverse parent directories the runner created mode 750. Without this,
# guix-build dies with "guix shell: error: statfs: <workspace>: Permission
# denied" before it even starts. Add o+x to every ancestor of $HOME so the
# inner unprivileged user can walk to the workspace + caches + SDK.
p="${GITHUB_WORKSPACE}"
while [ "${p}" != "/" ] && [ -n "${p}" ]; do
    chmod o+x "${p}" 2>/dev/null || true
    p="$(dirname "${p}")"
done

# guix-build must run as the user that OWNS the bind-mounted worktree and
# caches (the GitHub runner, typically uid 1001), not as root. guix-build
# uses `guix shell --container` for isolation, which maps the invoking uid
# to inner-root via a single-uid user namespace. Invoked as root, the
# bind-mounted files (owned by the runner uid) are unmapped inside the
# container, so the depends build cannot create depends/work or BASE_CACHE
# subdirs ("mkdir: ... Permission denied"). Matching the owning uid makes
# those files inner-root-owned and writable.
host_uid="$(stat -c %u "${GITHUB_WORKSPACE}")"
host_gid="$(stat -c %g "${GITHUB_WORKSPACE}")"
echo "worktree owner uid:gid = ${host_uid}:${host_gid}"
if [ "${host_uid}" = "0" ]; then
    build_user=root
else
    getent group "${host_gid}" >/dev/null || groupadd -g "${host_gid}" builder
    # -m -d /home/builder: a fresh container-local home the build user owns,
    # so guix can mkdir ~/.cache/guix for the time-machine checkout. (Do NOT
    # reuse $HOME here — this script runs as root, so $HOME is /root, which
    # the unprivileged build user cannot write: guix then failed with
    # "guix time-machine: error: mkdir: Permission denied".) The worktree +
    # caches are reached by absolute path, not via HOME.
    getent passwd "${host_uid}" >/dev/null || \
        useradd -u "${host_uid}" -g "${host_gid}" -m -d /home/builder -s /bin/bash builder
    build_user="$(getent passwd "${host_uid}" | cut -d: -f1)"
fi
echo "running guix-build as: ${build_user}"

# Make the guix-daemon socket reachable by the (non-root) build user.
chmod -R a+rwX /var/guix/daemon-socket 2>/dev/null || true
# System-wide so the build user is not tripped by git's dubious-ownership
# check (harmless even when uid already matches).
git config --system --add safe.directory "${GITHUB_WORKSPACE}" || true

# Retry on transient `guix substitute` network failures (e.g. intermittent
# 'write_to_session_record_port' TLS pushes). Guix is incremental:
# previously-built derivations stay in /gnu/store and the depends
# SOURCES_PATH / BASE_CACHE survive across attempts, so a retry picks up
# where the failed attempt left off. guix-clean between attempts removes
# stale per-commit distsrc-* dirs (else guix-build aborts with "Build
# directories for this commit already exist") while preserving SDK,
# SOURCES_PATH, BASE_CACHE, and gc-root profiles.
#
# shellcheck disable=SC2016  # vars must expand inside the su'd shell, not here
build_loop='
cd "${GITHUB_WORKSPACE}"
for attempt in 1 2 3; do
    if ./contrib/guix/guix-build; then
        exit 0
    fi
    echo "guix-build attempt ${attempt} failed; sleeping 30s then retrying..."
    sleep 30
    ./contrib/guix/guix-clean || true
done
echo "guix-build failed after 3 attempts"
exit 1
'

if [ "${build_user}" = "root" ]; then
    bash -euo pipefail -c "${build_loop}"
else
    # su (non-login) preserves the HOSTS / SOURCES_PATH / BASE_CACHE /
    # SDK_PATH / MAX_JOBS / ADDITIONAL_GUIX_TIMEMACHINE_FLAGS / LC_ALL env
    # vars and sets HOME to the build user's home (= the runner $HOME, which
    # it owns, so guix's ~/.cache is writable).
    su "${build_user}" -s /bin/bash -c "set -euo pipefail; ${build_loop}"
fi
