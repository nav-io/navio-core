#!/usr/bin/env python3
"""
Two checks for libblsct.a:

1. Reachability — every object file in the archive must be reachable from
   the public API entry point (blsct/external_api/blsct.cpp).

2. Undefined symbols — every strong undefined symbol in the archive must be
   satisfied by one of:
     a) another object in the archive itself,
     b) a provided dependency archive (BLS, MCL, secp256k1, univalue, …), or
     c) a known system/stdlib symbol (libc, libstdc++, pthreads, C++ ABI, …).

   Anything that falls outside those three categories is a navio-internal
   symbol that leaked in and will cause a link/load failure for consumers
   of the library.

Usage:
    libblsct-symbol-check.py <libblsct.a> [dep1.a dep2.a ...]

Exit code: 0 if all checks pass, 1 otherwise.
"""

import subprocess
import sys
import re

# ---------------------------------------------------------------------------
# Patterns that identify symbols provided by the system (libc, libstdc++,
# pthreads, C++ ABI runtime, linker internals, etc.).  Anything matching one
# of these is allowed to remain unsatisfied by the archives.
# ---------------------------------------------------------------------------
SYSTEM_SYMBOL_PATTERNS = [
    # C++ stdlib mangled names (libstdc++ and libc++)
    # _ZNSt / _ZNKSt — libstdc++ std:: namespace
    # _ZNS[a-z] — Itanium ABI standard substitutions (So=ostream, Sd=iostream, …)
    # _ZNSt3__1 — libc++ std::__1 namespace
    re.compile(r'^_ZNK?S[a-z]'),
    re.compile(r'^_ZNK?St3__1'),    # libc++ std::__1::
    # __gnu_cxx / __cxxabiv1 / __exception_ptr namespaces
    re.compile(r'^_ZNK?(9__gnu_cxx|10__cxxabiv1|14__exception_ptr)'),
    re.compile(r'^_ZSt'),       # std:: standalone (operators, globals, templates)
    re.compile(r'^_ZTI'),       # typeinfo
    re.compile(r'^_ZTV'),       # vtable
    re.compile(r'^_ZTT'),       # VTT (virtual table table)
    re.compile(r'^_ZTs'),       # typeinfo name
    re.compile(r'^_ZTh'),       # non-virtual thunk
    re.compile(r'^_ZTv'),       # virtual thunk
    # C++ ABI / exception runtime
    re.compile(r'^__cxa_'),
    re.compile(r'^__gxx_'),
    re.compile(r'^_Unwind_'),
    re.compile(r'^_ITM_'),
    # Thread-local storage / linker internals
    re.compile(r'^__tls_get_addr$'),
    re.compile(r'^_GLOBAL_OFFSET_TABLE_$'),
    re.compile(r'^__dso_handle$'),
    # POSIX threads
    re.compile(r'^pthread_'),
    # secp256k1 — always a separate mandatory dep for consumers
    re.compile(r'^secp256k1_'),
    # C runtime / glibc internals (double-underscore prefix)
    re.compile(r'^__'),
    # Common C library functions
    re.compile(r'^(abort|exit|free|malloc|calloc|realloc|'
               r'memcpy|memmove|memset|memchr|memcmp|bcmp|'
               r'strlen|strcmp|strncmp|strcpy|strncpy|strcat|strncat|'
               r'strncasecmp|strcasecmp|'
               r'printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|'
               r'fwrite|fread|fopen|fclose|fflush|puts|fputs|fputc|putchar|'
               r'stderr|stdout|stdin|'
               r'mlock|munlock|mmap|munmap|madvise|'
               r'getrlimit|sysconf|nanosleep|gmtime_r|'
               r'log2|log2f|log|exp|sqrt|'
               r'strcmp|strlen)$'),
    # C++ operator new/delete
    re.compile(r'^_Znw|^_Zna|^_Zdl|^_Zda'),
]


def is_system_symbol(sym: str) -> bool:
    return any(p.match(sym) for p in SYSTEM_SYMBOL_PATTERNS)


def get_archive_symbols(archive: str) -> tuple[set, set]:
    """Return (defined, undefined) symbol sets for an archive. Skips missing files."""
    import os
    if not os.path.isfile(archive):
        return set(), set()
    result = subprocess.run(
        ["nm", "-A", archive], text=True, capture_output=True
    )
    if result.returncode != 0:
        return set(), set()
    defined: set = set()
    undefined: set = set()
    for line in result.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        rest = parts[2].strip().split()
        if len(rest) < 2:
            continue
        typ, sym = rest[-2], rest[-1]
        if typ in ("T", "t", "W", "w", "B", "b", "D", "d", "R", "r"):
            defined.add(sym)
        elif typ == "U":
            undefined.add(sym)
    return defined, undefined


def get_member_symbols(archive: str) -> tuple[dict, dict, list]:
    """Parse nm -A output into per-member defined/undefined symbol maps."""
    out = subprocess.check_output(
        ["nm", "-A", archive], text=True, stderr=subprocess.DEVNULL
    )
    member_defined: dict = {}
    member_refs: dict = {}
    member_order: list = []
    member_counts: dict = {}
    current_members: dict = {}

    for line in out.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        member = parts[1]
        rest = parts[2].strip().split()
        if len(rest) < 2:
            continue
        typ, sym = rest[-2], rest[-1]

        if member not in current_members:
            n = member_counts.get(member, 0)
            member_counts[member] = n + 1
            key = (member, n)
            current_members[member] = key
            member_defined[key] = set()
            member_refs[key] = set()
            member_order.append(key)
        else:
            key = current_members[member]

        if typ in ("T", "t", "W", "w", "B", "b", "D", "d", "R", "r"):
            member_defined[key].add(sym)
        elif typ == "U":
            member_refs[key].add(sym)

    return member_defined, member_refs, member_order


def check_reachability(archive: str) -> list[str]:
    """Return list of unreachable object names (empty = pass)."""
    member_defined, member_refs, member_order = get_member_symbols(archive)

    sym_to_members: dict = {}
    for key, syms in member_defined.items():
        for s in syms:
            sym_to_members.setdefault(s, []).append(key)

    root_keys = [k for k in member_order if k[0] == "libblsct_a-blsct.o"]
    if not root_keys:
        raise SystemExit("ERROR: 'libblsct_a-blsct.o' not found in archive")

    visited: set = set()
    queue = list(root_keys)
    while queue:
        key = queue.pop()
        if key in visited:
            continue
        visited.add(key)
        for sym in member_refs.get(key, set()):
            for defining_key in sym_to_members.get(sym, []):
                if defining_key not in visited:
                    queue.append(defining_key)

    return sorted(name for name, _ in set(member_order) - visited)


def check_undefined(archive: str, dep_archives: list[str]) -> list[str]:
    """Return list of unsatisfied undefined symbols (empty = pass)."""
    # Collect all defined symbols: main archive + all dep archives
    all_defined: set = set()
    archive_defined, archive_undefined = get_archive_symbols(archive)
    all_defined |= archive_defined

    for dep in dep_archives:
        dep_defined, _ = get_archive_symbols(dep)
        all_defined |= dep_defined

    # Unsatisfied = undefined in main archive, not defined anywhere, not system
    unsatisfied = [
        sym for sym in archive_undefined
        if sym not in all_defined and not is_system_symbol(sym)
    ]

    # Demangle for readable output
    if unsatisfied:
        demangled = subprocess.check_output(
            ["c++filt"] + unsatisfied, text=True
        ).splitlines()
        return sorted(demangled)
    return []


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <libblsct.a> [dep1.a ...]", file=sys.stderr)
        return 1

    archive = sys.argv[1]
    dep_archives = sys.argv[2:]

    failed = False

    # Check 1: reachability
    unreachable = check_reachability(archive)
    if unreachable:
        print(f"FAIL [reachability]: {len(unreachable)} unreachable object(s) in {archive}:")
        for name in unreachable:
            print(f"  {name}")
        print("  → Remove their sources from libblsct_a_SOURCES / BLSCT_EXTERNAL_CPP in src/Makefile.am.")
        failed = True
    else:
        print(f"OK [reachability]: all objects reachable from public API.")

    # Check 2: undefined symbols
    unsatisfied = check_undefined(archive, dep_archives)
    if unsatisfied:
        print(f"FAIL [undefined]: {len(unsatisfied)} symbol(s) not satisfied by archive or known deps:")
        for sym in unsatisfied:
            print(f"  {sym}")
        print("  → Either include the source in libblsct_a_SOURCES or move it out of BLSCT_EXTERNAL_CPP.")
        failed = True
    else:
        print(f"OK [undefined]: all symbols satisfied by archive + {len(dep_archives)} dep archive(s).")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
