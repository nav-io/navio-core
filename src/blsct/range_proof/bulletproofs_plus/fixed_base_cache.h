// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_RANGE_PROOF_BULLETPROOFS_PLUS_FIXED_BASE_CACHE_H
#define NAVIO_BLSCT_RANGE_PROOF_BULLETPROOFS_PLUS_FIXED_BASE_CACHE_H

#include <blsct/arith/blst/blst.h>
#include <blsct/building_block/fixed_base_window.h>
#include <blsct/range_proof/generators.h>

#include <atomic>
#include <cassert>
#include <cstddef>

namespace bulletproofs_plus {

// Process-wide, lazily-built window tables for a PREFIX of the range-proof
// generators Gi/Hi. The generators are process-wide immutable statics (see
// range_proof::GeneratorsFactory), so the tables are built exactly once and
// shared by every verifier.
//
// This is an experimental acceleration of the range-proof verification MSM. It
// is disabled by default and enabled only via environment variables so that the
// default consensus path is byte-for-byte unchanged:
//
//   NAVIO_BLSCT_FIXEDBASE=1           enable (default: off)
//   NAVIO_BLSCT_FIXEDBASE_WIN=<bits>  window size, default 8
//   NAVIO_BLSCT_FIXEDBASE_PREFIX=<n>  # of Gi (and Hi) generators to table, default 128
//
// When enabled, a proof whose aggregated length mn is <= the tabled prefix has
// its Gi/Hi multi-scalar terms computed from the tables; larger proofs and the
// disabled case fall back to the generic mulVecMT path. The windowed result is
// bit-identical to mulVecMT (EC addition is associative/commutative), so the
// consensus verdict is unchanged either way.
class FixedBaseCache
{
public:
    static FixedBaseCache& Get();

    // Process-wide configuration, read once by MaybeInit. Defaults are ON so
    // every consumer that never touches init.cpp's ArgsManager (libblsct.a,
    // bench_navio, test_navio, navio-wallet) still gets the fast path; init.cpp
    // only ever turns it OFF via -blsctfixedbase=0 or retunes prefix/window.
    // Must be set before the first MaybeInit (i.e. before the first block
    // verify), which init.cpp satisfies. Setting after MaybeInit has latched the
    // config would silently do nothing (the tables are already built), so the
    // setters assert the tables have not been latched yet -- a mis-ordered call
    // (a proof verified before init runs) fails loudly instead of quietly
    // ignoring the operator's -blsctfixedbase* flags.
    static void SetEnabled(bool on) { assert(!s_latched.load(std::memory_order_acquire)); s_enabled = on; }
    static void SetPrefix(size_t prefix) { assert(!s_latched.load(std::memory_order_acquire)); s_prefix = prefix; }
    static void SetWinSize(size_t win) { assert(!s_latched.load(std::memory_order_acquire)); s_winSize = win; }

    // Build the tables from `gens` on first call (no-op afterwards / when off).
    void MaybeInit(const range_proof::Generators<Blst>& gens);

    bool Enabled() const { return m_enabled; }
    // Largest mn for which the tables can serve a proof (0 when disabled).
    size_t Prefix() const { return m_prefix; }

    const FixedBaseWindow& Gi() const { return m_gi; }
    const FixedBaseWindow& Hi() const { return m_hi; }

private:
    FixedBaseCache() = default;

    // Config source (defaults ON); MaybeInit copies these into the resolved
    // per-instance state below.
    inline static bool s_enabled = true;
    inline static size_t s_prefix = 128;
    inline static size_t s_winSize = 8;
    // Set true when MaybeInit latches the config into the built tables. Guards
    // the setters against a too-late config change (see above).
    inline static std::atomic<bool> s_latched{false};

    bool m_enabled = false;
    size_t m_prefix = 0;
    size_t m_winSize = 8;
    FixedBaseWindow m_gi;
    FixedBaseWindow m_hi;
    // First tabled base, kept to assert the generators the tables were built
    // from still match the ones each verification passes in.
    BlstG1Point m_gi_base0;
};

} // namespace bulletproofs_plus

#endif // NAVIO_BLSCT_RANGE_PROOF_BULLETPROOFS_PLUS_FIXED_BASE_CACHE_H
