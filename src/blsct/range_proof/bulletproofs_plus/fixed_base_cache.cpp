// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/range_proof/bulletproofs_plus/fixed_base_cache.h>
#include <blsct/range_proof/setup.h>

#include <blsct/common.h>

#ifndef LIBBLSCT
#include <logging.h>
#include <util/time.h>
#endif

#include <cassert>
#include <mutex>
#include <vector>

namespace bulletproofs_plus {

FixedBaseCache& FixedBaseCache::Get()
{
    static FixedBaseCache instance;
    return instance;
}

void FixedBaseCache::MaybeInit(const range_proof::Generators<Blst>& gens)
{
    static std::once_flag once;
    std::call_once(once, [&] {
        // Latch: from here on the config statics are baked into the tables, so
        // the setters must refuse further changes (they assert on !s_latched).
        s_latched.store(true, std::memory_order_release);
        m_enabled = s_enabled;
        if (!m_enabled) return;

        m_winSize = s_winSize;
        if (m_winSize < 2 || m_winSize > 12) m_winSize = 8;

        // Clamp the prefix to the generator pool actually available.
        const size_t pool = range_proof::Setup::max_input_value_vec_len;
        size_t prefix = s_prefix;
        if (prefix > pool) prefix = pool;
        if (prefix > gens.Gi->Size()) prefix = gens.Gi->Size();
        if (prefix > gens.Hi->Size()) prefix = gens.Hi->Size();
        m_prefix = prefix;
        if (m_prefix == 0) { m_enabled = false; return; }

        // The whole build is inside try: a bad_alloc (the tables can be large)
        // escaping the call_once callable would leave the once-flag unset and
        // make every subsequent proof retry the same oversized allocation from
        // inside block validation. Failing closed disables the fast path once
        // and keeps the generic MSM.
#ifndef LIBBLSCT
        const auto build_start = SteadyClock::now();
#endif
        try {
            std::vector<BlstG1Point> gi, hi;
            gi.reserve(m_prefix);
            hi.reserve(m_prefix);
            for (size_t i = 0; i < m_prefix; ++i) {
                gi.push_back((*gens.Gi)[i]);
                hi.push_back((*gens.Hi)[i]);
            }
            m_gi = FixedBaseWindow(gi, m_winSize);
            m_hi = FixedBaseWindow(hi, m_winSize);
            m_gi_base0 = (*gens.Gi)[0];
#ifndef LIBBLSCT
            // Log the one-time lazy precompute so its cost shows up as itself
            // in the [bench] breakdown rather than a mystery spike on the first
            // block verified after startup. Skipped in the standalone libblsct
            // build, which does not link the node's logging (LogInstance).
            LogPrint(BCLog::BENCH, "blsct: fixed-base precompute prefix=%u win=%u in %.2fms\n",
                     (unsigned)m_prefix, (unsigned)m_winSize,
                     Ticks<std::chrono::duration<double, std::milli>>(SteadyClock::now() - build_start));
#endif
        } catch (const std::exception&) {
            m_enabled = false;
            m_prefix = 0;
            m_gi = FixedBaseWindow();
            m_hi = FixedBaseWindow();
        }
    });

    // The tables are built from the FIRST caller's generators and never
    // rebuilt. Correct today because Gi/Hi are seed-independent process
    // statics (only G varies per TokenId); assert the coupling so a future
    // seed-dependent generator change fails loudly instead of producing wrong
    // verdicts from stale tables.
    if (m_enabled) {
        assert(m_gi_base0 == (*gens.Gi)[0]);
    }
}

} // namespace bulletproofs_plus
