// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/range_proof/bulletproofs_plus/fixed_base_cache.h>
#include <blsct/range_proof/setup.h>

#include <cassert>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

namespace bulletproofs_plus {

namespace {
// Locale-independent decimal parse of an env var (avoids strtoull, which the
// locale-dependence lint bans). Returns `def` on empty/non-numeric input.
size_t EnvSize(const char* name, size_t def)
{
    const char* v = std::getenv(name);
    if (!v || !*v) return def;
    size_t n = 0;
    for (const char* p = v; *p; ++p) {
        if (*p < '0' || *p > '9') return def;
        // Reject rather than wrap on absurd input; both consumers clamp to
        // small ranges anyway.
        if (n > 1000000) return def;
        n = n * 10 + static_cast<size_t>(*p - '0');
    }
    return n;
}
} // namespace

FixedBaseCache& FixedBaseCache::Get()
{
    static FixedBaseCache instance;
    return instance;
}

void FixedBaseCache::MaybeInit(const range_proof::Generators<Blst>& gens)
{
    static std::once_flag once;
    std::call_once(once, [&] {
        const char* on = std::getenv("NAVIO_BLSCT_FIXEDBASE");
        m_enabled = on && std::string(on) == "1";
        if (!m_enabled) return;

        m_winSize = EnvSize("NAVIO_BLSCT_FIXEDBASE_WIN", 8);
        if (m_winSize < 2 || m_winSize > 12) m_winSize = 8;

        // Clamp the prefix to the generator pool actually available.
        const size_t pool = range_proof::Setup::max_input_value_vec_len;
        size_t prefix = EnvSize("NAVIO_BLSCT_FIXEDBASE_PREFIX", 128);
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
