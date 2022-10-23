// Copyright (c) 2022 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_ARITH_RANGE_PROOF_GENERATORS_H
#define NAVCOIN_BLSCT_ARITH_RANGE_PROOF_GENERATORS_H

#include <boost/thread/lock_guard.hpp>
#include <boost/thread/mutex.hpp>

#include <blsct/arith/elements.h>
#include <blsct/arith/g1point.h>
#include <blsct/arith/range_proof/config.h>
#include <blsct/arith/scalar.h>
#include <ctokens/tokenid.h>

struct Generators {
public:
    Generators(G1Point& G, G1Point&H, G1Points& Gi, G1Points& Hi): G{G}, H{H}, Gi{Gi}, Hi{Hi} {}
    G1Points GetGi() const;
    G1Points GetHi() const;
    G1Points GetGiSubset(const size_t& size) const;
    G1Points GetHiSubset(const size_t& size) const;

    std::reference_wrapper<G1Point> G;
    G1Point H;

private:
    std::reference_wrapper<G1Points> Gi;
    std::reference_wrapper<G1Points> Hi;
};

class GeneratorsFactory
{
public:
    GeneratorsFactory();
    Generators GetInstance(const TokenId& token_id);

private:
    G1Point GetGenerator(
        const G1Point& p,
        const size_t index,
        const TokenId& token_id
    );

    // H generator is created for each instance and cached
    inline static std::map<const TokenId, const G1Point> m_H_cache;

    // made optional to initialize values lazily after mcl initialization
    inline static std::optional<G1Point> m_G;
    inline static std::optional<G1Points> m_Gi;
    inline static std::optional<G1Points> m_Hi;

    inline static boost::mutex m_init_mutex;
    inline static bool m_is_initialized = false;
};

#endif // NAVCOIN_BLSCT_ARITH_RANGE_PROOF_GENERATORS_H