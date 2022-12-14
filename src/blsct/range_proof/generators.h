// Copyright (c) 2022 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_RANGE_PROOF_GENERATORS_H
#define NAVCOIN_BLSCT_RANGE_PROOF_GENERATORS_H

#include <boost/thread/lock_guard.hpp>
#include <boost/thread/mutex.hpp>

#include <blsct/arith/elements.h>
#include <blsct/arith/point.h>
#include <blsct/arith/scalar.h>
#include <blsct/range_proof/config.h>
#include <ctokens/tokenid.h>

template <typename PV>
struct Generators {
public:
    Generators(
        Point<PV>& H, Point<PV>& G, Points<PV>& Gi, Points<PV>& Hi
    ): H{H}, G{G}, Gi{Gi}, Hi{Hi} {}
    Points<PV> GetGiSubset(const size_t& size) const;
    Points<PV> GetHiSubset(const size_t& size) const;

    std::reference_wrapper<Point<PV>> H;
    Point<PV> G;

private:
    std::reference_wrapper<Points<PV>> Gi;
    std::reference_wrapper<Points<PV>> Hi;
};

/**
 * Dependent on token_id:
 * - G generator is derived from token_id
 *
 * Static:
 * - H generator points to the base point
 * - Gi and Hi generators are derived from the base point
 *   and the default token_id at initialization time
 *
 * Reason for assigning the base point to H:
 *
 * On the bulletproofs paper, G is used for amounts and H is used
 * for randomness. Our Bulletproofs code follows the convention for
 * readbility.
 *
 * Upon checking if a tx is valid, the total of the value commitments
 * of tx input and output are calculated. The total becomes zero when
 * the tx is valid and that clears the G term. The remaining term will
 * be H^Sum(randomness).
 *
 * By assigning the base point to H, we are making the remaining term
 * the public key whose private key is Sum(randomness). That will be
 * used later for signature verification.
 */
template <typename PV>
class GeneratorsFactory
{
public:
    GeneratorsFactory();
    Generators<PV> GetInstance(const TokenId& token_id);

private:
    Point<PV> DeriveGenerator(
        const Point<PV>& p,
        const size_t index,
        const TokenId& token_id
    );

    // G generators are cached
    inline static std::map<const TokenId, const Point<PV>> m_G_cache;

    // made optional to initialize values lazily after mcl initialization
    inline static std::optional<Point<PV>> m_H;
    inline static std::optional<Points<PV>> m_Gi;
    inline static std::optional<Points<PV>> m_Hi;

    inline static boost::mutex m_init_mutex;
    inline static bool m_is_initialized = false;
};

#endif // NAVCOIN_BLSCT_RANGE_PROOF_GENERATORS_H
