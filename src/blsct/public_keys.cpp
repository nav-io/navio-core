// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <atomic>
#include <blst.h>
#include <blsct/common.h>
#include <blsct/public_keys.h>
#include <iterator>
#include <tinyformat.h>

#include <cstring>
#include <thread>

namespace blsct {

PublicKey PublicKeys::Aggregate() const
{
    if (m_pks.size() == 0) throw std::runtime_error(strprintf("%s: Vector of public keys is empty", __func__));

    auto retPoint = PublicKey::Point();
    bool isZero = true;

    for (auto& pk : m_pks) {
        if (!pk.fValid)
            throw std::runtime_error(strprintf("%s: Vector of public keys has an invalid element", __func__));

        retPoint = isZero ? pk.GetG1Point() : retPoint + pk.GetG1Point();
        isZero = false;
    }

    return PublicKey(retPoint);
}

bool PublicKeys::VerifyBalanceBatch(const Signature& sig) const
{
    auto aggr_pk = Aggregate();
    return aggr_pk.CoreVerify(Common::BLSCTBALANCE, sig);
}

bool PublicKeys::CoreAggregateVerify(const std::vector<PublicKey::Message>& msgs, const Signature& sig) const
{
    assert(m_pks.size() == msgs.size());
    const size_t n = m_pks.size();
    if (n == 0) return false;

    // Find the largest message size and zero-pad every message to it. This
    // padding is consensus-critical: the historical verifier hashed each
    // message as a fixed-width buffer, so a message and the same message with
    // trailing zero bytes up to the batch width verify identically.
    auto msg_size = std::max_element(msgs.begin(), msgs.end(), [](const auto& a, const auto& b) {
                        return a.size() < b.size();
                    })->size();
    std::vector<uint8_t> padded(msg_size * n);
    for (size_t i = 0; i < n; ++i) {
        std::memcpy(&padded[i * msg_size], msgs[i].data(), msgs[i].size());
    }

    std::vector<blst_p1_affine> pks(n);
    for (size_t i = 0; i < n; ++i) pks[i] = m_pks[i].ToAffine();
    blst_p2_affine sig_aff{};
    blst_p2_to_affine(&sig_aff, &sig.m_data);

    // prod_i e(pk_i, H(m_i)) == e(G1, sig): one Miller loop per pair,
    // accumulated in per-thread pairing contexts (hash-to-G2 + Miller loop
    // dominate and parallelise perfectly), merged, then one final
    // exponentiation. An identity public key fails (BLST_PK_IS_INFINITY).
    size_t threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 1;
    threads = std::min(threads, n);

    const size_t ctx_words = blst_pairing_sizeof() / sizeof(uint64_t) + 1;
    std::vector<std::vector<uint64_t>> ctxs(threads, std::vector<uint64_t>(ctx_words));
    std::vector<std::atomic<bool>> oks(threads);
    auto work = [&](size_t t) {
        auto* ctx = reinterpret_cast<blst_pairing*>(ctxs[t].data());
        blst_pairing_init(ctx, /*hash_or_encode=*/true, reinterpret_cast<const byte*>(BLS_SIG_G2_DST), BLS_SIG_G2_DST_LEN);
        bool ok = true;
        for (size_t i = t; i < n; i += threads) {
            if (blst_pairing_aggregate_pk_in_g1(ctx, &pks[i], nullptr, &padded[i * msg_size], msg_size, nullptr, 0) != BLST_SUCCESS) {
                ok = false;
                break;
            }
        }
        blst_pairing_commit(ctx);
        oks[t].store(ok);
    };
    std::vector<std::thread> pool;
    pool.reserve(threads - 1);
    for (size_t t = 1; t < threads; ++t) pool.emplace_back(work, t);
    work(0);
    for (auto& th : pool) th.join();
    for (size_t t = 0; t < threads; ++t) {
        if (!oks[t].load()) return false;
    }
    auto* ctx = reinterpret_cast<blst_pairing*>(ctxs[0].data());
    for (size_t t = 1; t < threads; ++t) {
        if (blst_pairing_merge(ctx, reinterpret_cast<const blst_pairing*>(ctxs[t].data())) != BLST_SUCCESS) return false;
    }
    blst_fp12 gtsig{};
    blst_aggregated_in_g2(&gtsig, &sig_aff);
    return blst_pairing_finalverify(ctx, &gtsig);
}

bool PublicKeys::VerifyBatch(const std::vector<PublicKey::Message>& msgs, const Signature& sig, const bool& fVerifyTx) const
{
    if (m_pks.size() != msgs.size() || m_pks.size() == 0) {
        throw std::runtime_error(std::string(__func__) + strprintf(
            "Expected the same positive numbers of public keys and messages, but got: %ld public keys and %ld messages", m_pks.size(), msgs.size()));
    }
    std::vector<std::vector<uint8_t>> aug_msgs;
    aug_msgs.reserve(m_pks.size());
    auto msg = msgs.begin();
    for (auto pk = m_pks.begin(), end = m_pks.end(); pk != end; ++pk, ++msg) {
        if ((*msg == blsct::Common::BLSCTBALANCE || *msg == blsct::Common::BLSCTFEE) && fVerifyTx) {
            aug_msgs.push_back(*msg);
        } else {
            aug_msgs.push_back(pk->AugmentMessage(*msg));
        }
    }
    return CoreAggregateVerify(aug_msgs, sig);
}

} // namespace blsct
