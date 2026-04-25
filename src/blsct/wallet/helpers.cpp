// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/eip_2333/bls12_381_keygen.h>
#include <blsct/wallet/helpers.h>
#include <random.h>

#include <atomic>
#include <thread>

namespace blsct {
uint64_t CalculateViewTag(const MclG1Point& blindingKey, const MclScalar& viewKey)
{
    HashWriter hash{};
    hash << (blindingKey * viewKey);

    return (hash.GetHash().GetUint64(0) & 0xFFFF);
}

std::vector<uint64_t> CalculateViewTagBatch(const std::vector<MclG1Point>& blindingKeys,
                                            const MclScalar& viewKey,
                                            size_t threads)
{
    const size_t n = blindingKeys.size();
    std::vector<uint64_t> tags(n);

    if (n < kViewTagBatchSerialThreshold) {
        for (size_t i = 0; i < n; ++i) {
            tags[i] = CalculateViewTag(blindingKeys[i], viewKey);
        }
        return tags;
    }

    if (threads == 0) {
        threads = std::thread::hardware_concurrency();
        if (threads == 0) threads = 1;
    }
    threads = std::min(threads, n);

    std::atomic<size_t> next{0};
    auto worker = [&]() {
        for (;;) {
            size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= n) return;
            tags[i] = CalculateViewTag(blindingKeys[i], viewKey);
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(threads - 1);
    for (size_t t = 1; t < threads; ++t) {
        pool.emplace_back(worker);
    }
    worker();
    for (auto& th : pool) th.join();

    return tags;
}

CKeyID CalculateHashId(const MclG1Point& blindingKey, const MclG1Point& spendingKey, const MclScalar& viewKey)
{
    auto t = blindingKey * viewKey;
    auto dh = MclG1Point::GetBasePoint() * t.GetHashWithSalt(0).Negate();
    auto D_prime = spendingKey + dh;

    return blsct::PublicKey(D_prime).GetID();
}

MclScalar CalculatePrivateSpendingKey(const MclG1Point& blindingKey, const MclScalar& viewKey, const MclScalar& spendingKey, const int64_t& account, const uint64_t& address)
{
    HashWriter string{};

    string << std::vector<unsigned char>(subAddressHeader.begin(), subAddressHeader.end());
    string << viewKey;
    string << account;
    string << address;

    MclG1Point t = blindingKey * viewKey;

    return t.GetHashWithSalt(0) + spendingKey + MclScalar(string.GetHash());
}

MclG1Point CalculateNonce(const MclG1Point& blindingKey, const MclScalar& viewKey)
{
    return blindingKey * viewKey;
}

SubAddress DeriveSubAddress(const PrivateKey& viewKey, const PublicKey& spendKey, const SubAddressIdentifier& subAddressId)
{
    return SubAddress(viewKey, spendKey, subAddressId);
}

MclScalar FromSeedToChildKey(const MclScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 130);
}

MclScalar FromChildToTransactionKey(const MclScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 0);
}

MclScalar FromChildToBlindingKey(const MclScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 1);
}

MclScalar FromChildToTokenKey(const MclScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 2);
}

MclScalar FromTransactionToViewKey(const MclScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 0);
}

MclScalar FromTransactionToSpendKey(const MclScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 1);
}

MclScalar GenRandomSeed()
{
    std::vector<unsigned char> seed(32);
    GetStrongRandBytes(seed);
    return BLS12_381_KeyGen::derive_master_SK(seed);
}
} // namespace blsct
