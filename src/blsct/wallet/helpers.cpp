// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/eip_2333/bls12_381_keygen.h>
#include <blsct/wallet/helpers.h>

#include <atomic>
#include <thread>

namespace blsct {
uint64_t ViewTagFromNonce(const BlstG1Point& nonce)
{
    HashWriter hash{};
    hash << nonce;

    return (hash.GetHash().GetUint64(0) & 0xFFFF);
}

uint64_t CalculateViewTag(const BlstG1Point& blindingKey, const BlstScalar& viewKey)
{
    return ViewTagFromNonce(blindingKey * viewKey);
}

std::vector<uint64_t> CalculateViewTagBatch(const std::vector<BlstG1Point>& blindingKeys,
                                            const BlstScalar& viewKey,
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

CKeyID CalculateHashId(const BlstG1Point& nonce, const BlstG1Point& spendingKey)
{
    auto dh = BlstG1Point::GetBasePoint() * nonce.GetHashWithSalt(0).Negate();
    auto D_prime = spendingKey + dh;

    return blsct::PublicKey(D_prime).GetID();
}

CKeyID CalculateHashId(const BlstG1Point& blindingKey, const BlstG1Point& spendingKey, const BlstScalar& viewKey)
{
    return CalculateHashId(blindingKey * viewKey, spendingKey);
}

BlstScalar CalculatePrivateSpendingKey(const BlstG1Point& blindingKey, const BlstScalar& viewKey, const BlstScalar& spendingKey, const int64_t& account, const uint64_t& address)
{
    HashWriter string{};

    string << std::vector<unsigned char>(subAddressHeader.begin(), subAddressHeader.end());
    string << viewKey;
    string << account;
    string << address;

    BlstG1Point t = blindingKey * viewKey;

    return t.GetHashWithSalt(0) + spendingKey + BlstScalar(string.GetHash());
}

BlstG1Point CalculateNonce(const BlstG1Point& blindingKey, const BlstScalar& viewKey)
{
    return blindingKey * viewKey;
}

SubAddress DeriveSubAddress(const PrivateKey& viewKey, const PublicKey& spendKey, const SubAddressIdentifier& subAddressId)
{
    return SubAddress(viewKey, spendKey, subAddressId);
}

BlstScalar FromSeedToChildKey(const BlstScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 130);
}

BlstScalar FromChildToTransactionKey(const BlstScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 0);
}

BlstScalar FromChildToBlindingKey(const BlstScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 1);
}

BlstScalar FromChildToTokenKey(const BlstScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 2);
}

BlstScalar FromTransactionToViewKey(const BlstScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 0);
}

BlstScalar FromTransactionToSpendKey(const BlstScalar& seed)
{
    return BLS12_381_KeyGen::derive_child_SK(seed, 1);
}

} // namespace blsct
