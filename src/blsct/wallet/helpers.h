// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_HELPERS_H
#define NAVIO_BLSCT_WALLET_HELPERS_H

#include <blsct/arith/blst/blst.h>
#include <blsct/public_key.h>
#include <blsct/wallet/address.h>
#include <hash.h>
#include <pubkey.h>

#include <vector>

namespace blsct {
uint64_t CalculateViewTag(const BlstG1Point& blindingKey, const BlstScalar& viewKey);

// Threaded batch variant. Computes CalculateViewTag for each blindingKey in `blindingKeys`
// against the shared `viewKey` in parallel. Thread count defaults to
// std::thread::hardware_concurrency(); pass an explicit `threads` to cap.
// For small batches (< kViewTagBatchSerialThreshold) falls back to the serial loop
// to avoid thread-spawn overhead.
std::vector<uint64_t> CalculateViewTagBatch(const std::vector<BlstG1Point>& blindingKeys,
                                            const BlstScalar& viewKey,
                                            size_t threads = 0);

inline constexpr size_t kViewTagBatchSerialThreshold = 16;
// The nonce (blindingKey * viewKey) is the expensive shared intermediate of
// the ownership test: the view tag, the hash id and amount recovery all
// derive from it. These variants take a precomputed nonce so a caller can pay
// the G1 scalar multiplication once per output and reuse it.
uint64_t ViewTagFromNonce(const BlstG1Point& nonce);
CKeyID CalculateHashId(const BlstG1Point& nonce, const BlstG1Point& spendingKey);
CKeyID CalculateHashId(const BlstG1Point& blindingKey, const BlstG1Point& spendingKey, const BlstScalar& viewKey);
BlstScalar CalculatePrivateSpendingKey(const BlstG1Point& blindingKey, const BlstScalar& viewKey, const BlstScalar& spendingKey, const int64_t& account, const uint64_t& address);
BlstG1Point CalculateNonce(const BlstG1Point& blindingKey, const BlstScalar& viewKey);
SubAddress DeriveSubAddress(const PrivateKey& viewKey, const PublicKey& spendKey, const SubAddressIdentifier& subAddressId);
BlstScalar FromSeedToChildKey(const BlstScalar& seed);
BlstScalar FromChildToTransactionKey(const BlstScalar& seed);
BlstScalar FromChildToBlindingKey(const BlstScalar& seed);
BlstScalar FromChildToTokenKey(const BlstScalar& seed);
BlstScalar FromTransactionToViewKey(const BlstScalar& seed);
BlstScalar FromTransactionToSpendKey(const BlstScalar& seed);
} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_HELPERS_H
