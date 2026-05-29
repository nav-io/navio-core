// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/pow.h>

#include <hash.h>

#include <cstdlib>

namespace p2pmsg {

uint256 PoWHeader::Hash() const
{
    HashWriter hw;
    hw << *this;
    return hw.GetSHA256();
}

arith_uint256 TargetFromBits(uint32_t bits)
{
    arith_uint256 target = ~arith_uint256(0); // 2^256 - 1
    if (bits >= 256) return arith_uint256(0);
    target >>= bits;
    return target;
}

bool CheckPoW(const PoWHeader& header, uint32_t bits)
{
    const arith_uint256 target = TargetFromBits(bits);
    return UintToArith256(header.Hash()) <= target;
}

bool CheckStamp(const PoWHeader& header, uint32_t bits, int64_t now)
{
    const int64_t skew = std::abs(now - header.timestamp);
    if (skew > POW_TIMESTAMP_TOLERANCE_SECONDS) return false;
    return CheckPoW(header, bits);
}

uint64_t Grind(PoWHeader& header, uint32_t bits, uint64_t max_iters)
{
    const arith_uint256 target = TargetFromBits(bits);
    uint64_t attempts = 0;
    while (max_iters == 0 || attempts < max_iters) {
        ++attempts;
        if (UintToArith256(header.Hash()) <= target) return attempts;
        ++header.nonce;
    }
    return 0;
}

} // namespace p2pmsg
