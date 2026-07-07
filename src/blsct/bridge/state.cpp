// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/bridge/state.h>

namespace nbp {

namespace {

enum KeyKind : uint8_t {
    KEY_GUARDIAN_SET = 'G',
    KEY_DEPOSIT = 'D',
    KEY_MINT_OUT = 'M',
    KEY_EPOCH_PEGOUTS = 'E',
    KEY_COMMITTEE = 'P',
    KEY_CHECKPOINT = 'K',
    KEY_SPP_TAG = 'S',
    KEY_TOKEN_AGG = 'A',
};

std::vector<unsigned char> MakeKey(uint8_t kind)
{
    return {kind};
}

std::vector<unsigned char> MakeKey(uint8_t kind, const uint256& id)
{
    std::vector<unsigned char> key;
    key.reserve(1 + 32);
    key.push_back(kind);
    key.insert(key.end(), id.begin(), id.end());
    return key;
}

std::vector<unsigned char> MakeKey(uint8_t kind, uint64_t id)
{
    std::vector<unsigned char> key;
    key.reserve(1 + 8);
    key.push_back(kind);
    for (int i = 7; i >= 0; --i) {
        key.push_back(static_cast<unsigned char>((id >> (8 * i)) & 0xff));
    }
    return key;
}

} // namespace

std::vector<unsigned char> KeyGuardianSet() { return MakeKey(KEY_GUARDIAN_SET); }
std::vector<unsigned char> KeyDeposit(const uint256& depositId) { return MakeKey(KEY_DEPOSIT, depositId); }
std::vector<unsigned char> KeyMintOut(const uint256& outHash) { return MakeKey(KEY_MINT_OUT, outHash); }
std::vector<unsigned char> KeyEpochPegOuts(uint64_t epoch) { return MakeKey(KEY_EPOCH_PEGOUTS, epoch); }
std::vector<unsigned char> KeyCommittee(uint64_t period) { return MakeKey(KEY_COMMITTEE, period); }
std::vector<unsigned char> KeyCheckpoint(uint64_t epoch) { return MakeKey(KEY_CHECKPOINT, epoch); }

std::vector<unsigned char> KeySppTag(uint64_t period, const uint256& tag)
{
    auto key = MakeKey(KEY_SPP_TAG, period);
    key.insert(key.end(), tag.begin(), tag.end());
    return key;
}

std::vector<unsigned char> KeyTokenAggregate(const uint256& tokenId) { return MakeKey(KEY_TOKEN_AGG, tokenId); }

} // namespace nbp
