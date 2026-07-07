// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/bridge/logic.h>

#include <blsct/bridge/epoch.h>
#include <blsct/bridge/merkle.h>
#include <blsct/bridge/messages.h>
#include <blsct/bridge/predicates.h>
#include <blsct/public_keys.h>
#include <blsct/tokens/predicate_parser.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <primitives/block.h>
#include <chain.h>
#include <consensus/amount.h>
#include <util/strencodings.h>

#include <algorithm>

namespace nbp {

namespace {

//! Mock stake-participation proof marker (IMPLEMENTATION.md P1). Real SPP
//! verification (SetMemProof ring + aggregated BP+ over the staked set) is
//! prototype debt; the verify entrypoint is here so the call path does not
//! change when it lands.
const std::vector<unsigned char> MOCK_SPP{0x01};

std::vector<unsigned char> DstMessage(const std::string& dst, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> msg;
    msg.reserve(dst.size() + payload.size());
    msg.insert(msg.end(), dst.begin(), dst.end());
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}

std::vector<unsigned char> PopMessage(const std::vector<unsigned char>& pk)
{
    return DstMessage(DST_POP, pk);
}

std::vector<unsigned char> ExitMessage(const std::vector<unsigned char>& pk)
{
    static const std::string action{"exit"};
    std::vector<unsigned char> payload(action.begin(), action.end());
    payload.insert(payload.end(), pk.begin(), pk.end());
    return DstMessage(DST_POP, payload);
}

//! The withdraw signature cannot cover the carrying output's hash (the
//! predicate containing the signature is part of that hash), so it binds
//! the destination script and amount directly.
std::vector<unsigned char> WithdrawMessage(const std::vector<unsigned char>& pk, const CTxOut& out)
{
    static const std::string action{"withdraw"};
    std::vector<unsigned char> payload(action.begin(), action.end());
    payload.insert(payload.end(), pk.begin(), pk.end());
    uint256 scriptHash;
    CSHA256().Write(out.scriptPubKey.data(), out.scriptPubKey.size()).Finalize(scriptHash.begin());
    payload.insert(payload.end(), scriptHash.begin(), scriptHash.end());
    const uint64_t v = static_cast<uint64_t>(out.nValue);
    for (int i = 0; i < 8; i++) payload.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
    return DstMessage(DST_POP, payload);
}

std::vector<unsigned char> ChallengeMessage(const uint256& depositId)
{
    static const std::string action{"challenge"};
    std::vector<unsigned char> payload(action.begin(), action.end());
    payload.insert(payload.end(), depositId.begin(), depositId.end());
    return DstMessage(DST_RES, payload);
}

//! Keep a tokens-DB entry in sync with the bridge supply so ordinary
//! wallet/token RPCs can see and transfer wrapped assets. The bridge's own
//! accounting (TokenAggregate) stays authoritative for consensus checks.
void AdjustBridgeTokenSupply(CCoinsViewCache& view, const uint256& tokenHash, uint64_t ethChainId,
                             const std::vector<unsigned char>& token, CAmount delta)
{
    blsct::TokenEntry entry;
    if (!view.GetToken(tokenHash, entry)) {
        blsct::TokenInfo info;
        info.type = blsct::TOKEN;
        info.publicKey = blsct::PublicKey(MclG1Point::GetBasePoint());
        info.nTotalSupply = MAX_MONEY;
        info.mapMetadata["nbp"] = "bridge";
        info.mapMetadata["eth_chain_id"] = std::to_string(ethChainId);
        info.mapMetadata["erc20"] = HexStr(token);
        entry = blsct::TokenEntry{info};
    }
    entry.Mint(delta);
    view.AddToken(uint256{tokenHash}, std::move(entry));
}

uint256 ComputeClaimCommit(const blsct::DoublePublicKey& dpk, const uint256& r)
{
    const auto dpkVch = dpk.GetVch();
    uint256 out;
    CSHA256 hasher;
    hasher.Write(dpkVch.data(), dpkVch.size());
    hasher.Write(r.begin(), 32);
    hasher.Finalize(out.begin());
    return out;
}

bool RequireActive(const PredicateContext& ctx, std::string& err)
{
    if (ctx.params == nullptr || !ctx.params->nbp.IsActive(ctx.height) || ctx.out == nullptr) {
        err = "nbp-inactive";
        return false;
    }
    return true;
}

CAmount ReporterReward(CAmount bond) { return bond / 10; }

// --- guardian registry -----------------------------------------------------

bool ExecGuardianRegister(const GuardianRegisterPredicate& p, CCoinsViewCache& view,
                          const PredicateContext& ctx, std::string& err)
{
    const auto pk = p.guardianKey.GetVch();

    GuardianSet gs;
    GetState(view, KeyGuardianSet(), gs);

    if (ctx.fDisconnect) {
        gs.members.erase(pk);
        SetState(view, KeyGuardianSet(), gs);
        return true;
    }

    if (!p.guardianKey.IsValid()) {
        err = "nbp-bad-guardian-key";
        return false;
    }
    if (gs.members.count(pk)) {
        err = "nbp-guardian-exists";
        return false;
    }
    if (!p.guardianKey.Verify(PopMessage(pk), p.proofOfPossession)) {
        err = "nbp-bad-pop";
        return false;
    }
    // Bond output: transparent value >= MIN_BOND, provably unspendable so
    // the bond is escrowed by burning (refunded later via the withdraw
    // pseudo-input path).
    if (!ctx.out->scriptPubKey.IsUnspendable() || ctx.out->nValue < ctx.params->nbp.minBond ||
        !MoneyRange(ctx.out->nValue)) {
        err = "nbp-bad-bond";
        return false;
    }
    if (p.sppBlob != MOCK_SPP) {
        // Real SPP verification is not implemented in the prototype.
        err = "nbp-spp-invalid";
        return false;
    }
    if (p.sppRefHeight > static_cast<uint32_t>(ctx.height) ||
        static_cast<uint32_t>(ctx.height) - p.sppRefHeight > ctx.params->nbp.nSppMaxAge) {
        err = "nbp-spp-stale";
        return false;
    }

    GuardianEntry entry;
    entry.pk = pk;
    entry.bond = ctx.out->nValue;
    entry.status = static_cast<uint8_t>(GuardianStatus::ACTIVE);
    entry.statusHeight = ctx.height;
    entry.regHeight = ctx.height;
    entry.lastSppHeight = ctx.height;
    gs.members[pk] = entry;
    SetState(view, KeyGuardianSet(), gs);
    return true;
}

bool ExecGuardianExit(const GuardianExitPredicate& p, CCoinsViewCache& view,
                      const PredicateContext& ctx, std::string& err)
{
    const auto pk = p.guardianKey.GetVch();
    GuardianSet gs;
    GetState(view, KeyGuardianSet(), gs);
    auto it = gs.members.find(pk);

    if (ctx.fDisconnect) {
        if (it != gs.members.end()) {
            it->second.status = it->second.prevStatus;
            it->second.statusHeight = it->second.prevStatusHeight;
            SetState(view, KeyGuardianSet(), gs);
        }
        return true;
    }

    if (it == gs.members.end() || it->second.Status() != GuardianStatus::ACTIVE) {
        err = "nbp-not-active-guardian";
        return false;
    }
    if (!p.guardianKey.Verify(ExitMessage(pk), p.exitSig)) {
        err = "nbp-bad-exit-sig";
        return false;
    }
    it->second.prevStatus = it->second.status;
    it->second.prevStatusHeight = it->second.statusHeight;
    it->second.status = static_cast<uint8_t>(GuardianStatus::EXITING);
    it->second.statusHeight = ctx.height;
    SetState(view, KeyGuardianSet(), gs);
    return true;
}

bool ExecGuardianWithdraw(const GuardianWithdrawPredicate& p, CCoinsViewCache& view,
                          const PredicateContext& ctx, BalanceTerms* terms, std::string& err)
{
    const auto pk = p.guardianKey.GetVch();
    GuardianSet gs;
    GetState(view, KeyGuardianSet(), gs);
    auto it = gs.members.find(pk);

    if (ctx.fDisconnect) {
        if (it != gs.members.end()) {
            it->second.status = it->second.prevStatus;
            it->second.statusHeight = it->second.prevStatusHeight;
            SetState(view, KeyGuardianSet(), gs);
        }
        return true;
    }

    if (it == gs.members.end() || it->second.Status() != GuardianStatus::EXITING) {
        err = "nbp-not-exiting-guardian";
        return false;
    }
    if (ctx.height < static_cast<int>(it->second.statusHeight + ctx.params->nbp.nUnbondingBlocks)) {
        err = "nbp-unbonding-immature";
        return false;
    }
    if (ctx.out->nValue != it->second.bond) {
        err = "nbp-bad-withdraw-value";
        return false;
    }
    if (!p.guardianKey.Verify(WithdrawMessage(pk, *ctx.out), p.withdrawSig)) {
        err = "nbp-bad-withdraw-sig";
        return false;
    }
    if (terms) {
        terms->pseudoInput = it->second.bond; // native NAV
        terms->tokenId = TokenId();
    }
    it->second.prevStatus = it->second.status;
    it->second.prevStatusHeight = it->second.statusHeight;
    it->second.status = static_cast<uint8_t>(GuardianStatus::WITHDRAWN);
    it->second.statusHeight = ctx.height;
    SetState(view, KeyGuardianSet(), gs);
    return true;
}

// --- slashing (S1 / S2 / S5, objective evidence) ---------------------------

bool CheckSlashEvidence(const GuardianSlashPredicate& p, const CCoinsViewCache& view,
                        const Consensus::Params& params, std::string& err)
{
    const auto pk = p.guardianKey.GetVch();

    switch (p.evidenceType) {
    case 1: { // S1: two checkpoint signatures, same epoch, different block hash
        if (p.msg1.size() != 144 || p.msg2.size() != 144) {
            err = "nbp-slash-bad-msg";
            return false;
        }
        if (!std::equal(p.msg1.begin(), p.msg1.begin() + 32, params.hashGenesisBlock.begin()) ||
            !std::equal(p.msg2.begin(), p.msg2.begin() + 32, params.hashGenesisBlock.begin())) {
            err = "nbp-slash-wrong-chain";
            return false;
        }
        const bool sameEpoch = std::equal(p.msg1.begin() + 32, p.msg1.begin() + 40, p.msg2.begin() + 32);
        const bool sameHash = std::equal(p.msg1.begin() + 40, p.msg1.begin() + 72, p.msg2.begin() + 40);
        if (!sameEpoch || sameHash) {
            err = "nbp-slash-not-equivocation";
            return false;
        }
        if (!p.guardianKey.Verify(DstMessage(DST_CKPT, p.msg1), p.sig1) ||
            !p.guardianKey.Verify(DstMessage(DST_CKPT, p.msg2), p.sig2)) {
            err = "nbp-slash-bad-sig";
            return false;
        }
        return true;
    }
    case 2: { // S2: checkpoint signature with wrong roots for a canonical boundary block
        if (p.msg1.size() != 144) {
            err = "nbp-slash-bad-msg";
            return false;
        }
        if (!std::equal(p.msg1.begin(), p.msg1.begin() + 32, params.hashGenesisBlock.begin())) {
            err = "nbp-slash-wrong-chain";
            return false;
        }
        uint64_t epoch = 0;
        for (int i = 0; i < 8; i++) epoch = (epoch << 8) | p.msg1[32 + i];
        uint256 hashT, committeeRoot, pegOutRoot;
        std::copy(p.msg1.begin() + 40, p.msg1.begin() + 72, hashT.begin());
        std::copy(p.msg1.begin() + 80, p.msg1.begin() + 112, committeeRoot.begin());
        std::copy(p.msg1.begin() + 112, p.msg1.begin() + 144, pegOutRoot.begin());

        CheckpointRecord canonical;
        if (!GetState(view, KeyCheckpoint(epoch), canonical) || canonical.hashT != hashT) {
            // Without a canonical record for the same boundary block the
            // evidence is not objectively checkable on this chain.
            err = "nbp-slash-no-canonical";
            return false;
        }
        if (committeeRoot == canonical.committeeRoot && pegOutRoot == canonical.pegOutRoot) {
            err = "nbp-slash-not-equivocation";
            return false;
        }
        if (!p.guardianKey.Verify(DstMessage(DST_CKPT, p.msg1), p.sig1)) {
            err = "nbp-slash-bad-sig";
            return false;
        }
        return true;
    }
    case 5: { // S5: two resolution votes on one challenge, opposite verdicts
        if (p.msg1.size() != 97 || p.msg2.size() != 97) {
            err = "nbp-slash-bad-msg";
            return false;
        }
        const bool sameChallenge = std::equal(p.msg1.begin() + 32, p.msg1.begin() + 64, p.msg2.begin() + 32);
        if (!sameChallenge || p.msg1[96] == p.msg2[96]) {
            err = "nbp-slash-not-equivocation";
            return false;
        }
        if (!p.guardianKey.Verify(DstMessage(DST_RES, p.msg1), p.sig1) ||
            !p.guardianKey.Verify(DstMessage(DST_RES, p.msg2), p.sig2)) {
            err = "nbp-slash-bad-sig";
            return false;
        }
        return true;
    }
    default:
        err = "nbp-slash-bad-type";
        return false;
    }
}

bool ExecGuardianSlash(const GuardianSlashPredicate& p, CCoinsViewCache& view,
                       const PredicateContext& ctx, BalanceTerms* terms, std::string& err)
{
    const auto pk = p.guardianKey.GetVch();
    GuardianSet gs;
    GetState(view, KeyGuardianSet(), gs);
    auto it = gs.members.find(pk);

    if (ctx.fDisconnect) {
        if (it != gs.members.end()) {
            it->second.status = it->second.prevStatus;
            it->second.statusHeight = it->second.prevStatusHeight;
            SetState(view, KeyGuardianSet(), gs);
        }
        return true;
    }

    if (it == gs.members.end() ||
        (it->second.Status() != GuardianStatus::ACTIVE && it->second.Status() != GuardianStatus::EXITING)) {
        err = "nbp-slash-not-slashable";
        return false;
    }
    if (!CheckSlashEvidence(p, view, *ctx.params, err)) return false;

    // Reporter reward: the carrying output receives exactly 10% of the bond
    // as a consensus-minted transparent value; the remaining 90% stays
    // burned (the bond output was unspendable at registration).
    if (ctx.out->nValue != ReporterReward(it->second.bond)) {
        err = "nbp-slash-bad-reward";
        return false;
    }
    if (terms) {
        terms->pseudoInput = ReporterReward(it->second.bond);
        terms->tokenId = TokenId();
    }
    it->second.prevStatus = it->second.status;
    it->second.prevStatusHeight = it->second.statusHeight;
    it->second.status = static_cast<uint8_t>(GuardianStatus::SLASHED);
    it->second.statusHeight = ctx.height;
    SetState(view, KeyGuardianSet(), gs);
    return true;
}

// --- peg-in ----------------------------------------------------------------

bool ExecBridgeMint(const BridgeMintPredicate& p, CCoinsViewCache& view,
                    const PredicateContext& ctx, BalanceTerms* terms, std::string& err)
{
    const auto key = KeyDeposit(p.depositId);

    if (ctx.fDisconnect) {
        DepositRecord rec;
        if (GetState(view, key, rec) && rec.mintTxid == ctx.txid) {
            const uint256 tokenHash = BridgeTokenId(p.ethChainId, p.token);
            TokenAggregate agg;
            GetState(view, KeyTokenAggregate(tokenHash), agg);
            agg.minted -= p.amount;
            AdjustBridgeTokenSupply(view, tokenHash, p.ethChainId, p.token, -p.amount);
            if (!rec.prevRecord.empty()) {
                // This mint replaced a timeout-revoked deposit whose dead
                // supply was netted out on connect; restore it.
                DepositRecord prev;
                DataStream ss{rec.prevRecord};
                ss >> prev;
                agg.minted += prev.amount;
                AdjustBridgeTokenSupply(view, tokenHash, p.ethChainId, p.token, prev.amount);
                view.SetNbpState(key, rec.prevRecord);
            } else {
                EraseState(view, key);
            }
            SetState(view, KeyTokenAggregate(tokenHash), agg);
            EraseState(view, KeyMintOut(ctx.out->GetHash()));
        }
        return true;
    }

    if (p.token.size() != 20 || p.amount <= 0 || !MoneyRange(p.amount)) {
        err = "nbp-mint-bad-payload";
        return false;
    }
    if (ComputeClaimCommit(p.dpk, p.r) != p.claimCommit) {
        err = "nbp-mint-bad-open";
        return false;
    }

    DepositRecord existing;
    std::vector<unsigned char> prevRecord;
    if (GetState(view, key, existing)) {
        // Only a fail-safe-revoked deposit id may be minted again
        // (DESIGN §7.4); embed the predecessor for exact disconnect.
        if (!existing.IsReMintable(ctx.height, ctx.params->nbp.nResolutionWindow)) {
            err = "nbp-mint-dup-deposit";
            return false;
        }
        DataStream ss;
        ss << existing;
        const auto bytes = MakeUCharSpan(ss);
        prevRecord.assign(bytes.begin(), bytes.end());
    }

    const auto attBytes = AttestationBytes(ctx.params->hashGenesisBlock, p.ethChainId,
                                           p.depositId, p.token, static_cast<uint64_t>(p.amount),
                                           p.claimCommit);
    if (!VerifyQuorum(view, *ctx.params, ctx.height, p.bitfield, p.aggSig,
                      DstMessage(DST_ATT, attBytes), err)) {
        return false;
    }

    const uint256 tokenHash = BridgeTokenId(p.ethChainId, p.token);
    if (terms) {
        terms->pseudoInput = p.amount;
        terms->tokenId = TokenId(tokenHash);
    }

    DepositRecord rec;
    rec.status = static_cast<uint8_t>(DepositStatus::MINTED);
    rec.mintTxid = ctx.txid;
    rec.mintHeight = ctx.height;
    rec.ethChainId = p.ethChainId;
    rec.token = p.token;
    rec.amount = p.amount;
    rec.attBitfield = p.bitfield;
    rec.prevRecord = prevRecord;
    SetState(view, key, rec);
    SetState(view, KeyMintOut(ctx.out->GetHash()), p.depositId);

    TokenAggregate agg;
    GetState(view, KeyTokenAggregate(tokenHash), agg);
    // Re-minting a timeout-revoked deposit: the predecessor's supply is dead
    // (its outputs are permanently frozen), so net it out first — otherwise
    // circulating supply would double-count the deposit and break solvency.
    if (!prevRecord.empty()) {
        agg.minted -= existing.amount;
        AdjustBridgeTokenSupply(view, tokenHash, p.ethChainId, p.token, -existing.amount);
    }
    agg.minted += p.amount;
    SetState(view, KeyTokenAggregate(tokenHash), agg);
    AdjustBridgeTokenSupply(view, tokenHash, p.ethChainId, p.token, p.amount);
    return true;
}

// --- peg-out ---------------------------------------------------------------

bool ExecBridgeBurn(const BridgeBurnPredicate& p, CCoinsViewCache& view,
                    const PredicateContext& ctx, BalanceTerms* terms, std::string& err)
{
    const uint256 tokenHash = BridgeTokenId(p.ethChainId, p.token.size() == 20 ? p.token : std::vector<unsigned char>(20, 0));
    const int64_t epoch = EpochOfHeight(*ctx.params, ctx.height);

    if (ctx.fDisconnect) {
        EpochPegOuts pegouts;
        GetState(view, KeyEpochPegOuts(epoch), pegouts);
        pegouts.events.erase(std::remove_if(pegouts.events.begin(), pegouts.events.end(),
                                            [&](const PegOutEvent& ev) {
                                                return ev.txid == ctx.txid && ev.outIndex == ctx.voutIndex;
                                            }),
                             pegouts.events.end());
        SetState(view, KeyEpochPegOuts(epoch), pegouts);
        TokenAggregate agg;
        GetState(view, KeyTokenAggregate(tokenHash), agg);
        agg.burned -= p.amount;
        SetState(view, KeyTokenAggregate(tokenHash), agg);
        AdjustBridgeTokenSupply(view, tokenHash, p.ethChainId, p.token, p.amount);
        return true;
    }

    if (p.token.size() != 20 || p.ethRecipient.size() != 20 || p.amount <= 0 || !MoneyRange(p.amount)) {
        err = "nbp-burn-bad-payload";
        return false;
    }

    TokenAggregate agg;
    GetState(view, KeyTokenAggregate(tokenHash), agg);
    if (agg.burned + p.amount > agg.minted) {
        err = "nbp-burn-exceeds-supply";
        return false;
    }

    if (terms) {
        terms->pseudoOutput = p.amount;
        terms->tokenId = TokenId(tokenHash);
    }

    EpochPegOuts pegouts;
    GetState(view, KeyEpochPegOuts(epoch), pegouts);
    PegOutEvent ev;
    ev.txid = ctx.txid;
    ev.tokenId = tokenHash;
    ev.amount = static_cast<uint64_t>(p.amount);
    ev.ethRecipient = p.ethRecipient;
    ev.outIndex = ctx.voutIndex;
    pegouts.events.push_back(ev);
    SetState(view, KeyEpochPegOuts(epoch), pegouts);

    agg.burned += p.amount;
    SetState(view, KeyTokenAggregate(tokenHash), agg);
    AdjustBridgeTokenSupply(view, tokenHash, p.ethChainId, p.token, -p.amount);
    return true;
}

// --- fraud window ------------------------------------------------------------

bool ExecBridgeChallenge(const BridgeChallengePredicate& p, CCoinsViewCache& view,
                         const PredicateContext& ctx, std::string& err)
{
    const auto key = KeyDeposit(p.depositId);
    DepositRecord rec;
    const bool haveRec = GetState(view, key, rec);

    if (ctx.fDisconnect) {
        if (haveRec && rec.challengeTxid == ctx.txid) {
            rec.status = static_cast<uint8_t>(DepositStatus::MINTED);
            rec.challengeTxid.SetNull();
            rec.challengeHeight = 0;
            rec.challengerPk.clear();
            SetState(view, key, rec);
        }
        return true;
    }

    if (!haveRec || rec.Status() != DepositStatus::MINTED) {
        err = "nbp-challenge-bad-target";
        return false;
    }
    if (ctx.height >= static_cast<int>(rec.mintHeight + ctx.params->nbp.nMintMaturity)) {
        err = "nbp-challenge-too-late";
        return false;
    }
    GuardianSet gs;
    GetState(view, KeyGuardianSet(), gs);
    auto it = gs.members.find(p.guardianKey.GetVch());
    if (it == gs.members.end() ||
        (it->second.Status() != GuardianStatus::ACTIVE && it->second.Status() != GuardianStatus::EXITING)) {
        err = "nbp-challenge-not-guardian";
        return false;
    }
    if (!ctx.out->scriptPubKey.IsUnspendable() || ctx.out->nValue != ctx.params->nbp.challengeBond) {
        err = "nbp-challenge-bad-bond";
        return false;
    }
    if (!p.guardianKey.Verify(ChallengeMessage(p.depositId), p.challengeSig)) {
        err = "nbp-challenge-bad-sig";
        return false;
    }

    rec.status = static_cast<uint8_t>(DepositStatus::CHALLENGED);
    rec.challengeTxid = ctx.txid;
    rec.challengeHeight = ctx.height;
    rec.challengerPk = p.guardianKey.GetVch();
    SetState(view, key, rec);
    return true;
}

bool ExecBridgeResolve(const BridgeResolvePredicate& p, CCoinsViewCache& view,
                       const PredicateContext& ctx, BalanceTerms* terms, std::string& err)
{
    const auto key = KeyDeposit(p.depositId);
    DepositRecord rec;
    const bool haveRec = GetState(view, key, rec);

    GuardianSet gs;
    GetState(view, KeyGuardianSet(), gs);

    if (ctx.fDisconnect) {
        if (haveRec && rec.resolveTxid == ctx.txid) {
            if (rec.Status() == DepositStatus::REVOKED_UPHELD) {
                // Restore any attesters slashed by this resolution.
                for (auto& [pk, entry] : gs.members) {
                    if (entry.Status() == GuardianStatus::SLASHED &&
                        entry.statusHeight == static_cast<uint32_t>(ctx.height)) {
                        entry.status = entry.prevStatus;
                        entry.statusHeight = entry.prevStatusHeight;
                    }
                }
                SetState(view, KeyGuardianSet(), gs);
                // Restore the supply the revocation rolled back.
                const uint256 tokenHash = BridgeTokenId(rec.ethChainId, rec.token);
                TokenAggregate agg;
                GetState(view, KeyTokenAggregate(tokenHash), agg);
                agg.minted += rec.amount;
                SetState(view, KeyTokenAggregate(tokenHash), agg);
                AdjustBridgeTokenSupply(view, tokenHash, rec.ethChainId, rec.token, rec.amount);
            }
            rec.status = static_cast<uint8_t>(DepositStatus::CHALLENGED);
            rec.resolveTxid.SetNull();
            rec.resolveHeight = 0;
            SetState(view, key, rec);
        }
        return true;
    }

    if (!haveRec || rec.Status() != DepositStatus::CHALLENGED) {
        err = "nbp-resolve-bad-target";
        return false;
    }
    if (ctx.height > static_cast<int>(rec.challengeHeight + ctx.params->nbp.nResolutionWindow)) {
        // Fail-safe window passed: the mint is already revoked dynamically.
        err = "nbp-resolve-too-late";
        return false;
    }
    if (p.verdict > 1) {
        err = "nbp-resolve-bad-verdict";
        return false;
    }
    const auto resBytes = ResolutionBytes(ctx.params->hashGenesisBlock, rec.challengeTxid,
                                          p.depositId, p.verdict);
    if (!VerifyQuorum(view, *ctx.params, ctx.height, p.bitfield, p.aggSig,
                      DstMessage(DST_RES, resBytes), err)) {
        return false;
    }

    if (p.verdict == 1) {
        // Challenge upheld: revoke the mint, slash every attester of the
        // fraudulent attestation, refund + reward the challenger via the
        // carrying output.
        const int64_t mintPeriod = PeriodOfHeight(*ctx.params, rec.mintHeight);
        CommitteeSnapshot mintCommittee;
        GetState(view, KeyCommittee(mintPeriod), mintCommittee);
        CAmount totalSlashed = 0;
        for (size_t i = 0; i < mintCommittee.members.size(); ++i) {
            if (i / 8 >= rec.attBitfield.size() || !((rec.attBitfield[i / 8] >> (i % 8)) & 1)) continue;
            auto it = gs.members.find(mintCommittee.members[i].pk);
            if (it == gs.members.end() || it->second.Status() == GuardianStatus::SLASHED ||
                it->second.Status() == GuardianStatus::WITHDRAWN) continue;
            it->second.prevStatus = it->second.status;
            it->second.prevStatusHeight = it->second.statusHeight;
            it->second.status = static_cast<uint8_t>(GuardianStatus::SLASHED);
            it->second.statusHeight = ctx.height;
            totalSlashed += it->second.bond;
        }
        SetState(view, KeyGuardianSet(), gs);

        const CAmount refund = ctx.params->nbp.challengeBond + ReporterReward(totalSlashed);
        if (ctx.out->nValue != refund) {
            err = "nbp-resolve-bad-refund";
            return false;
        }
        if (terms) {
            terms->pseudoInput = refund;
            terms->tokenId = TokenId();
        }
        // Roll back the supply the fraudulent mint added.
        const uint256 tokenHash = BridgeTokenId(rec.ethChainId, rec.token);
        TokenAggregate agg;
        GetState(view, KeyTokenAggregate(tokenHash), agg);
        agg.minted -= rec.amount;
        SetState(view, KeyTokenAggregate(tokenHash), agg);
        AdjustBridgeTokenSupply(view, tokenHash, rec.ethChainId, rec.token, -rec.amount);

        rec.status = static_cast<uint8_t>(DepositStatus::REVOKED_UPHELD);
    } else {
        // Challenge rejected: the challenge bond stays burned; the mint
        // resumes maturing.
        if (ctx.out->nValue != 0) {
            err = "nbp-resolve-bad-refund";
            return false;
        }
        rec.status = static_cast<uint8_t>(DepositStatus::REJECTED);
    }
    rec.resolveTxid = ctx.txid;
    rec.resolveHeight = ctx.height;
    SetState(view, key, rec);
    return true;
}

} // namespace

// --- public entry points -----------------------------------------------------

bool ExecuteNbpPredicate(const blsct::ParsedPredicate& pred, CCoinsViewCache& view,
                         const PredicateContext& ctx, BalanceTerms* terms, std::string& err)
{
    if (!RequireActive(ctx, err)) return false;

    if (pred.Is<GuardianRegisterPredicate>())
        return ExecGuardianRegister(pred.Get<GuardianRegisterPredicate>(), view, ctx, err);
    if (pred.Is<GuardianExitPredicate>())
        return ExecGuardianExit(pred.Get<GuardianExitPredicate>(), view, ctx, err);
    if (pred.Is<GuardianWithdrawPredicate>())
        return ExecGuardianWithdraw(pred.Get<GuardianWithdrawPredicate>(), view, ctx, terms, err);
    if (pred.Is<GuardianSlashPredicate>())
        return ExecGuardianSlash(pred.Get<GuardianSlashPredicate>(), view, ctx, terms, err);
    if (pred.Is<BridgeMintPredicate>())
        return ExecBridgeMint(pred.Get<BridgeMintPredicate>(), view, ctx, terms, err);
    if (pred.Is<BridgeBurnPredicate>())
        return ExecBridgeBurn(pred.Get<BridgeBurnPredicate>(), view, ctx, terms, err);
    if (pred.Is<BridgeChallengePredicate>())
        return ExecBridgeChallenge(pred.Get<BridgeChallengePredicate>(), view, ctx, err);
    if (pred.Is<BridgeResolvePredicate>())
        return ExecBridgeResolve(pred.Get<BridgeResolvePredicate>(), view, ctx, terms, err);

    err = "nbp-unknown-predicate";
    return false;
}

bool CheckNbpSpend(const CCoinsViewCache& view, const Consensus::Params& params,
                   const COutPoint& prevout, int height, std::string& err)
{
    if (!params.nbp.IsActive(height)) return true;

    uint256 depositId;
    if (!GetState(view, KeyMintOut(prevout.hash), depositId)) return true; // not a bridge mint

    DepositRecord rec;
    if (!GetState(view, KeyDeposit(depositId), rec)) {
        err = "nbp-mint-state-missing";
        return false;
    }
    switch (rec.Status()) {
    case DepositStatus::MINTED:
        if (height < static_cast<int>(rec.mintHeight + params.nbp.nMintMaturity)) {
            err = "nbp-mint-immature";
            return false;
        }
        return true;
    case DepositStatus::CHALLENGED:
        // Frozen while the challenge is open; permanently revoked once the
        // resolution window lapses (fail-safe).
        err = rec.IsTimeoutRevoked(height, params.nbp.nResolutionWindow) ? "nbp-mint-revoked" : "nbp-mint-frozen";
        return false;
    case DepositStatus::REVOKED_UPHELD:
        err = "nbp-mint-revoked";
        return false;
    case DepositStatus::REJECTED:
        if (height < static_cast<int>(rec.mintHeight + params.nbp.nMintMaturity) ||
            height < static_cast<int>(rec.resolveHeight)) {
            err = "nbp-mint-immature";
            return false;
        }
        return true;
    }
    err = "nbp-mint-state-missing";
    return false;
}

bool VerifyQuorum(const CCoinsViewCache& view, const Consensus::Params& params, int height,
                  const std::vector<unsigned char>& bitfield, const blsct::Signature& aggSig,
                  const std::vector<unsigned char>& msg, std::string& err)
{
    const int64_t period = PeriodOfHeight(params, height);
    CommitteeSnapshot committee;
    if (!GetState(view, KeyCommittee(period), committee) || committee.members.empty()) {
        err = "nbp-no-committee";
        return false;
    }
    const size_t n = committee.members.size();
    if (bitfield.size() != (n + 7) / 8) {
        err = "nbp-bad-bitfield";
        return false;
    }
    // Trailing bits beyond the committee size must be zero.
    for (size_t i = n; i < bitfield.size() * 8; ++i) {
        if ((bitfield[i / 8] >> (i % 8)) & 1) {
            err = "nbp-bad-bitfield";
            return false;
        }
    }

    CAmount weight = 0;
    std::vector<blsct::PublicKey> signers;
    for (size_t i = 0; i < n; ++i) {
        if ((bitfield[i / 8] >> (i % 8)) & 1) {
            signers.emplace_back(committee.members[i].pk);
            weight += committee.members[i].bond;
        }
    }
    const CAmount total = committee.TotalWeight();
    if (weight <= 0 || 3 * weight < 2 * total) {
        err = "nbp-quorum-weight";
        return false;
    }

    const std::vector<blsct::PublicKey::Message> msgs(signers.size(), msg);
    if (!blsct::PublicKeys(signers).VerifyBatch(msgs, aggSig)) {
        err = "nbp-quorum-badsig";
        return false;
    }
    return true;
}

uint256 CommitteeRootForPeriod(const CCoinsViewCache& view, uint64_t period)
{
    CommitteeSnapshot committee;
    GetState(view, KeyCommittee(period), committee);
    std::vector<std::vector<unsigned char>> leaves;
    leaves.reserve(committee.members.size());
    for (const auto& m : committee.members) {
        leaves.push_back(CommitteeLeaf(m.pk, static_cast<uint64_t>(m.bond)));
    }
    return ComputeMerkleRoot(leaves);
}

uint256 PegOutRootForEpoch(const CCoinsViewCache& view, uint64_t epoch)
{
    EpochPegOuts pegouts;
    GetState(view, KeyEpochPegOuts(epoch), pegouts);
    std::vector<std::vector<unsigned char>> leaves;
    leaves.reserve(pegouts.events.size());
    for (const auto& ev : pegouts.events) {
        leaves.push_back(PegOutLeaf(ev.txid, ev.tokenId, ev.amount, ev.ethRecipient, ev.outIndex));
    }
    return ComputeMerkleRoot(leaves);
}

namespace {

//! Validate an embedded checkpoint against this chain (DESIGN §5.2) and
//! store its record. `pindex` is the block containing the checkpoint.
bool ConnectCheckpoint(CCoinsViewCache& view, const Consensus::Params& params,
                       const CheckpointData& cp, const CBlockIndex* pindex, std::string& err)
{
    // Rule 1: referenced block must be the epoch-boundary ancestor.
    if (cp.heightT >= static_cast<uint64_t>(pindex->nHeight) ||
        static_cast<int>(cp.heightT) != EpochBoundaryHeight(params, cp.epoch)) {
        err = "nbp-ckpt-bad-height";
        return false;
    }
    const CBlockIndex* ancestor = pindex->GetAncestor(static_cast<int>(cp.heightT));
    if (ancestor == nullptr || ancestor->GetBlockHash() != cp.hashT) {
        err = "nbp-ckpt-not-ancestor";
        return false;
    }
    // Rule 2: first valid checkpoint per epoch wins.
    CheckpointRecord existing;
    if (GetState(view, KeyCheckpoint(cp.epoch), existing)) {
        err = "nbp-ckpt-duplicate";
        return false;
    }
    // Rule 3: roots must equal this chain's canonical values — a checkpoint
    // lying about its roots is invalid in-consensus.
    const int64_t period = PeriodOfEpoch(params, cp.epoch);
    const int64_t rootPeriod = IsLastEpochOfPeriod(params, cp.epoch) ? period + 1 : period;
    if (cp.committeeRoot != CommitteeRootForPeriod(view, rootPeriod)) {
        err = "nbp-ckpt-root-mismatch";
        return false;
    }
    if (cp.pegOutRoot != PegOutRootForEpoch(view, cp.epoch)) {
        err = "nbp-ckpt-root-mismatch";
        return false;
    }
    // Rules 4/5: signer weight and aggregate signature against the
    // committee of the checkpoint's own period.
    const auto cpBytes = CheckpointBytes(params.hashGenesisBlock, cp.epoch, cp.hashT,
                                         cp.heightT, cp.committeeRoot, cp.pegOutRoot);
    std::string quorumErr;
    if (!VerifyQuorum(view, params, static_cast<int>(cp.heightT), cp.bitfield, cp.aggSig,
                      DstMessage(DST_CKPT, cpBytes), quorumErr)) {
        err = quorumErr;
        return false;
    }

    CheckpointRecord rec;
    rec.epoch = cp.epoch;
    rec.hashT = cp.hashT;
    rec.heightT = cp.heightT;
    rec.committeeRoot = cp.committeeRoot;
    rec.pegOutRoot = cp.pegOutRoot;
    rec.inclusionHeight = pindex->nHeight;
    SetState(view, KeyCheckpoint(cp.epoch), rec);
    return true;
}

//! Committee snapshot for period p+2, taken at the last block of period p
//! (two-period lookahead): ACTIVE guardians with a fresh-enough SPP, top
//! maxCommittee by bond (tie-break: ascending pk), stored in canonical
//! (ascending pk) order.
CommitteeSnapshot BuildCommitteeSnapshot(const CCoinsViewCache& view, const Consensus::Params& params, int height)
{
    GuardianSet gs;
    GetState(view, KeyGuardianSet(), gs);

    std::vector<CommitteeMember> eligible;
    for (const auto& [pk, entry] : gs.members) {
        if (entry.Status() != GuardianStatus::ACTIVE) continue;
        const int64_t sppAgePeriods = PeriodOfHeight(params, height) - PeriodOfHeight(params, entry.lastSppHeight);
        if (sppAgePeriods > static_cast<int64_t>(params.nbp.nSppRefreshPeriods)) continue;
        eligible.push_back(CommitteeMember{pk, entry.bond});
    }
    std::sort(eligible.begin(), eligible.end(), [](const CommitteeMember& a, const CommitteeMember& b) {
        if (a.bond != b.bond) return a.bond > b.bond;
        return a.pk < b.pk;
    });
    if (eligible.size() > params.nbp.maxCommittee) eligible.resize(params.nbp.maxCommittee);
    std::sort(eligible.begin(), eligible.end(), [](const CommitteeMember& a, const CommitteeMember& b) {
        return a.pk < b.pk;
    });

    CommitteeSnapshot snapshot;
    snapshot.members = std::move(eligible);
    return snapshot;
}

} // namespace

bool ConnectNbpBlock(CCoinsViewCache& view, const Consensus::Params& params,
                     const CBlock& block, const CBlockIndex* pindex, std::string& err)
{
    if (!params.nbp.IsActive(pindex->nHeight)) {
        if (block.HasNbpCheckpoint()) {
            err = "nbp-inactive";
            return false;
        }
        return true;
    }

    if (block.HasNbpCheckpoint()) {
        if (!ConnectCheckpoint(view, params, block.nbpCheckpoint, pindex, err)) return false;
    }

    if (IsPeriodBoundary(params, pindex->nHeight)) {
        const int64_t period = PeriodOfHeight(params, pindex->nHeight);
        SetState(view, KeyCommittee(period + 2), BuildCommitteeSnapshot(view, params, pindex->nHeight));
    }
    return true;
}

void DisconnectNbpBlock(CCoinsViewCache& view, const Consensus::Params& params,
                        const CBlock& block, const CBlockIndex* pindex)
{
    if (!params.nbp.IsActive(pindex->nHeight)) return;

    if (block.HasNbpCheckpoint()) {
        CheckpointRecord rec;
        if (GetState(view, KeyCheckpoint(block.nbpCheckpoint.epoch), rec) &&
            rec.inclusionHeight == static_cast<uint32_t>(pindex->nHeight)) {
            EraseState(view, KeyCheckpoint(block.nbpCheckpoint.epoch));
        }
    }
    if (IsPeriodBoundary(params, pindex->nHeight)) {
        EraseState(view, KeyCommittee(PeriodOfHeight(params, pindex->nHeight) + 2));
    }
}

bool GetFinalizedCheckpoint(const CCoinsViewCache& view, const Consensus::Params& params,
                            int tipHeight, uint256& hashOut, int& heightOut)
{
    if (!params.nbp.IsActive(tipHeight)) return false;
    const int64_t tipEpoch = EpochOfHeight(params, tipHeight);
    for (int64_t e = tipEpoch; e >= 0; --e) {
        CheckpointRecord rec;
        if (!GetState(view, KeyCheckpoint(e), rec)) continue;
        if (static_cast<int>(rec.inclusionHeight) + static_cast<int>(params.nbp.nFinalityBurial) <= tipHeight) {
            hashOut = rec.hashT;
            heightOut = static_cast<int>(rec.heightT);
            return true;
        }
    }
    return false;
}

} // namespace nbp
