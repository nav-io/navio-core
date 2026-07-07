// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/bridge/rpc.h>

#include <blsct/bridge/epoch.h>
#include <blsct/bridge/logic.h>
#include <blsct/bridge/merkle.h>
#include <blsct/bridge/messages.h>
#include <blsct/bridge/state.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <core_io.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <sync.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

namespace nbp {

namespace {
GlobalMutex g_pending_checkpoint_mutex;
std::optional<CheckpointData> g_pending_checkpoint GUARDED_BY(g_pending_checkpoint_mutex);
} // namespace

void SetPendingCheckpoint(const CheckpointData& cp)
{
    LOCK(g_pending_checkpoint_mutex);
    g_pending_checkpoint = cp;
}

std::optional<CheckpointData> GetPendingCheckpoint()
{
    LOCK(g_pending_checkpoint_mutex);
    return g_pending_checkpoint;
}

void ClearPendingCheckpoint()
{
    LOCK(g_pending_checkpoint_mutex);
    g_pending_checkpoint.reset();
}

} // namespace nbp

namespace {

UniValue GuardianEntryToJson(const nbp::GuardianEntry& e)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("pubkey", HexStr(e.pk));
    o.pushKV("bond", ValueFromAmount(e.bond));
    switch (e.Status()) {
    case nbp::GuardianStatus::ACTIVE: o.pushKV("status", "active"); break;
    case nbp::GuardianStatus::EXITING: o.pushKV("status", "exiting"); break;
    case nbp::GuardianStatus::SLASHED: o.pushKV("status", "slashed"); break;
    case nbp::GuardianStatus::WITHDRAWN: o.pushKV("status", "withdrawn"); break;
    }
    o.pushKV("status_height", static_cast<int64_t>(e.statusHeight));
    o.pushKV("registration_height", static_cast<int64_t>(e.regHeight));
    o.pushKV("last_spp_height", static_cast<int64_t>(e.lastSppHeight));
    return o;
}

RPCHelpMan getnbpepochinfo()
{
    return RPCHelpMan{
        "getnbpepochinfo",
        "Returns NBP bridge epoch/period information for the current tip.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "active", "whether the bridge is active at the tip"},
            {RPCResult::Type::NUM, "height", "current tip height"},
            {RPCResult::Type::NUM, "epoch", "epoch containing the tip"},
            {RPCResult::Type::NUM, "period", "committee period containing the tip"},
            {RPCResult::Type::NUM, "epoch_boundary_height", "last height of the current epoch"},
            {RPCResult::Type::BOOL, "is_epoch_boundary", "tip is an epoch boundary block"},
            {RPCResult::Type::NUM, "epoch_blocks", "blocks per epoch (E)"},
            {RPCResult::Type::NUM, "period_epochs", "epochs per period (P)"},
        }},
        RPCExamples{HelpExampleCli("getnbpepochinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const Consensus::Params& params = chainman.GetConsensus();
            const int height = chainman.ActiveChain().Height();

            UniValue o(UniValue::VOBJ);
            o.pushKV("active", nbp::BridgeActive(params, height));
            o.pushKV("height", height);
            if (nbp::BridgeActive(params, height)) {
                const int64_t epoch = nbp::EpochOfHeight(params, height);
                o.pushKV("epoch", epoch);
                o.pushKV("period", nbp::PeriodOfEpoch(params, epoch));
                o.pushKV("epoch_boundary_height", nbp::EpochBoundaryHeight(params, epoch));
                o.pushKV("is_epoch_boundary", nbp::IsEpochBoundary(params, height));
            }
            o.pushKV("epoch_blocks", static_cast<int64_t>(params.nbp.nEpochBlocks));
            o.pushKV("period_epochs", static_cast<int64_t>(params.nbp.nPeriodEpochs));
            return o;
        },
    };
}

RPCHelpMan getnbpcommittee()
{
    return RPCHelpMan{
        "getnbpcommittee",
        "Returns the NBP guardian committee for a period (default: the period containing the tip).\n",
        {
            {"period", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Committee period"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "period", "the period"},
            {RPCResult::Type::STR_HEX, "committee_root", "canonical committee Merkle root"},
            {RPCResult::Type::STR_AMOUNT, "total_weight", "sum of member bonds"},
            {RPCResult::Type::ARR, "members", "canonical (bitfield) order", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "pubkey", "guardian BLS public key"},
                    {RPCResult::Type::STR_AMOUNT, "bond", "member weight"},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("getnbpcommittee", "3")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const Consensus::Params& params = chainman.GetConsensus();
            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();

            int64_t period;
            if (!request.params[0].isNull()) {
                period = request.params[0].getInt<int64_t>();
            } else {
                period = nbp::PeriodOfHeight(params, chainman.ActiveChain().Height());
            }

            nbp::CommitteeSnapshot committee;
            nbp::GetState(view, nbp::KeyCommittee(period), committee);

            UniValue members(UniValue::VARR);
            for (const auto& m : committee.members) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("pubkey", HexStr(m.pk));
                o.pushKV("bond", ValueFromAmount(m.bond));
                members.push_back(o);
            }
            UniValue o(UniValue::VOBJ);
            o.pushKV("period", period);
            o.pushKV("committee_root", nbp::CommitteeRootForPeriod(view, period).GetHex());
            o.pushKV("total_weight", ValueFromAmount(committee.TotalWeight()));
            o.pushKV("members", members);
            return o;
        },
    };
}

RPCHelpMan getnbpguardians()
{
    return RPCHelpMan{
        "getnbpguardians",
        "Returns the full NBP guardian registry.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "pubkey", ""},
                {RPCResult::Type::STR_AMOUNT, "bond", ""},
                {RPCResult::Type::STR, "status", "active|exiting|slashed|withdrawn"},
                {RPCResult::Type::NUM, "status_height", ""},
                {RPCResult::Type::NUM, "registration_height", ""},
                {RPCResult::Type::NUM, "last_spp_height", ""},
            }},
        }},
        RPCExamples{HelpExampleCli("getnbpguardians", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();

            nbp::GuardianSet gs;
            nbp::GetState(view, nbp::KeyGuardianSet(), gs);

            UniValue arr(UniValue::VARR);
            for (const auto& [pk, entry] : gs.members) {
                arr.push_back(GuardianEntryToJson(entry));
            }
            return arr;
        },
    };
}

RPCHelpMan getnbpcheckpoint()
{
    return RPCHelpMan{
        "getnbpcheckpoint",
        "Returns the embedded NBP checkpoint record for an epoch, if any.\n",
        {
            {"epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Epoch number"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "epoch", ""},
            {RPCResult::Type::STR_HEX, "block_hash", "epoch-boundary block the checkpoint finalizes"},
            {RPCResult::Type::NUM, "block_height", ""},
            {RPCResult::Type::STR_HEX, "committee_root", ""},
            {RPCResult::Type::STR_HEX, "pegout_root", ""},
            {RPCResult::Type::NUM, "inclusion_height", "height of the block embedding the checkpoint"},
        }},
        RPCExamples{HelpExampleCli("getnbpcheckpoint", "4")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();

            nbp::CheckpointRecord rec;
            if (!nbp::GetState(view, nbp::KeyCheckpoint(request.params[0].getInt<int64_t>()), rec)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "no checkpoint for epoch");
            }
            UniValue o(UniValue::VOBJ);
            o.pushKV("epoch", static_cast<int64_t>(rec.epoch));
            o.pushKV("block_hash", rec.hashT.GetHex());
            o.pushKV("block_height", static_cast<int64_t>(rec.heightT));
            o.pushKV("committee_root", rec.committeeRoot.GetHex());
            o.pushKV("pegout_root", rec.pegOutRoot.GetHex());
            o.pushKV("inclusion_height", static_cast<int64_t>(rec.inclusionHeight));
            return o;
        },
    };
}

RPCHelpMan getnbpfinality()
{
    return RPCHelpMan{
        "getnbpfinality",
        "Returns the NBP dynamic-finality anchor (highest checkpoint buried >= q blocks).\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "finalized", "whether any checkpoint is finalized"},
            {RPCResult::Type::STR_HEX, "block_hash", /*optional=*/true, ""},
            {RPCResult::Type::NUM, "block_height", /*optional=*/true, ""},
        }},
        RPCExamples{HelpExampleCli("getnbpfinality", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();

            uint256 hash;
            int height = 0;
            UniValue o(UniValue::VOBJ);
            const bool finalized = nbp::GetFinalizedCheckpoint(view, chainman.GetConsensus(),
                                                               chainman.ActiveChain().Height(), hash, height);
            o.pushKV("finalized", finalized);
            if (finalized) {
                o.pushKV("block_hash", hash.GetHex());
                o.pushKV("block_height", height);
            }
            return o;
        },
    };
}

RPCHelpMan getnbpdeposit()
{
    return RPCHelpMan{
        "getnbpdeposit",
        "Returns the NBP deposit record for a deposit id, if any.\n",
        {
            {"deposit_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte deposit id"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "status", "minted|challenged|revoked_upheld|rejected|revoked_timeout"},
            {RPCResult::Type::STR_HEX, "mint_txid", ""},
            {RPCResult::Type::NUM, "mint_height", ""},
            {RPCResult::Type::STR_AMOUNT, "amount", ""},
            {RPCResult::Type::NUM, "spendable_height", "height at which the minted outputs mature (0 if revoked/frozen)"},
            {RPCResult::Type::STR_HEX, "challenge_txid", /*optional=*/true, ""},
            {RPCResult::Type::NUM, "challenge_height", /*optional=*/true, ""},
        }},
        RPCExamples{HelpExampleCli("getnbpdeposit", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const Consensus::Params& params = chainman.GetConsensus();
            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
            const int height = chainman.ActiveChain().Height();

            nbp::DepositRecord rec;
            if (!nbp::GetState(view, nbp::KeyDeposit(uint256S(request.params[0].get_str())), rec)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown deposit id");
            }
            UniValue o(UniValue::VOBJ);
            std::string status;
            int64_t spendable = 0;
            switch (rec.Status()) {
            case nbp::DepositStatus::MINTED:
                status = "minted";
                spendable = rec.mintHeight + params.nbp.nMintMaturity;
                break;
            case nbp::DepositStatus::CHALLENGED:
                status = rec.IsTimeoutRevoked(height, params.nbp.nResolutionWindow) ? "revoked_timeout" : "challenged";
                break;
            case nbp::DepositStatus::REVOKED_UPHELD:
                status = "revoked_upheld";
                break;
            case nbp::DepositStatus::REJECTED:
                status = "rejected";
                spendable = std::max<int64_t>(rec.mintHeight + params.nbp.nMintMaturity, rec.resolveHeight);
                break;
            }
            o.pushKV("status", status);
            o.pushKV("mint_txid", rec.mintTxid.GetHex());
            o.pushKV("mint_height", static_cast<int64_t>(rec.mintHeight));
            o.pushKV("amount", ValueFromAmount(rec.amount));
            o.pushKV("spendable_height", spendable);
            if (!rec.challengeTxid.IsNull()) {
                o.pushKV("challenge_txid", rec.challengeTxid.GetHex());
                o.pushKV("challenge_height", static_cast<int64_t>(rec.challengeHeight));
            }
            return o;
        },
    };
}

RPCHelpMan getnbppegouts()
{
    return RPCHelpMan{
        "getnbppegouts",
        "Returns the NBP peg-out events accumulated for an epoch, with the canonical PegOutRoot.\n",
        {
            {"epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Epoch number"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "pegout_root", ""},
            {RPCResult::Type::ARR, "events", "", {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "txid", ""},
                    {RPCResult::Type::STR_HEX, "token_id", ""},
                    {RPCResult::Type::STR_AMOUNT, "amount", ""},
                    {RPCResult::Type::STR_HEX, "eth_recipient", ""},
                    {RPCResult::Type::NUM, "out_index", ""},
                }},
            }},
        }},
        RPCExamples{HelpExampleCli("getnbppegouts", "4")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
            const int64_t epoch = request.params[0].getInt<int64_t>();

            nbp::EpochPegOuts pegouts;
            nbp::GetState(view, nbp::KeyEpochPegOuts(epoch), pegouts);

            UniValue events(UniValue::VARR);
            for (const auto& ev : pegouts.events) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("txid", ev.txid.GetHex());
                o.pushKV("token_id", ev.tokenId.GetHex());
                o.pushKV("amount", ValueFromAmount(static_cast<CAmount>(ev.amount)));
                o.pushKV("eth_recipient", HexStr(ev.ethRecipient));
                o.pushKV("out_index", static_cast<int64_t>(ev.outIndex));
                events.push_back(o);
            }
            UniValue o(UniValue::VOBJ);
            o.pushKV("pegout_root", nbp::PegOutRootForEpoch(view, epoch).GetHex());
            o.pushKV("events", events);
            return o;
        },
    };
}

RPCHelpMan getnbptokeninfo()
{
    return RPCHelpMan{
        "getnbptokeninfo",
        "Returns cumulative mint/burn accounting for a bridged token.\n",
        {
            {"eth_chain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Source EVM chain id"},
            {"token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "20-byte ERC20 address"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "token_id", "derived Navio token id"},
            {RPCResult::Type::STR_AMOUNT, "minted", "cumulative minted"},
            {RPCResult::Type::STR_AMOUNT, "burned", "cumulative burned"},
            {RPCResult::Type::STR_AMOUNT, "circulating", "minted - burned"},
        }},
        RPCExamples{HelpExampleCli("getnbptokeninfo", "31337 \"aabb...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();

            const auto token = ParseHex(request.params[1].get_str());
            if (token.size() != 20) throw JSONRPCError(RPC_INVALID_PARAMETER, "token must be 20 bytes");
            const uint256 tokenId = nbp::BridgeTokenId(request.params[0].getInt<int64_t>(), token);

            nbp::TokenAggregate agg;
            nbp::GetState(view, nbp::KeyTokenAggregate(tokenId), agg);

            UniValue o(UniValue::VOBJ);
            o.pushKV("token_id", tokenId.GetHex());
            o.pushKV("minted", ValueFromAmount(agg.minted));
            o.pushKV("burned", ValueFromAmount(agg.burned));
            o.pushKV("circulating", ValueFromAmount(agg.minted - agg.burned));
            return o;
        },
    };
}

RPCHelpMan getnbpcheckpointmsg()
{
    return RPCHelpMan{
        "getnbpcheckpointmsg",
        "Builds the canonical checkpoint message bytes (cp_bytes) for an epoch from this node's chain. Sign with nbpsignmessage context=checkpoint.\n",
        {
            {"epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Epoch number (its boundary block must exist)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "cp_bytes", "144-byte checkpoint message"},
            {RPCResult::Type::STR_HEX, "block_hash", ""},
            {RPCResult::Type::NUM, "block_height", ""},
            {RPCResult::Type::STR_HEX, "committee_root", ""},
            {RPCResult::Type::STR_HEX, "pegout_root", ""},
        }},
        RPCExamples{HelpExampleCli("getnbpcheckpointmsg", "4")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const Consensus::Params& params = chainman.GetConsensus();
            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
            const int64_t epoch = request.params[0].getInt<int64_t>();

            const int boundary = nbp::EpochBoundaryHeight(params, epoch);
            const CBlockIndex* pindex = chainman.ActiveChain()[boundary];
            if (pindex == nullptr) throw JSONRPCError(RPC_INVALID_PARAMETER, "epoch boundary not on chain");

            const int64_t period = nbp::PeriodOfEpoch(params, epoch);
            const int64_t rootPeriod = nbp::IsLastEpochOfPeriod(params, epoch) ? period + 1 : period;
            const uint256 committeeRoot = nbp::CommitteeRootForPeriod(view, rootPeriod);
            const uint256 pegOutRoot = nbp::PegOutRootForEpoch(view, epoch);

            const auto cpBytes = nbp::CheckpointBytes(params.hashGenesisBlock, epoch,
                                                      pindex->GetBlockHash(), boundary,
                                                      committeeRoot, pegOutRoot);
            UniValue o(UniValue::VOBJ);
            o.pushKV("cp_bytes", HexStr(cpBytes));
            o.pushKV("block_hash", pindex->GetBlockHash().GetHex());
            o.pushKV("block_height", boundary);
            o.pushKV("committee_root", committeeRoot.GetHex());
            o.pushKV("pegout_root", pegOutRoot.GetHex());
            return o;
        },
    };
}

RPCHelpMan getnbpattestationmsg()
{
    return RPCHelpMan{
        "getnbpattestationmsg",
        "Builds the deposit attestation message bytes (att_bytes). Sign with nbpsignmessage context=attestation.\n",
        {
            {"eth_chain_id", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
            {"deposit_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32 bytes"},
            {"token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "20-byte ERC20 address"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, ""},
            {"claim_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32 bytes"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "att_bytes", "132-byte attestation message"},
        RPCExamples{HelpExampleCli("getnbpattestationmsg", "31337 \"<id>\" \"<token>\" 5 \"<commit>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const Consensus::Params& params = chainman.GetConsensus();

            const auto token = ParseHex(request.params[2].get_str());
            if (token.size() != 20) throw JSONRPCError(RPC_INVALID_PARAMETER, "token must be 20 bytes");
            const auto attBytes = nbp::AttestationBytes(
                params.hashGenesisBlock,
                request.params[0].getInt<int64_t>(),
                uint256S(request.params[1].get_str()),
                token,
                AmountFromValue(request.params[3]),
                uint256S(request.params[4].get_str()));
            return HexStr(attBytes);
        },
    };
}

RPCHelpMan getnbpresolutionmsg()
{
    return RPCHelpMan{
        "getnbpresolutionmsg",
        "Builds the challenge-resolution message bytes (res_bytes). Sign with nbpsignmessage context=resolution.\n",
        {
            {"challenge_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"deposit_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"verdict", RPCArg::Type::NUM, RPCArg::Optional::NO, "1 = uphold, 0 = reject"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "res_bytes", "97-byte resolution message"},
        RPCExamples{HelpExampleCli("getnbpresolutionmsg", "\"<txid>\" \"<id>\" 1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const auto resBytes = nbp::ResolutionBytes(
                chainman.GetConsensus().hashGenesisBlock,
                uint256S(request.params[0].get_str()),
                uint256S(request.params[1].get_str()),
                static_cast<uint8_t>(request.params[2].getInt<int>()));
            return HexStr(resBytes);
        },
    };
}

RPCHelpMan submitnbpcheckpoint()
{
    return RPCHelpMan{
        "submitnbpcheckpoint",
        "Queues an assembled checkpoint attestation for embedding into the next mined block.\n",
        {
            {"epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
            {"block_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "epoch-boundary block hash"},
            {"block_height", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
            {"committee_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"pegout_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"bitfield", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "signer bitfield over the committee"},
            {"agg_sig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "aggregate BLS signature"},
        },
        RPCResult{RPCResult::Type::BOOL, "queued", ""},
        RPCExamples{HelpExampleCli("submitnbpcheckpoint", "4 \"<hash>\" 24 \"<root>\" \"<root>\" \"07\" \"<sig>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            nbp::CheckpointData cp;
            cp.epoch = request.params[0].getInt<int64_t>();
            cp.hashT = uint256S(request.params[1].get_str());
            cp.heightT = request.params[2].getInt<int64_t>();
            cp.committeeRoot = uint256S(request.params[3].get_str());
            cp.pegOutRoot = uint256S(request.params[4].get_str());
            cp.bitfield = ParseHex(request.params[5].get_str());
            const auto sigBytes = ParseHex(request.params[6].get_str());
            try {
                cp.aggSig.SetVch(sigBytes);
            } catch (const std::exception&) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid aggregate signature encoding");
            }
            nbp::SetPendingCheckpoint(cp);
            return true;
        },
    };
}

} // namespace

void RegisterNbpRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blsct", &getnbpepochinfo},
        {"blsct", &getnbpcommittee},
        {"blsct", &getnbpguardians},
        {"blsct", &getnbpcheckpoint},
        {"blsct", &getnbpfinality},
        {"blsct", &getnbpdeposit},
        {"blsct", &getnbppegouts},
        {"blsct", &getnbptokeninfo},
        {"blsct", &getnbpcheckpointmsg},
        {"blsct", &getnbpattestationmsg},
        {"blsct", &getnbpresolutionmsg},
        {"blsct", &submitnbpcheckpoint},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
