// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/tokens/predicate_parser.h>

namespace blsct {
ParsedPredicate ParsePredicate(const VectorPredicate& vch)
{
    DataStream ss{vch};
    PredicateOperation op;
    ss >> Using<CustomUintFormatter<1>>(op);

    if (op == CREATE_TOKEN) {
        CreateTokenPredicate p;
        ss >> p;
        return p;
    } else if (op == MINT) {
        MintTokenPredicate p;
        ss >> p;
        return p;
    } else if (op == NFT_MINT) {
        MintNftPredicate p;
        ss >> p;
        return p;
    } else if (op == PAY_FEE) {
        PayFeePredicate p;
        ss >> p;
        return p;
    } else if (op == DATA) {
        DataPredicate p;
        ss >> p;
        return p;
    } else if (op == NBP_GUARDIAN_REGISTER) {
        nbp::GuardianRegisterPredicate p;
        ss >> p;
        return p;
    } else if (op == NBP_GUARDIAN_EXIT) {
        nbp::GuardianExitPredicate p;
        ss >> p;
        return p;
    } else if (op == NBP_GUARDIAN_WITHDRAW) {
        nbp::GuardianWithdrawPredicate p;
        ss >> p;
        return p;
    } else if (op == NBP_GUARDIAN_SLASH) {
        nbp::GuardianSlashPredicate p;
        ss >> p;
        return p;
    } else if (op == NBP_BRIDGE_MINT) {
        nbp::BridgeMintPredicate p;
        ss >> p;
        return p;
    } else if (op == NBP_BRIDGE_BURN) {
        nbp::BridgeBurnPredicate p;
        ss >> p;
        return p;
    } else if (op == NBP_BRIDGE_CHALLENGE) {
        nbp::BridgeChallengePredicate p;
        ss >> p;
        return p;
    } else if (op == NBP_BRIDGE_RESOLVE) {
        nbp::BridgeResolvePredicate p;
        ss >> p;
        return p;
    } else {
        throw std::ios_base::failure("unknown predicate operation");
    }
}

std::string PredicateToString(const VectorPredicate& vch)
{
    try {
        auto predicate = ParsePredicate(vch);

        std::string ret;

        if (predicate.IsCreateTokenPredicate())
            ret = "CREATE_TOKEN";
        else if (predicate.IsMintTokenPredicate())
            ret = "MINT_TOKEN";
        else if (predicate.IsMintNftPredicate())
            ret = "MINT_NFT";
        else if (predicate.IsPayFeePredicate())
            ret = "PAY_FEE";
        else if (predicate.IsDataPredicate())
            ret = "DATA";
        else if (predicate.Is<nbp::GuardianRegisterPredicate>())
            ret = "NBP_GUARDIAN_REGISTER";
        else if (predicate.Is<nbp::GuardianExitPredicate>())
            ret = "NBP_GUARDIAN_EXIT";
        else if (predicate.Is<nbp::GuardianWithdrawPredicate>())
            ret = "NBP_GUARDIAN_WITHDRAW";
        else if (predicate.Is<nbp::GuardianSlashPredicate>())
            ret = "NBP_GUARDIAN_SLASH";
        else if (predicate.Is<nbp::BridgeMintPredicate>())
            ret = "NBP_BRIDGE_MINT";
        else if (predicate.Is<nbp::BridgeBurnPredicate>())
            ret = "NBP_BRIDGE_BURN";
        else if (predicate.Is<nbp::BridgeChallengePredicate>())
            ret = "NBP_BRIDGE_CHALLENGE";
        else if (predicate.Is<nbp::BridgeResolvePredicate>())
            ret = "NBP_BRIDGE_RESOLVE";

        return ret;
    } catch (const std::ios_base::failure&) {
        // If predicate parsing fails, return a generic error message
        return "INVALID_PREDICATE";
    }
}
} // namespace blsct