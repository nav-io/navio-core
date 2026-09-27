// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <blsct/arith/blst/blst.h>
#include <blsct/arith/blst/blst_init.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <ctokens/tokenid.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <uint256.h>

#include <cassert>
#include <cstdint>
#include <vector>

using Arith = Blst;
using Point = Arith::Point;
using Scalar = Arith::Scalar;
using Scalars = Elements<Scalar>;

namespace {

constexpr size_t N_OUTPUTS{16};

// A BLSCT transaction shaped like a wallet send: every output carries a real
// range proof and keys, so (de)serialization and per-output hashing see
// realistic sizes.
CMutableTransaction MakeBLSCTTx(size_t n_outputs)
{
    volatile BlstInit init;
    (void)init;

    bulletproofs_plus::RangeProofLogic<Arith> rp;
    CMutableTransaction mtx;
    mtx.nVersion |= CTransaction::BLSCT_MARKER;
    for (size_t i = 0; i < n_outputs; ++i) {
        mtx.vin.emplace_back(COutPoint(uint256(static_cast<uint8_t>(i + 1))));

        Scalars vs;
        vs.Add(Scalar(static_cast<int64_t>(1000 + i)));
        Scalars nonce_seed;
        nonce_seed.Add(Scalar::Rand(true));
        range_proof::GammaSeed<Arith> nonce(nonce_seed);

        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = CScript() << OP_TRUE;
        out.blsctData.rangeProof = rp.Prove(vs, nonce, std::vector<uint8_t>(8, 0), TokenId());
        out.blsctData.spendingKey = Point::Rand();
        out.blsctData.blindingKey = Point::Rand();
        out.blsctData.ephemeralKey = Point::Rand();
        out.blsctData.viewTag = static_cast<uint16_t>(i);
        mtx.vout.push_back(out);
    }
    return mtx;
}

} // namespace

// Wire-to-CTransaction cost of a BLSCT transaction, which is what a node pays
// for every relayed transaction and every block transaction.
static void BLSCTTransactionDeserialize(benchmark::Bench& bench)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(MakeBLSCTTx(N_OUTPUTS));
    const size_t size{stream.size()};
    std::byte a{0};
    stream.write({&a, 1}); // Prevent compaction

    bench.unit("tx").run([&] {
        CTransactionRef tx;
        stream >> TX_WITH_WITNESS(tx);
        ankerl::nanobench::doNotOptimizeAway(tx);
        bool rewound = stream.Rewind(size);
        assert(rewound);
    });
}

// CMutableTransaction -> CTransaction, as the wallet and the miner's
// aggregation step do with freshly built outputs.
static void BLSCTTransactionFromMutable(benchmark::Bench& bench)
{
    const CMutableTransaction mtx{MakeBLSCTTx(N_OUTPUTS)};
    bench.unit("tx").run([&] {
        CTransactionRef tx{MakeTransactionRef(mtx)};
        ankerl::nanobench::doNotOptimizeAway(tx);
    });
}

BENCHMARK(BLSCTTransactionDeserialize, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTTransactionFromMutable, benchmark::PriorityLevel::HIGH);
