// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_ARITH_BLST_BLST_H
#define NAVIO_BLSCT_ARITH_BLST_BLST_H

#include <blsct/arith/blst/blst_g1point.h>
#include <blsct/arith/blst/blst_init.h>
#include <blsct/arith/blst/blst_scalar.h>
#include <blsct/arith/blst/blst_util.h>

// Arith backend over supranational/blst. Drop-in for `Mcl` in the templated
// proof code (RangeProofLogic<Blst>, SetMemProofProver<Blst>, ...). Built only
// with -DWITH_BLST=ON; see cmake/blst.cmake and doc/blsct-blst-evaluation.md.
struct Blst {
    using Scalar = BlstScalar;
    using Point = BlstG1Point;
    using Util = BlstUtil;
    using Init = BlstInit;
};

#endif // NAVIO_BLSCT_ARITH_BLST_BLST_H
