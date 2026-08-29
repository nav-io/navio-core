// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_ARITH_BLST_BLST_INIT_H
#define NAVIO_BLSCT_ARITH_BLST_BLST_INIT_H

// blst has no global state to initialise (no curve parameter setup, no
// serialization-mode switch). The class exists only so `T::Init` is
// well-formed for the templated proof code that does `volatile T::Init init;`.
class BlstInit
{
public:
    BlstInit() {}
};

#endif // NAVIO_BLSCT_ARITH_BLST_BLST_INIT_H
