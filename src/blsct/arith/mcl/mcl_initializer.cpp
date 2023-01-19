// Copyright (c) 2022 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BLS_ETH 1
#include <bls/bls384_256.h> // must include this before bls/bls.h

#include <blsct/arith/mcl/mcl_initializer.h>

void MclInitializer::Init()
{
    boost::lock_guard<boost::mutex> lock(MclInitializer::m_init_mutex);
    static bool is_initialized = false;
    if (is_initialized) return;

    if (blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR) != 0) {
        throw std::runtime_error("blsInit failed");
    }
	// auto r = blsSetETHmode(BLS_ETH_MODE_DRAFT_07);
	// if (r != 0) {
	// 	printf("err blsSetETHmode %d\n", r);
	// 	throw std::runtime_error("");
	// }
    mclBn_setETHserialization(1);

    is_initialized = true;
}