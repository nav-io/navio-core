// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_ARITH_MCL_STATIC_MCL_INIT_H
#define NAVCOIN_BLSCT_ARITH_MCL_STATIC_MCL_INIT_H

#define BLS_ETH 1
#include <bls/bls384_256.h>
#include <stdexcept>
#include <blsct/arith/mcl/init/mcl_init.h>

/**
 * Note that:
 * - This class initializes Mcl library for static context
 * - Define this variable before any other static variables
 *   that instantiate MclG1Point class directly or indirectly
 *   are defined
 * - volatile keyword is necessary to protect the line from
 *   comipler optimization
 * - Defining this variable as a global variable results in
 *   memory leaks
*/
class StaticMclInit: MclInit
{
public:
    StaticMclInit()
    {
        Initialize();
    }
};

#endif // NAVCOIN_BLSCT_ARITH_MCL_STATIC_MCL_INIT_H
