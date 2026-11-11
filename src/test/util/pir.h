// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_PIR_H
#define BITCOIN_TEST_UTIL_PIR_H

#include <pir/simplepir.h>
#include <uint256.h>

#include <memory>

namespace pir {
/**
 * A SecretRng that produces the stream of FastRandomContext(seed), so tests
 * and fuzz targets get reproducible queries. Only in the test utility
 * library: queries made with it are not private.
 */
std::unique_ptr<SecretRng> MakeSecretRngForTesting(const uint256& seed);
} // namespace pir

#endif // BITCOIN_TEST_UTIL_PIR_H
