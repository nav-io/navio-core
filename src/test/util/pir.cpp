// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/pir.h>

namespace pir {
std::unique_ptr<SecretRng> MakeSecretRngForTesting(const uint256& seed)
{
    return std::unique_ptr<SecretRng>{new SecretRng{seed}};
}
} // namespace pir
