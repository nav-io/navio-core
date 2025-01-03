// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/address.h>

#ifdef LIBBLSCT
#include <blsct/external_api/blsct.h>
#include <blsct/key_io.h>
#endif

namespace blsct {
SubAddress::SubAddress(const std::string& sAddress)
{
#ifdef LIBBLSCT
    auto chain = get_chain();
    auto maybe_dpk = DecodeDoublePublicKey(chain, sAddress);
    if (maybe_dpk) {
        auto dpk = maybe_dpk.value();
        if (dpk.IsValid()) {
            pk = dpk;
        } else {
            throw std::runtime_error(std::string(__func__) + ": invalid double public key: " + sAddress);
        }
    }
#else
    auto dest = DecodeDestination(sAddress);
    if (std::holds_alternative<blsct::DoublePublicKey>(dest)) {
        pk = std::get<blsct::DoublePublicKey>(dest);
    }
#endif
}

SubAddress::SubAddress(const PrivateKey& viewKey, const PublicKey& spendKey, const SubAddressIdentifier& subAddressId)
{
    if (!viewKey.IsValid() || !spendKey.IsValid()) {
        throw std::runtime_error(std::string(__func__) + ": no valid blsct keys");
    }

    HashWriter string{};

    string << std::vector<unsigned char>(subAddressHeader.begin(), subAddressHeader.end());
    string << viewKey;
    string << subAddressId.account;
    string << subAddressId.address;

    // m = Hs(a || i)
    // M = m*G
    // D = B + M
    // C = a*D
    MclScalar m{string.GetHash()};
    MclG1Point M = MclG1Point::GetBasePoint() * m;
    MclG1Point B = spendKey.GetG1Point();

    MclG1Point D = M + B;
    auto C = D * viewKey.GetScalar();
    pk = DoublePublicKey(C, D);
}

std::string SubAddress::GetString() const
{
#ifdef LIBBLSCT
    auto chain = get_chain();
    auto enc_dpk = EncodeDoublePublicKey(
        chain,
        bech32_mod::Encoding::BECH32M,
        pk
    );
    return enc_dpk;
#else
    return EncodeDestination(pk);
#endif
}

CTxDestination SubAddress::GetDestination() const
{
    if (!IsValid())
        return CNoDestination();
    return pk;
}

bool SubAddress::IsValid() const
{
    return pk.IsValid();
}

bool SubAddress::operator==(const SubAddress& rhs) const
{
    return pk == rhs.pk;
}

bool SubAddress::operator<(const SubAddress& rhs) const
{
    return pk == rhs.pk ? pk < rhs.pk : pk < rhs.pk;
};
} // namespace blsct
