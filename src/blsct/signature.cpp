// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/signature.h>
#include <streams.h>
#include <tinyformat.h>

#include <algorithm>
#include <cstring>

namespace blsct {

Signature::Signature()
{
    std::memset(&m_data, 0, sizeof(m_data));
}

Signature Signature::Aggregate(const std::vector<blsct::Signature>& sigs)
{
    blsct::Signature aggr_sig;
    for (const auto& sig : sigs) {
        blst_p2_add_or_double(&aggr_sig.m_data, &aggr_sig.m_data, &sig.m_data);
    }
    return aggr_sig;
}

bool Signature::IsZero() const
{
    return blst_p2_is_inf(&m_data);
}

std::vector<uint8_t> Signature::GetVch() const
{
    std::vector<uint8_t> buf(SERIALIZATION_SIZE);
    blst_p2_compress(buf.data(), &m_data);
    return buf;
}

bool Signature::SetVch(const std::vector<uint8_t>& buf)
{
    if (buf.size() != SERIALIZATION_SIZE) {
        *this = Signature();
        return false;
    }
    blst_p2_affine aff{};
    // blst_p2_uncompress validates the encoding and the curve equation.
    if (blst_p2_uncompress(&aff, buf.data()) != BLST_SUCCESS) {
        *this = Signature();
        return false;
    }
    // Enforce prime-order subgroup membership on the deserialized signature.
    // BLS12-381 G2 has a large cofactor, so a point can be on the curve yet
    // outside the order-r subgroup; the aggregate-verify path does not check
    // it again. Without this guard an attacker could submit a txSig with a
    // small-order component added (signature malleability: distinct
    // serialized signatures accepted for the same message set, and forgeries
    // whenever the off-subgroup pairing factor is trivial). Mirrors the guard
    // in BlstG1Point::SetVch. The identity is permitted.
    if (!blst_p2_affine_is_inf(&aff) && !blst_p2_affine_in_g2(&aff)) {
        *this = Signature();
        return false;
    }
    blst_p2_from_affine(&m_data, &aff);
    return true;
}

bool Signature::operator==(const Signature& b) const
{
    return blst_p2_is_equal(&m_data, &b.m_data);
}

} // namespace blsct
