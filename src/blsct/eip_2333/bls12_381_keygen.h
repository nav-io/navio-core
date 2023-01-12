// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bls/bls384_256.h> // must include this before bls/bls.h
#include <bls/bls.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <crypto/sha256.h>
#include <crypto/hmac_sha256.h>

class BLS12_381_KeyGen
{
public:
    // Inputs
    // - parent_SK, the secret key of the parent node, a big endian encoded integer
    // - index, the index of the desired child node, an integer 0 <= index < 2^32
    // Outputs
    // - child_SK, the secret key of the child node, a big endian encoded integer
    std::vector<uint8_t> derive_child_SK(const std::vector<uint8_t>& parent_SK, const uint32_t& index);

    // Inputs
    // - seed, the source entropy for the entire tree, a octet string >= 256 bits in length
    // Outputs
    // - SK, the secret key of master node within the tree, a big endian encoded integer
    std::array<uint8_t,32> derive_master_SK(const std::vector<uint8_t>& seed, const std::vector<uint8_t>& SK);

#ifndef BOOST_UNIT_TEST
private:
#endif
    inline static const uint32_t K = 32;  // digest size
    inline static const uint32_t N = 255;  // ? TODO give a better name
    inline static const uint32_t L = K * N;  // HKDF output size

    // TODO check if this remains the same in v5
    inline static std::string r = "52435875175126190479447740508185965837690552500527637822603658699938581184513";

    // TODO check this remains the same in v5 environment as well
    inline static const uint32_t HKDF_mod_r_L = 48; // ceil((3 * ceil(log2(r))) / 16).(L=48)

    // HKDF-Extract is as defined in RFC5869, instantiated with SHA256
    // Inputs:
    // - salt, optional salt value (a non-secret random value); if not provided, it is set to a string of HashLen zeros.
    // - IKM, input keying material
    // Output:
    // - PRK, a pseudorandom key (of HashLen octets)
    static std::array<uint8_t,K> HKDF_Extract(const std::vector<uint8_t>& IKM, const MclScalar& salt = MclScalar{0});

    // HKDF-Expand is as defined in RFC5869, instantiated with SHA256
    // Inputs:
    // - PRK, a pseudorandom key of at least HashLen octets (usually, the output from the extract step) <- for bls12-381 keygen this is fixed to 32
    // - info, optional context and application specific information (can be a zero-length string)
    // - L, length of output keying material in octets (<= 255*HashLen)  <- for bls12-381 keygen this is fixed to 32*255
    // Output:
    // - OKM, output keying material (of L octets)
    static std::array<uint8_t,L> HKDF_Expand(const std::array<uint8_t,K>& PRK, const std::vector<uint8_t>& info);

    // I2OSP converts a nonnegative integer to an octet string of a specified length
    // as defined in RFC3447 (Big endian decoding)
    //
    // I2OSP (x, xLen)
    // Input:
    // - x, nonnegative integer to be converted
    // - xLen, intended length of the resulting octet string
    // Output:
    // - X, corresponding octet string of length xLen
    static std::vector<uint8_t> I2OSP(const MclScalar& x, const size_t& xLen);

    // OS2IP converts an octet string to a nonnegative integer as defined in RFC3447
    // (Big endian encoding)
    // OS2IP (X)
    // Input:
    // - X, octet string to be converted
    // Output:
    // - x, corresponding nonnegative integer
    static MclScalar OS2IP(const std::vector<uint8_t>& X);

    // flip_bits is a function that returns the bitwise negation of its input
    static MclScalar flip_bits(const MclScalar& s);

    // a function that takes in an octet string and splits it into K-byte chunks which are returned as an array
    // expects that length of octet string is N * K
    static std::array<std::array<uint8_t,K>,N> bytes_split(const std::vector<uint8_t>& octet_string);

    // Inputs
    // - IKM, a secret octet string
    // - salt, an octet string
    //
    // Outputs
    // - lamport_SK, an array of 255 32-octet strings
    std::array<uint8_t,BLS12_381_KeyGen::L> IKM_to_lamport_SK(const std::vector<uint8_t>& IKM, const std::vector<uint8_t>& salt);

    // Inputs
    // - parent_SK, the BLS Secret Key of the parent node
    // - index, the index of the desired child node, an integer 0 <= index < 2^32
    //
    // Outputs
    // - lamport_PK, the compressed lamport PK, a 32 octet string Inputs
    std::array<uint8_t,BLS12_381_KeyGen::K> parent_SK_to_lamport_PK(const std::vector<uint8_t>& parent_SK, const uint32_t& index);

    // Inputs
    // - IKM, a secret octet string >= 256 bits in length
    // - key_info, an optional octet string (default="", the empty string)
    // Outputs
    // - SK, the corresponding secret key, an integer 0 <= SK < r.
    MclScalar HKDF_mod_r(const std::vector<uint8_t>& IKM, const std::vector<uint8_t>& key_info = {});
};