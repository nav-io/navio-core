#include <blsct/building_block/generator_deriver.h>
#include <util/strencodings.h>
#include <optional>

Point GeneratorDeriver::Derive(
    const Point& p,
    const size_t index,
    const std::optional<TokenId>& token_id
) const {
    static const std::string salt(salt_str);
    std::vector<uint8_t> serialized_p = p.GetVch();

    auto num_to_str = [](auto n) {
        std::ostringstream os;
        os << n;
        return os.str();
    };
    std::string hash_preimage =
        HexStr(serialized_p) +
        salt +
        num_to_str(index) +
        (token_id.has_value() ? token_id.value().ToString() : "") +
        (token_id.has_value() ? "nft" + num_to_str(token_id.value().subid) : "");

    CHashWriter ss(SER_GETHASH, 0);
    ss << hash_preimage;
    auto hash = ss.GetHash();

    auto vec_hash = std::vector<uint8_t>(hash.begin(), hash.end());
    auto ret = Point::MapToG1(vec_hash);
    if (ret.IsZero()) {
        throw std::runtime_error(strprintf(
            "%s: Generated G1Point is the point at infinity. Try changing parameters", __func__));
    }
    return ret;
}