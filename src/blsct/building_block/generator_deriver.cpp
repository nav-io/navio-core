#include <blsct/building_block/generator_deriver.h>
#include <blsct/arith/mcl/mcl.h>
#include <util/strencodings.h>
#include <hash.h>
#include <optional>

template <typename Point>
Point GeneratorDeriver<Point>::Derive(
    const Point& p,
    const size_t index,
    const std::optional<TokenId>& token_id
) const {
    std::vector<uint8_t> serialized_p = p.GetVch();

    auto num_to_str = [](auto n) {
        std::ostringstream os;
        os << n;
        return os.str();
    };
    std::string hash_preimage =
        HexStr(serialized_p) +
        salt_str +
        num_to_str(index) +
        (token_id.has_value() ? token_id.value().ToString() : "") +
        (token_id.has_value() ? "nft" + num_to_str(token_id.value().subid) : "");

    CHashWriter ss(SER_GETHASH, 0);
    ss << hash_preimage;
    auto hash = ss.GetHash();

    auto vec_hash = std::vector<uint8_t>(hash.begin(), hash.end());
    auto ret = Point::MapToPoint(vec_hash);
    if (ret.IsZero()) {
        throw std::runtime_error(strprintf(
            "%s: Generated G1Point is the point at infinity. Try changing parameters", __func__));
    }
    return ret;
}
template
typename Mcl::Point GeneratorDeriver<typename Mcl::Point>::Derive(
    const Mcl::Point& p,
    const size_t index,
    const std::optional<TokenId>& token_id
) const;
