#include <blsct/arith/mcl/mcl.h>

#include <bit>
#include <blsct/common.h>
#include <blsct/range_proof/common.h>
#include <blsct/range_proof/setup.h>
#include <blsct/range_proof/bulletproofs/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <tinyformat.h>
#include <stdexcept>
#include <variant>

namespace range_proof {

template <typename T>
typename T::Scalar* Common<T>::m_zero = nullptr;

template <typename T>
typename T::Scalar* Common<T>::m_one = nullptr;

template <typename T>
typename T::Scalar* Common<T>::m_two = nullptr;

template <typename T>
Elements<typename T::Scalar>* Common<T>::m_two_pows_64 = nullptr;

template <typename T>
typename T::Scalar* Common<T>::m_inner_prod_1x2_pows_64 = nullptr;

template <typename T>
typename T::Scalar* Common<T>::m_uint64_max = nullptr;

template <typename T>
range_proof::GeneratorsFactory<T>* Common<T>::m_gf = nullptr;

template <typename T>
const typename T::Scalar& Common<T>::GetUint64Max() const
{
    return *m_uint64_max;
}
template const Mcl::Scalar& Common<Mcl>::GetUint64Max() const;

template <typename T>
range_proof::GeneratorsFactory<T>& Common<T>::Gf() const
{
    return *m_gf;
}
template
range_proof::GeneratorsFactory<Mcl>& Common<Mcl>::Gf() const;

template <typename T>
const typename T::Scalar& Common<T>::Zero() const
{
    return *m_zero;
}
template
const Mcl::Scalar& Common<Mcl>::Zero() const;

template <typename T>
const typename T::Scalar& Common<T>::One() const
{
    return *m_one;
}
template
const Mcl::Scalar& Common<Mcl>::One() const;

template <typename T>
const typename T::Scalar& Common<T>::Two() const
{
    return *m_two;
}
template
const Mcl::Scalar& Common<Mcl>::Two() const;

template <typename T>
const Elements<typename T::Scalar>& Common<T>::TwoPows64() const
{
    return *m_two_pows_64;

}
template
const Elements<Mcl::Scalar>& Common<Mcl>::TwoPows64() const;

template <typename T>
const typename T::Scalar& Common<T>::InnerProd1x2Pows64() const
{
    return *m_inner_prod_1x2_pows_64;

}
template
const Mcl::Scalar& Common<Mcl>::InnerProd1x2Pows64() const;

template <typename T>
const typename T::Scalar& Common<T>::Uint64Max() const
{
    return *m_uint64_max;
}
template
const Mcl::Scalar& Common<Mcl>::Uint64Max() const;

template <typename T>
Common<T>::Common()
{
    using Scalar = typename T::Scalar;
    using Scalars = Elements<Scalar>;

    // Take the lock before reading the flag, as GeneratorsFactory and
    // SetMemProofSetup do. Checked outside, two threads could both see false,
    // serialise here, and both run the initialisation below: the second set of
    // `new`s replaces every static pointer while another thread may be
    // dereferencing the first set, and the first set leaks. The unsynchronised
    // read was also a plain data race against the store at the end: the flag is
    // a non-atomic bool set as the last statement of this critical section, so
    // an early return that never took the lock got no acquire against that
    // release and could see it true while m_gf was still null - and Gf()
    // dereferences that pointer without a lock.
    std::lock_guard<std::mutex> lock(Common<T>::m_init_mutex);
    if (m_is_initialized) return;

    Common<T>::m_zero = new Scalar(0);
    Common<T>::m_one = new Scalar(1);
    Common<T>::m_two = new Scalar(2);
    Common<T>::m_gf = new range_proof::GeneratorsFactory<T>();
    {
        auto two_pows_64 = Scalars::FirstNPow(*m_two, range_proof::Setup::num_input_value_bits);
        Common<T>::m_two_pows_64 = new Scalars(two_pows_64);
        auto ones_64 = Scalars::RepeatN(*Common<T>::m_one, range_proof::Setup::num_input_value_bits);
        Common<T>::m_inner_prod_1x2_pows_64 =
            new Scalar((ones_64 * *Common<T>::m_two_pows_64).Sum());
    }
    {
        Scalar int64_max(INT64_MAX);
        Scalar one(1);
        Scalar uint64_max = (int64_max << 1) + one;
        Common<T>::m_uint64_max = new Scalar(uint64_max);
    }
    m_is_initialized = true;
}
template Common<Mcl>::Common();

template <typename T>
size_t Common<T>::GetNumRoundsExclLast(
    const size_t& num_input_values
) {
    // Both operands are exact powers of two, so log2 is bit_width - 1;
    // integer arithmetic avoids the double round-trip of std::log2 (exact
    // today, but a floating-point step has no place in a consensus count).
    auto num_input_values_pow2 =
        blsct::Common::GetFirstPowerOf2GreaterOrEqTo(num_input_values);
    static_assert(std::has_single_bit(range_proof::Setup::num_input_value_bits));
    auto num_rounds =
        static_cast<size_t>(std::bit_width(num_input_values_pow2) - 1) +
        static_cast<size_t>(std::bit_width(range_proof::Setup::num_input_value_bits) - 1);

    return num_rounds;
}
template
size_t Common<Mcl>::GetNumRoundsExclLast(
    const size_t& num_input_values
);

template <typename T>
void Common<T>::ValidateParameters(
    const Elements<typename T::Scalar>& vs,
    const std::vector<uint8_t>& message
) {
    if (message.size() > range_proof::Setup::max_message_size) {
        throw std::runtime_error(strprintf("%s: message size is too large", __func__));
    }
    if (vs.Empty()) {
        throw std::runtime_error(strprintf("%s: no input values to prove", __func__));
    }
    if (vs.Size() > range_proof::Setup::max_input_values) {
        throw std::runtime_error(strprintf("%s: number of input values exceeds the maximum", __func__));
    }
}
template
void Common<Mcl>::ValidateParameters(
    const Elements<Mcl::Scalar>& vs,
    const std::vector<uint8_t>& message
);

template <typename T>
template <typename P>
void Common<T>::ValidateProofsBySizes(
    const std::vector<P>& proofs
) {
    for (const auto& proof : proofs) {
        // proof must contain input values
        if (proof.Vs.Size() == 0)
            throw std::runtime_error(strprintf("%s: no input value", __func__));

        // invalid if # of input values are lager than maximum
        if (proof.Vs.Size() > range_proof::Setup::max_input_values)
            throw std::runtime_error(strprintf("%s: number of input values exceeds the maximum %ld",
                                               __func__, range_proof::Setup::max_input_values));

        // L,R keep track of aggregation history and the size should equal to # of rounds
        size_t num_rounds = range_proof::Common<T>::GetNumRoundsExclLast(proof.Vs.Size());
        if (proof.Ls.Size() != num_rounds)
            throw std::runtime_error(strprintf("%s: size of Ls (%ld) differs from number of intermediate rounds (%ld)",
                                               __func__, proof.Ls.Size(), num_rounds));

        // if Ls and Rs should have the same size
        if (proof.Ls.Size() != proof.Rs.Size())
            throw std::runtime_error(strprintf("%s: size of Ls (%ld) differs from size of Rs (%ld)",
                                               __func__, proof.Ls.Size(), proof.Rs.Size()));
    }
}
template void Common<Mcl>::ValidateProofsBySizes(
    const std::vector<bulletproofs::RangeProofWithSeed<Mcl>>&);
template void Common<Mcl>::ValidateProofsBySizes(
    const std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>&);
}


// ---------------------------------------------------------------------------
// Optional supranational/blst arith backend (cmake -DWITH_BLST=ON). Mirrors
// the Mcl instantiations above 1:1; compiled out of default builds.
#ifdef NAVIO_BLSCT_ARITH_BLST
#include <blsct/arith/blst/blst.h>
namespace range_proof {
template const Blst::Scalar& Common<Blst>::GetUint64Max() const;
template
range_proof::GeneratorsFactory<Blst>& Common<Blst>::Gf() const;
template
const Blst::Scalar& Common<Blst>::Zero() const;
template
const Blst::Scalar& Common<Blst>::One() const;
template
const Blst::Scalar& Common<Blst>::Two() const;
template
const Elements<Blst::Scalar>& Common<Blst>::TwoPows64() const;
template
const Blst::Scalar& Common<Blst>::InnerProd1x2Pows64() const;
template
const Blst::Scalar& Common<Blst>::Uint64Max() const;
template Common<Blst>::Common();
template
size_t Common<Blst>::GetNumRoundsExclLast(
    const size_t& num_input_values
);
template
void Common<Blst>::ValidateParameters(
    const Elements<Blst::Scalar>& vs,
    const std::vector<uint8_t>& message
);
template void Common<Blst>::ValidateProofsBySizes(
    const std::vector<bulletproofs_plus::RangeProofWithSeed<Blst>>&);
} // namespace range_proof
#endif // NAVIO_BLSCT_ARITH_BLST
