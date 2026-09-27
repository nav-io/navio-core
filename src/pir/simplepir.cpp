// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pir/simplepir.h>

#include <crypto/chacha20.h>
#include <crypto/common.h>
#include <random.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>

namespace pir {

namespace {

//! ChaCha20 blocks per row of A.
constexpr uint32_t BLOCKS_PER_ROW{LWE_N * 4 / 64};
static_assert(LWE_N * 4 % 64 == 0);
//! Rows of A are addressed by a 32-bit ChaCha20 block counter.
static_assert(uint64_t{MAX_COLS} * BLOCKS_PER_ROW <= uint64_t{1} << 32);

//! Columns processed together while building a hint: their rows of A
//! (128 KiB) are expanded once and streamed through HintKernel for every
//! group of hint rows.
constexpr uint32_t HINT_BLOCK{32};

//! Largest error magnitude the sampler produces (10 standard deviations).
constexpr int32_t ERROR_TAIL{64};

//! Database entry as a centred value in [-128, 127], lifted to Z_q.
inline uint32_t Lift(uint8_t byte) { return static_cast<uint32_t>(static_cast<int32_t>(static_cast<int8_t>(byte))); }

//! Cumulative distribution of |e| for the discrete Gaussian, as 64-bit thresholds.
const std::array<uint64_t, ERROR_TAIL>& ErrorCdt()
{
    static const std::array<uint64_t, ERROR_TAIL> cdt = [] {
        std::array<double, ERROR_TAIL + 1> weight;
        double total{0};
        for (int32_t m = 0; m <= ERROR_TAIL; ++m) {
            // |e| = m > 0 covers both signs.
            weight[m] = std::exp(-double(m) * m / (2 * SIGMA * SIGMA)) * (m == 0 ? 1 : 2);
            total += weight[m];
        }
        std::array<uint64_t, ERROR_TAIL> out;
        double cumulative{0};
        for (int32_t m = 0; m < ERROR_TAIL; ++m) {
            cumulative += weight[m];
            // 2^64 * P(|e| <= m); saturates below 2^64.
            const double scaled{std::ldexp(cumulative / total, 64)};
            out[m] = scaled >= 18446744073709551615.0 ? ~uint64_t{0} : static_cast<uint64_t>(scaled);
        }
        return out;
    }();
    return cdt;
}

} // namespace

bool Params::IsValid() const
{
    if (record_bytes == 0 || records_per_col == 0) return false;
    if (uint64_t{record_bytes} * records_per_col > MAX_ROWS) return false;
    if (Cols() > MAX_COLS) return false;
    return true;
}

uint32_t ChooseRecordsPerCol(uint32_t num_records)
{
    if (num_records <= MAX_COLS) return 1;
    return (num_records - 1) / MAX_COLS + 1;
}

double ErrorStdDevOverHalfDelta(uint32_t cols)
{
    // Worst case: every centred entry at the extreme |d| = p / 2.
    return SIGMA * double(uint32_t{1} << (LOG_P - 1)) * std::sqrt(double(cols)) / (DELTA / 2.0);
}

void ExpandA(const uint256& seed, uint32_t first, uint32_t count, uint32_t* out)
{
    Assert(uint64_t{first} + count <= MAX_COLS);
    const uint32_t first_block{first * BLOCKS_PER_ROW};
    const uint32_t blocks{count * BLOCKS_PER_ROW};
#if defined(__GNUC__) || defined(__clang__)
    // ChaCha20 (the ChaCha20Aligned block function, zero nonce) four blocks
    // at a time in SIMD lanes. The scalar ChaCha20 class runs at about
    // 0.4 GB/s on an Apple M2, and expanding A dominates the client's query
    // cost. Each output word is the keystream read as a little-endian
    // uint32_t, i.e. the block function's output word.
    typedef uint32_t V __attribute__((vector_size(16)));
    uint32_t key[8];
    for (int i = 0; i < 8; ++i) key[i] = ReadLE32(seed.data() + 4 * i);
    const V c0{0x61707865, 0x61707865, 0x61707865, 0x61707865};
    const V c1{0x3320646e, 0x3320646e, 0x3320646e, 0x3320646e};
    const V c2{0x79622d32, 0x79622d32, 0x79622d32, 0x79622d32};
    const V c3{0x6b206574, 0x6b206574, 0x6b206574, 0x6b206574};
    V k[8];
    for (int i = 0; i < 8; ++i) k[i] = V{key[i], key[i], key[i], key[i]};
#define PIR_ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#if defined(__clang__)
    // Byte-granular rotations as single shuffles (rev32 / tbl on ARM, pshufb on x86).
    typedef uint8_t B __attribute__((vector_size(16)));
    auto rotl16 = [](V v) { return (V)__builtin_shufflevector((B)v, (B)v, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13); };
    auto rotl8 = [](V v) { return (V)__builtin_shufflevector((B)v, (B)v, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14); };
#else
    auto rotl16 = [](V v) { return PIR_ROTL(v, 16); };
    auto rotl8 = [](V v) { return PIR_ROTL(v, 8); };
#endif
#define PIR_QR(a, b, c, d)          \
    a += b; d = rotl16(d ^ a);      \
    c += d; b = PIR_ROTL(b ^ c, 12); \
    a += b; d = rotl8(d ^ a);       \
    c += d; b = PIR_ROTL(b ^ c, 7);
    for (uint32_t b0 = 0; b0 < blocks; b0 += 4) {
        const uint32_t ctr{first_block + b0};
        const V j12{ctr, ctr + 1, ctr + 2, ctr + 3};
        V x0{c0}, x1{c1}, x2{c2}, x3{c3};
        V x4{k[0]}, x5{k[1]}, x6{k[2]}, x7{k[3]}, x8{k[4]}, x9{k[5]}, x10{k[6]}, x11{k[7]};
        V x12{j12}, x13{}, x14{}, x15{};
        for (int round = 0; round < 10; ++round) {
            PIR_QR(x0, x4, x8, x12)
            PIR_QR(x1, x5, x9, x13)
            PIR_QR(x2, x6, x10, x14)
            PIR_QR(x3, x7, x11, x15)
            PIR_QR(x0, x5, x10, x15)
            PIR_QR(x1, x6, x11, x12)
            PIR_QR(x2, x7, x8, x13)
            PIR_QR(x3, x4, x9, x14)
        }
        const V x[16]{x0 + c0, x1 + c1, x2 + c2, x3 + c3, x4 + k[0], x5 + k[1], x6 + k[2], x7 + k[3],
                      x8 + k[4], x9 + k[5], x10 + k[6], x11 + k[7], x12 + j12, x13, x14, x15};
        if (blocks - b0 >= 4) {
            for (uint32_t l = 0; l < 4; ++l) {
                uint32_t* o{out + size_t{b0 + l} * 16};
                for (int i = 0; i < 16; ++i) o[i] = x[i][l];
            }
        } else {
            for (uint32_t l = 0; l < blocks - b0; ++l) {
                uint32_t* o{out + size_t{b0 + l} * 16};
                for (int i = 0; i < 16; ++i) o[i] = x[i][l];
            }
        }
    }
#undef PIR_QR
#undef PIR_ROTL
#else
    ChaCha20 chacha{MakeByteSpan(seed)};
    chacha.Seek({0, 0}, first_block);
    std::byte* bytes{reinterpret_cast<std::byte*>(out)};
    chacha.Keystream({bytes, size_t{blocks} * 64});
    for (size_t i = 0; i < size_t{blocks} * 16; ++i) {
        out[i] = ReadLE32(reinterpret_cast<const unsigned char*>(bytes + 4 * i));
    }
#endif
}

Database::Database(uint32_t record_bytes, uint32_t records_per_col)
{
    m_params.record_bytes = record_bytes;
    m_params.records_per_col = records_per_col;
}

void Database::Append(Span<const uint8_t> record)
{
    Assert(record.size() == m_params.record_bytes);
    m_data.insert(m_data.end(), record.begin(), record.end());
    ++m_params.num_records;
}

void Database::Truncate(uint32_t n)
{
    Assert(n <= m_params.num_records);
    m_params.num_records = n;
    m_data.resize(size_t{n} * m_params.record_bytes);
}

Span<const uint8_t> Database::Record(uint32_t i) const
{
    Assert(i < m_params.num_records);
    return Span{m_data}.subspan(size_t{i} * m_params.record_bytes, m_params.record_bytes);
}

Hint ComputeHint(const Database& db, const uint256& seed)
{
    Hint hint(size_t{db.GetParams().Rows()} * LWE_N, 0);
    ExtendHint(hint, db, seed, 0);
    return hint;
}

namespace {
//! Hint rows accumulated together by the kernel below.
constexpr uint32_t KERNEL_ROWS{4};
//! Hint columns (entries of a row) accumulated together.
constexpr uint32_t KERNEL_COLS{16};
static_assert(LWE_N % KERNEL_COLS == 0);

/**
 * h[r][x] += sum over u < m of coef[u * R + r] * a[u][x], for the R hint rows
 * h[0..R) and all x: a small matrix product blocked so that an R x KERNEL_COLS
 * tile of the hint stays in registers while the m rows of A stream by.
 */
template <uint32_t R>
void HintKernel(uint32_t* const* h, const uint32_t* coef, const uint32_t* const* a, uint32_t m)
{
    for (uint32_t x0 = 0; x0 < LWE_N; x0 += KERNEL_COLS) {
        uint32_t acc[R][KERNEL_COLS];
        for (uint32_t r = 0; r < R; ++r) {
            for (uint32_t xx = 0; xx < KERNEL_COLS; ++xx) acc[r][xx] = h[r][x0 + xx];
        }
        for (uint32_t u = 0; u < m; ++u) {
            const uint32_t* au{a[u] + x0};
            for (uint32_t r = 0; r < R; ++r) {
                const uint32_t c{coef[u * R + r]};
                for (uint32_t xx = 0; xx < KERNEL_COLS; ++xx) acc[r][xx] += c * au[xx];
            }
        }
        for (uint32_t r = 0; r < R; ++r) {
            for (uint32_t xx = 0; xx < KERNEL_COLS; ++xx) h[r][x0 + xx] = acc[r][xx];
        }
    }
}
} // namespace

void ExtendHint(Hint& hint, const Database& db, const uint256& seed, uint32_t first_record)
{
    const Params& p{db.GetParams()};
    Assert(p.IsValid());
    Assert(hint.size() == size_t{p.Rows()} * LWE_N);
    const uint32_t L{p.record_bytes};
    const uint32_t k{p.records_per_col};
    const uint32_t cols{p.Cols()};
    const uint8_t* data{db.Data().data()};

    std::vector<uint32_t> a_block(size_t{HINT_BLOCK} * LWE_N);
    std::array<uint32_t, HINT_BLOCK * KERNEL_ROWS> coef;
    for (uint32_t j0 = first_record / k; j0 < cols; j0 += HINT_BLOCK) {
        const uint32_t nb{std::min(HINT_BLOCK, cols - j0)};
        ExpandA(seed, j0, nb, a_block.data());
        for (uint32_t t = 0; t < k; ++t) {
            // The records of this slot in these columns that are new.
            std::array<const uint8_t*, HINT_BLOCK> recs;
            std::array<const uint32_t*, HINT_BLOCK> arows;
            uint32_t m{0};
            for (uint32_t jj = 0; jj < nb; ++jj) {
                const uint64_t i{uint64_t{j0 + jj} * k + t};
                if (i < first_record || i >= p.num_records) continue;
                recs[m] = data + i * L;
                arows[m] = a_block.data() + size_t{jj} * LWE_N;
                ++m;
            }
            if (m == 0) continue;
            uint32_t* rows[KERNEL_ROWS];
            uint32_t b{0};
            for (; b + KERNEL_ROWS <= L; b += KERNEL_ROWS) {
                uint32_t any{0};
                for (uint32_t u = 0; u < m; ++u) {
                    for (uint32_t r = 0; r < KERNEL_ROWS; ++r) any |= coef[u * KERNEL_ROWS + r] = Lift(recs[u][b + r]);
                }
                if (any == 0) continue;
                for (uint32_t r = 0; r < KERNEL_ROWS; ++r) rows[r] = hint.data() + (size_t{t} * L + b + r) * LWE_N;
                HintKernel<KERNEL_ROWS>(rows, coef.data(), arows.data(), m);
            }
            for (; b < L; ++b) {
                for (uint32_t u = 0; u < m; ++u) coef[u] = Lift(recs[u][b]);
                rows[0] = hint.data() + (size_t{t} * L + b) * LWE_N;
                HintKernel<1>(rows, coef.data(), arows.data(), m);
            }
        }
    }
}

std::optional<std::vector<uint32_t>> Answer(const Database& db, Span<const uint32_t> query, uint32_t num_records)
{
    const Params& full{db.GetParams()};
    if (num_records > full.num_records) return std::nullopt;
    Params p{full};
    p.num_records = num_records;
    // A prefix that ends inside a column would leave that column different
    // from the one the client's hint was computed over.
    if (num_records != full.num_records && num_records % p.records_per_col != 0) return std::nullopt;
    if (!p.IsValid() || query.size() != p.Cols()) return std::nullopt;

    const uint32_t L{p.record_bytes};
    const uint32_t k{p.records_per_col};
    const uint32_t cols{p.Cols()};
    const uint8_t* data{db.Data().data()};
    std::vector<uint32_t> out(p.Rows(), 0);
    // Walk the database in storage order (column after column, each column's
    // slots in turn), four columns at a time while all four are full.
    uint32_t j{0};
    for (; j + 4 <= cols && uint64_t{j + 4} * k <= num_records; j += 4) {
        const uint32_t q0{query[j]}, q1{query[j + 1]}, q2{query[j + 2]}, q3{query[j + 3]};
        for (uint32_t t = 0; t < k; ++t) {
            uint32_t* a{out.data() + size_t{t} * L};
            const uint8_t* r0{data + (uint64_t{j} * k + t) * L};
            const uint8_t* r1{r0 + uint64_t{k} * L};
            const uint8_t* r2{r1 + uint64_t{k} * L};
            const uint8_t* r3{r2 + uint64_t{k} * L};
            for (uint32_t b = 0; b < L; ++b) {
                a[b] += q0 * Lift(r0[b]) + q1 * Lift(r1[b]) + q2 * Lift(r2[b]) + q3 * Lift(r3[b]);
            }
        }
    }
    for (; j < cols; ++j) {
        const uint32_t q{query[j]};
        for (uint32_t t = 0; t < k; ++t) {
            const uint64_t i{uint64_t{j} * k + t};
            if (i >= num_records) break;
            uint32_t* a{out.data() + size_t{t} * L};
            const uint8_t* r{data + i * L};
            for (uint32_t b = 0; b < L; ++b) a[b] += q * Lift(r[b]);
        }
    }
    return out;
}

int32_t SampleError(FastRandomContext& rng)
{
    const auto& cdt{ErrorCdt()};
    const uint64_t u{rng.rand64()};
    int32_t mag{0};
    // Constant-time scan: count the thresholds u is at or above.
    for (int32_t m = 0; m < ERROR_TAIL; ++m) mag += static_cast<int32_t>(u >= cdt[m]);
    const int32_t sign{static_cast<int32_t>(rng.randbits(1))};
    return mag - 2 * sign * mag;
}

std::optional<std::vector<uint32_t>> MakeQuery(const Params& params, const uint256& seed, uint32_t index,
                                               FastRandomContext& rng, QueryState& state)
{
    if (!params.IsValid() || index >= params.num_records) return std::nullopt;
    state.params = params;
    state.index = index;
    state.secret.resize(LWE_N);
    for (auto& s : state.secret) s = rng.rand32();

    const uint32_t cols{params.Cols()};
    const uint32_t col{index / params.records_per_col};
    std::vector<uint32_t> query(cols);
    constexpr uint32_t BLOCK{64};
    std::vector<uint32_t> a_block(size_t{BLOCK} * LWE_N);
    const uint32_t* s{state.secret.data()};
    for (uint32_t j0 = 0; j0 < cols; j0 += BLOCK) {
        const uint32_t nb{std::min(BLOCK, cols - j0)};
        ExpandA(seed, j0, nb, a_block.data());
        for (uint32_t jj = 0; jj < nb; ++jj) {
            const uint32_t* a{a_block.data() + size_t{jj} * LWE_N};
            uint32_t acc{0};
            for (uint32_t x = 0; x < LWE_N; ++x) acc += a[x] * s[x];
            query[j0 + jj] = acc + static_cast<uint32_t>(SampleError(rng));
        }
    }
    query[col] += DELTA;
    return query;
}

std::optional<std::vector<uint8_t>> Decode(const QueryState& state, Span<const uint32_t> hint, Span<const uint32_t> answer)
{
    const Params& p{state.params};
    if (!p.IsValid() || state.secret.size() != LWE_N) return std::nullopt;
    if (hint.size() != size_t{p.Rows()} * LWE_N || answer.size() != p.Rows()) return std::nullopt;
    const uint32_t L{p.record_bytes};
    const uint32_t t{state.index % p.records_per_col};
    const uint32_t* s{state.secret.data()};
    std::vector<uint8_t> out(L);
    for (uint32_t b = 0; b < L; ++b) {
        const size_t row{size_t{t} * L + b};
        const uint32_t* h{hint.data() + row * LWE_N};
        uint32_t hs{0};
        for (uint32_t x = 0; x < LWE_N; ++x) hs += h[x] * s[x];
        const uint32_t noisy{answer[row] - hs};
        // Round to the nearest multiple of Delta; the top LOG_P bits are the
        // centred entry mod p, i.e. the byte.
        out[b] = static_cast<uint8_t>((noisy + DELTA / 2) >> (32 - LOG_P));
    }
    return out;
}

std::unique_ptr<FastRandomContext> MakeSecretRng()
{
    uint256 key;
    GetStrongRandBytes(key);
    return std::make_unique<FastRandomContext>(key);
}

} // namespace pir
