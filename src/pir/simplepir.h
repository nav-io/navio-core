// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_PIR_SIMPLEPIR_H
#define NAVIO_PIR_SIMPLEPIR_H

#include <span.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

class FastRandomContext;

/**
 * Single-server private information retrieval after SimplePIR (Henzinger,
 * Hong, Corrigan-Gibbs, Meiklejohn, Vaikuntanathan: "One Server for the Price
 * of Two: Simple and Fast Single-Server Private Information Retrieval",
 * USENIX Security 2023).
 *
 * PROTOTYPE, NOT AUDITED. The LWE parameters are the ones the paper selects
 * for 128-bit security (secret dimension n = 1024, modulus q = 2^32, discrete
 * Gaussian error with standard deviation 6.4); they have not been reviewed
 * for this use.
 *
 * Layout. A database of `num_records` records of `record_bytes` bytes is a
 * matrix D over Z_p with p = 2^8, one byte per entry, each byte read as a
 * centred value in [-128, 127] (two's complement int8_t) so that the noise
 * growth is that of a centred distribution and zero padding adds none. Records
 * are stacked `records_per_col` (k) at a time into columns: record i is
 * column i / k, rows [(i % k) * record_bytes, (i % k + 1) * record_bytes).
 * Stored column after column this is simply the records back to back, so a
 * database that only grows at the end only gains columns (or fills its last
 * one), and the hint can be updated incrementally.
 *
 * Protocol, for a public matrix A in Z_q^{cols x n} expanded from a seed:
 *   hint   H = D * A                            (rows x n, once per database)
 *   query  q = A * s + e + Delta * u_col        (cols entries, s uniform, e Gaussian)
 *   answer a = D * q                            (rows entries)
 *   decode round((a - H * s) / Delta) mod p     (the whole column)
 * with Delta = q / p = 2^24. All arithmetic mod 2^32 is plain uint32_t
 * wrap-around. The query hides the column under LWE; the server learns
 * nothing about which record is fetched.
 */
namespace pir {

/** LWE secret dimension. */
static constexpr uint32_t LWE_N{1024};
/** log2 of the plaintext modulus p: one database byte per matrix entry. */
static constexpr uint32_t LOG_P{8};
/** Delta = q / p with q = 2^32. */
static constexpr uint32_t DELTA{uint32_t{1} << (32 - LOG_P)};
/** Standard deviation of the discrete Gaussian error. */
static constexpr double SIGMA{6.4};
/**
 * Maximum number of columns (LWE samples in one query). Bounds the query to
 * 2 MiB and keeps the decryption error far below Delta / 2: the error in one
 * answer entry is a sum of `cols` products of a centred byte (|d| <= 128) and
 * a Gaussian sample, so its standard deviation is at most
 * SIGMA * 128 * sqrt(cols) ~ 2^19.2 at 2^19 columns, against
 * Delta / 2 = 2^23: a wrong byte needs a deviation of over 14 standard
 * deviations. See ErrorStdDevOverHalfDelta().
 */
static constexpr uint32_t MAX_COLS{uint32_t{1} << 19};
/** Maximum rows (record_bytes * records_per_col): bounds hint and answer size. */
static constexpr uint32_t MAX_ROWS{uint32_t{1} << 16};

/** Shape of a database. */
struct Params {
    uint32_t record_bytes{0};
    uint32_t num_records{0};
    uint32_t records_per_col{1};

    uint32_t Rows() const { return record_bytes * records_per_col; }
    uint32_t Cols() const { return num_records == 0 ? 0 : (num_records - 1) / records_per_col + 1; }
    /** Whether the shape is within the limits above and internally consistent. */
    bool IsValid() const;

    uint64_t DatabaseBytes() const { return uint64_t{num_records} * record_bytes; }
    uint64_t HintBytes() const { return uint64_t{Rows()} * LWE_N * 4; }
    uint64_t QueryBytes() const { return uint64_t{Cols()} * 4; }
    uint64_t AnswerBytes() const { return uint64_t{Rows()} * 4; }

    bool operator==(const Params&) const = default;
};

/**
 * The records_per_col to use for a database of num_records records: the
 * smallest k that keeps the column count within MAX_COLS. k = 1 gives the
 * smallest hint (record_bytes x n, independent of the database size), which
 * for single-output fetches minimises hint + query traffic up to about 2^20
 * records; above MAX_COLS records k grows to keep the query bounded.
 */
uint32_t ChooseRecordsPerCol(uint32_t num_records);

/** Standard deviation of the decryption error in one answer entry, in units of Delta / 2. */
double ErrorStdDevOverHalfDelta(uint32_t cols);

/**
 * Write rows [first, first + count) of the public matrix A (each LWE_N
 * uint32_t) to out. Row j is bytes [4 * LWE_N * j, 4 * LWE_N * (j + 1)) of
 * the ChaCha20 keystream keyed with the seed (zero nonce), read as
 * little-endian uint32_t: the stream FastRandomContext(seed) produces, but
 * seekable so rows can be expanded independently and in any order.
 */
void ExpandA(const uint256& seed, uint32_t first, uint32_t count, uint32_t* out);

/** The database: the records back to back, record_bytes each. */
class Database
{
public:
    Database() = default;
    explicit Database(uint32_t record_bytes, uint32_t records_per_col = 1);

    /** Append a record (size must equal record_bytes). */
    void Append(Span<const uint8_t> record);
    /** Drop records from the end so that num_records == n. */
    void Truncate(uint32_t n);
    /** Change records_per_col (the hint must then be recomputed). */
    void SetRecordsPerCol(uint32_t k) { m_params.records_per_col = k; }
    void Reserve(uint32_t n) { m_data.reserve(size_t{n} * m_params.record_bytes); }

    const Params& GetParams() const { return m_params; }
    Span<const uint8_t> Record(uint32_t i) const;
    const std::vector<uint8_t>& Data() const { return m_data; }

private:
    Params m_params;
    std::vector<uint8_t> m_data;
};

/** Hint H = D * A: Rows() x LWE_N, row-major. */
using Hint = std::vector<uint32_t>;

/** Compute the hint of the whole database. */
Hint ComputeHint(const Database& db, const uint256& seed);

/**
 * Add the contribution of records [first_record, num_records) to a hint of
 * the database's first `first_record` records (same records_per_col). Since
 * H = sum over records of (record entries) x (row of A of its column), this is
 * exactly the hint of the whole database.
 */
void ExtendHint(Hint& hint, const Database& db, const uint256& seed, uint32_t first_record);

/**
 * Answer a query against the database's first `num_records` records (at
 * most db.num_records; must be a multiple of records_per_col unless it is all
 * of them, so every column used is the same as in that prefix database).
 * Returns std::nullopt if the query has the wrong length.
 */
std::optional<std::vector<uint32_t>> Answer(const Database& db, Span<const uint32_t> query, uint32_t num_records);

/** Client state for one query: kept secret until the answer is decoded. */
struct QueryState {
    Params params;
    uint32_t index{0};
    std::vector<uint32_t> secret;
};

/** Sample one discrete Gaussian value (standard deviation SIGMA, |x| <= 64). */
int32_t SampleError(FastRandomContext& rng);

/**
 * Build the query for record `index` of a database with the given shape.
 * rng must be a cryptographically secure generator seeded from strong
 * randomness (see MakeSecretRng); it provides the secret and the errors.
 * Returns std::nullopt for invalid params or index.
 */
std::optional<std::vector<uint32_t>> MakeQuery(const Params& params, const uint256& seed, uint32_t index,
                                               FastRandomContext& rng, QueryState& state);

/**
 * Decode an answer into the queried record's bytes. Needs the rows of the
 * hint for the record's slot; `hint` is the full hint (Rows() x LWE_N).
 * Returns std::nullopt if the hint or answer has the wrong size.
 */
std::optional<std::vector<uint8_t>> Decode(const QueryState& state, Span<const uint32_t> hint, Span<const uint32_t> answer);

/** A FastRandomContext keyed from GetStrongRandBytes, for query secrets and errors. */
std::unique_ptr<FastRandomContext> MakeSecretRng();

} // namespace pir

#endif // NAVIO_PIR_SIMPLEPIR_H
