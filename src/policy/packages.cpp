// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <memory>
#include <numeric>

/** IsTopoSortedPackage where a set of txids has been pre-populated. The set is assumed to be correct and
 * is mutated within this function (even if return value is false). */
bool IsTopoSortedPackage(const Package& txns, std::unordered_set<uint256, SaltedTxidHasher>& later_outids)
{
    // later_outids contains the output hashes of this transaction and the ones that come later in
    // txns. If any transaction's input spends an output in that set, we've found a parent placed later
    // than its child.
    for (const auto& tx : txns) {
        for (const auto& input : tx->vin) {
            if (later_outids.find(input.prevout.hash) != later_outids.end()) {
                // The parent is a subsequent transaction in the package.
                return false;
            }
        }
        // Remove this transaction's output hashes from the set as we process it
        for (const auto& output : tx->vout) {
            later_outids.erase(output.GetHash());
        }
    }

    return true;
}

bool IsTopoSortedPackage(const Package& txns)
{
    std::unordered_set<uint256, SaltedTxidHasher> later_outids;
    for (const auto& tx : txns) {
        for (const auto& output : tx->vout) {
            later_outids.insert(output.GetHash());
        }
    }

    return IsTopoSortedPackage(txns, later_outids);
}

bool IsConsistentPackage(const Package& txns)
{
    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    std::unordered_set<COutPoint, SaltedOutpointHasher> inputs_seen;
    for (const auto& tx : txns) {
        if (tx->vin.empty()) {
            // This function checks consistency based on inputs, and we can't do that if there are
            // no inputs. Duplicate empty transactions are also not consistent with one another.
            // This doesn't create false negatives, as unconfirmed transactions are not allowed to
            // have no inputs.
            return false;
        }
        for (const auto& input : tx->vin) {
            if (inputs_seen.find(input.prevout) != inputs_seen.end()) {
                // This input is also present in another tx in the package.
                return false;
            }
        }
        // Batch-add all the inputs for a tx at a time. If we added them 1 at a time, we could
        // catch duplicate inputs within a single tx.  This is a more severe, consensus error,
        // and we want to report that from CheckTransaction instead.
        std::transform(tx->vin.cbegin(), tx->vin.cend(), std::inserter(inputs_seen, inputs_seen.end()),
                       [](const auto& input) { return input.prevout; });
    }
    return true;
}

bool IsWellFormedPackage(const Package& txns, PackageValidationState& state, bool require_sorted)
{
    const unsigned int package_count = txns.size();

    if (package_count > MAX_PACKAGE_COUNT) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-many-transactions");
    }

    const int64_t total_weight = std::accumulate(txns.cbegin(), txns.cend(), 0,
                               [](int64_t sum, const auto& tx) { return sum + GetTransactionWeight(*tx); });
    // If the package only contains 1 tx, it's better to report the policy violation on individual tx weight.
    if (package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-large");
    }

    std::unordered_set<uint256, SaltedTxidHasher> later_txids;
    std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
                   [](const auto& tx) { return tx->GetHash(); });

    std::unordered_set<uint256, SaltedTxidHasher> later_outids;
    for (const auto& tx : txns) {
        for (const auto& output : tx->vout) {
            later_outids.insert(output.GetHash());
        }
    }

    // Package must not contain any duplicate transactions, which is checked by txid. This also
    // includes transactions with duplicate wtxids and same-txid-different-witness transactions.
    if (later_txids.size() != txns.size()) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-contains-duplicates");
    }

    // Require the package to be sorted in order of dependency, i.e. parents appear before children.
    // An unsorted package will fail anyway on missing-inputs, but it's better to quit earlier and
    // fail on something less ambiguous (missing-inputs could also be an orphan or trying to
    // spend nonexistent coins).
    if (require_sorted && !IsTopoSortedPackage(txns, later_outids)) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-sorted");
    }

    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    if (!IsConsistentPackage(txns)) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "conflict-in-package");
    }
    return true;
}

bool IsChildWithParents(const Package& package)
{
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));
    if (package.size() < 2) return false;

    // The package is expected to be sorted, so the last transaction is the child.
    const auto& child = package.back();
    std::unordered_set<uint256, SaltedTxidHasher> input_outids;
    std::transform(child->vin.cbegin(), child->vin.cend(),
                   std::inserter(input_outids, input_outids.end()),
                   [](const auto& input) { return input.prevout.hash; });

    // Every transaction must be a parent of the last transaction in the package.
    // Check if any output from each parent transaction matches an input of the child.
    return std::all_of(package.cbegin(), package.cend() - 1,
                       [&input_outids](const auto& ptx) {
                           for (const auto& output : ptx->vout) {
                               if (input_outids.count(output.GetHash()) > 0) {
                                   return true;
                               }
                           }
                           return false;
                       });
}

bool IsChildWithParentsTree(const Package& package)
{
    if (!IsChildWithParents(package)) return false;
    // Check each parent against all other parents
    for (auto it1 = package.cbegin(); it1 != package.cend() - 1; ++it1) {
        // Collect outputs from all other parents (excluding the current one)
        std::unordered_set<uint256, SaltedTxidHasher> other_parent_outids;
        for (auto it2 = package.cbegin(); it2 != package.cend() - 1; ++it2) {
            if (it1 != it2) { // Skip the current parent
                for (const auto& output : (*it2)->vout) {
                    other_parent_outids.insert(output.GetHash());
                }
            }
        }

        // Check if current parent spends any output from other parents
        for (const auto& input : (*it1)->vin) {
            if (other_parent_outids.count(input.prevout.hash) > 0) return false;
        }
    }

    return true;
}
