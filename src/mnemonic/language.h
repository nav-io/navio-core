// Copyright (c) 2023-2023 The Navcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MNEMONIC_LANGUAGE_H
#define BITCOIN_MNEMONIC_LANGUAGE_H

namespace mnemonic {

typedef enum class language
{
    en,
    es,
    it,
    fr,
    cs,
    pt,
    ja,
    ko,
    zh_Hans,
    zh_Hant,
    none
} language;

} // namespace mnemonic

#endif // BITCOIN_MNEMONIC_LANGUAGE_H
