// Copyright (c) 2023-2023 The Navcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MNEMONIC_LEXICON_H
#define BITCOIN_MNEMONIC_LEXICON_H

#include <array>

#include <mnemonic/language.h>

namespace mnemonic {

template <std::size_t Size>
class lexicon final
{
public:
    typedef std::array<const char*, Size> words;

private:
    // This dictionary creates only this one word of state.
    const language identifier_;

    // Arrays of words are declared statically and held by reference here.
    // The array type is POD, so no words are copied into the array. Only
    // this wrapper dictionary object is created for each word list, for
    // each dictionaries object constructed by various mnemonic classes.
    const words& words_;
};

} // namespace mnemonic

#endif // BITCOIN_MNEMONIC_LEXICON_H
