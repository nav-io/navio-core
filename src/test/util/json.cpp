// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/json.h>

#include <string>
#include <string_view>
#include <util/check.h>

#include <univalue.h>

UniValue read_json(std::string_view jsondata)
{
    UniValue v;
    Assert(v.read(std::string(jsondata)) && v.isArray());
    return v.get_array();
}
