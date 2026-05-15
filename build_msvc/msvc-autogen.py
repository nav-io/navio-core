#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import re
import argparse
from shutil import copyfile

SOURCE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
DEFAULT_PLATFORM_TOOLSET = R'v143'

libs = [
    'libbitcoin_cli',
    'libbitcoin_common',
    'libbitcoin_crypto',
    'libbitcoin_node',
    'libbitcoin_util',
    'libbitcoin_wallet_tool',
    'libbitcoin_wallet',
    'libbitcoin_zmq',
    'bench_navio',
    'libtest_util',
]

ignore_list = [
]

lib_sources = {}

# Automake Makefile.am list variables referenced from *_SOURCES entries, e.g.
# libbitcoin_node_a_SOURCES += $(BLSCT_CPP). The naive parser previously skipped
# any line that did not start with "*.cpp", so MSVC projects missed every file
# only carried by such macros; link failures on Win64 once validation.cpp began
# calling into blsct/pos/pos_async_verifier.cpp.
LIST_VAR_ASSIGN_RE = re.compile(r'^([A-Z][A-Z0-9_]*) *= *\\$')
REF_VAR_RE = re.compile(r'^\$\(([A-Z][A-Z0-9_]*)\)$')


def parse_list_variables(lines):
    """Parse top-level makefile variables assigned as backslash-terminated lists."""
    variables = {}
    n = len(lines)
    i = 0
    while i < n:
        stripped = lines[i].strip()
        m = LIST_VAR_ASSIGN_RE.match(stripped)
        if m:
            name = m.group(1)
            entries = []
            i += 1
            while i < n:
                cont = lines[i].strip()
                if cont.endswith('\\'):
                    tok = cont[:-1].strip().split()
                    if tok:
                        entries.append(tok[0])
                    i += 1
                else:
                    if cont:
                        entries.append(cont.split()[0])
                    i += 1
                    break
            variables[name] = entries
            continue
        i += 1
    return variables


def expand_list_var(name, variables, stack=None):
    """Expand one list variable recursively; tokens are $(FOO) refs or literals."""
    if stack is None:
        stack = set()
    if name in stack:
        raise ValueError(f'circular list variable reference: {name}')
    stack = stack | {name}
    out = []
    for token in variables.get(name, []):
        rm = REF_VAR_RE.match(token)
        if rm:
            out.extend(expand_list_var(rm.group(1), variables, stack))
        else:
            out.append(token)
    return out


def append_cpp_source(lib, cpp_path):
    """Add a single .cpp to lib_sources if not ignored; avoids duplicate paths."""
    if cpp_path.startswith('$'):
        return False
    if not cpp_path.endswith('.cpp'):
        return False
    if cpp_path in ignore_list:
        return False
    pair = (
        cpp_path.replace('/', '\\'),
        cpp_path.replace('/', '_')[:-4] + '.obj',
    )
    existing_paths = [p for p, _ in lib_sources[lib]]
    if pair[0] in existing_paths:
        return True
    lib_sources[lib].append(pair)
    return True


def parse_makefile(makefile, list_variables):
    with open(makefile, 'r', encoding='utf-8') as file:
        current_lib = ''
        for line in file.read().splitlines():
            if current_lib:
                line_stripped = line.strip()
                if not line_stripped:
                    if not line.endswith('\\'):
                        current_lib = ''
                    continue

                token = line_stripped.split()[0]

                ref_m = REF_VAR_RE.match(token)
                if ref_m:
                    expanded = expand_list_var(ref_m.group(1), list_variables)
                    for cpp in expanded:
                        append_cpp_source(current_lib, cpp)
                elif token.endswith('.cpp') and token not in ignore_list:
                    append_cpp_source(current_lib, token)

                if not line.endswith('\\'):
                    current_lib = ''
                continue
            for lib in libs:
                _lib = lib.replace('-', '_')
                if re.search(_lib + '.*_SOURCES \\= \\\\', line):
                    current_lib = lib
                    lib_sources[current_lib] = []
                    break

def parse_config_into_btc_config():
    def find_between( s, first, last ):
        try:
            start = s.index( first ) + len( first )
            end = s.index( last, start )
            return s[start:end]
        except ValueError:
            return ""

    config_info = []
    with open(os.path.join(SOURCE_DIR,'../configure.ac'), encoding="utf8") as f:
        for line in f:
            if line.startswith("define"):
                config_info.append(find_between(line, "(_", ")"))

    config_info = [c for c in config_info if not c.startswith("COPYRIGHT_HOLDERS")]

    config_dict = dict(item.split(", ") for item in config_info)
    config_dict["PACKAGE_VERSION"] = f"\"{config_dict['CLIENT_VERSION_MAJOR']}.{config_dict['CLIENT_VERSION_MINOR']}.{config_dict['CLIENT_VERSION_BUILD']}\""
    version = config_dict["PACKAGE_VERSION"].strip('"')
    config_dict["PACKAGE_STRING"] = f"\"Navio Core {version}\""

    with open(os.path.join(SOURCE_DIR,'../build_msvc/bitcoin_config.h.in'), "r", encoding="utf8") as template_file:
        template = template_file.readlines()

    for index, line in enumerate(template):
        header = ""
        if line.startswith("#define"):
            header = line.split(" ")[1]
        if header in config_dict:
            template[index] = line.replace("$", f"{config_dict[header]}")

    with open(os.path.join(SOURCE_DIR,'../build_msvc/bitcoin_config.h'), "w", encoding="utf8") as btc_config:
        btc_config.writelines(template)

def set_properties(vcxproj_filename, placeholder, content):
    with open(vcxproj_filename + '.in', 'r', encoding='utf-8') as vcxproj_in_file:
        with open(vcxproj_filename, 'w', encoding='utf-8') as vcxproj_file:
            vcxproj_file.write(vcxproj_in_file.read().replace(placeholder, content))

def main():
    parser = argparse.ArgumentParser(description='Navio-core msbuild configuration initialiser.')
    parser.add_argument('-toolset', nargs='?', default=DEFAULT_PLATFORM_TOOLSET,
        help='Optionally sets the msbuild platform toolset, e.g. v143 for Visual Studio 2022.'
         ' default is %s.'%DEFAULT_PLATFORM_TOOLSET)
    args = parser.parse_args()
    set_properties(os.path.join(SOURCE_DIR, '../build_msvc/common.init.vcxproj'), '@TOOLSET@', args.toolset)

    list_variables = {}
    makefile_am_path = os.path.join(SOURCE_DIR, 'Makefile.am')
    if os.path.isfile(makefile_am_path):
        with open(makefile_am_path, 'r', encoding='utf-8') as makefile_am_file:
            list_variables = parse_list_variables(makefile_am_file.read().splitlines())

    for makefile_name in os.listdir(SOURCE_DIR):
        if 'Makefile' in makefile_name:
            parse_makefile(os.path.join(SOURCE_DIR, makefile_name), list_variables)
    for key, value in lib_sources.items():
        vcxproj_filename = os.path.abspath(os.path.join(os.path.dirname(__file__), key, key + '.vcxproj'))
        content = ''
        for source_filename, object_filename in value:
            content += '    <ClCompile Include="..\\..\\src\\' + source_filename + '">\n'
            content += '      <ObjectFileName>$(IntDir)' + object_filename + '</ObjectFileName>\n'
            content += '    </ClCompile>\n'
        set_properties(vcxproj_filename, '@SOURCE_FILES@\n', content)
    parse_config_into_btc_config()
    copyfile(os.path.join(SOURCE_DIR,'../build_msvc/bitcoin_config.h'), os.path.join(SOURCE_DIR, 'config/bitcoin-config.h'))

if __name__ == '__main__':
    main()
