UNIX BUILD NOTES
====================
Some notes on how to build Navio Core in Unix.

(For BSD specific instructions, see `build-*bsd.md` in this directory.)

To Build
---------------------

```bash
cmake -B build -G Ninja
cmake --build build           # use `-j N` for N parallel jobs
ctest --test-dir build        # optional: run unit tests
cmake --install build         # optional: install to system prefix
```

See below for [Linux distribution-specific instructions](#linux-distribution-specific-instructions),
or the [dependencies](#dependencies) section for a complete overview.

## Memory Requirements

C++ compilers are memory-hungry. It is recommended to have at least 1.5 GB of
memory available when compiling Navio Core. On systems with less, gcc can be
tuned to conserve memory with additional CXXFLAGS, passed via the cmake cache:

    cmake -B build -G Ninja \
      -DCMAKE_CXX_FLAGS="--param ggc-min-expand=1 --param ggc-min-heapsize=32768"

Alternatively, or in addition, debugging information can be skipped:

    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release

clang (often less resource hungry) can be used instead of gcc:

    cmake -B build -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++

## Linux Distribution Specific Instructions

### Ubuntu & Debian

#### Dependency Build Instructions

Build requirements:

    sudo apt-get install build-essential cmake ninja-build pkgconf python3

Now, you can either build from self-compiled [depends](#dependencies) or
install the required dependencies:

    sudo apt-get install libevent-dev libboost-dev

SQLite is required for the descriptor wallet:

    sudo apt install libsqlite3-dev

To build without wallet, see [*Disable-wallet mode*](#disable-wallet-mode).

ZMQ dependencies (provides ZMQ API):

    sudo apt-get install libzmq3-dev

User-Space, Statically Defined Tracing (USDT) dependencies:

    sudo apt install systemtap-sdt-dev

### Fedora

#### Dependency Build Instructions

Build requirements:

    sudo dnf install gcc-c++ cmake ninja-build pkgconf python3

Now, you can either build from self-compiled [depends](#dependencies) or
install the required dependencies:

    sudo dnf install libevent-devel boost-devel

SQLite is required for the descriptor wallet:

    sudo dnf install sqlite-devel

To build without wallet, see [*Disable-wallet mode*](#disable-wallet-mode).

ZMQ dependencies (provides ZMQ API):

    sudo dnf install zeromq-devel

User-Space, Statically Defined Tracing (USDT) dependencies:

    sudo dnf install systemtap-sdt-devel

## Dependencies

See [dependencies.md](dependencies.md) for a complete overview, and
[depends](/depends/README.md) on how to compile them yourself, if you wish to
not use the packages of your Linux distribution.

Disable-wallet mode
--------------------
When the intention is to only run a P2P node, without a wallet, Navio Core can
be compiled in disable-wallet mode:

    cmake -B build -G Ninja -DENABLE_WALLET=OFF

In this case there is no dependency on SQLite.

Mining is also possible in disable-wallet mode using the `getblocktemplate` RPC
call.

Additional CMake Options
--------------------------
A list of available CMake options can be displayed with:

    cmake -B build -LH

Setup and Build Example: Arch Linux
-----------------------------------
This example lists the steps necessary to setup and build a command line only
distribution of the latest changes on Arch Linux:

    pacman --sync --needed cmake ninja boost gcc git libevent pkgconf python sqlite
    git clone https://github.com/nav-io/navio-core.git
    cd navio-core/
    cmake -B build -G Ninja
    cmake --build build
    ctest --test-dir build
    ./build/bin/naviod
