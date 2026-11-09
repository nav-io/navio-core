# NetBSD Build Guide

Updated for NetBSD [9.2](https://netbsd.org/releases/formal-9/NetBSD-9.2.html).

This guide describes how to build naviod and command-line utilities on NetBSD.

## Preparation

### 1. Install Required Dependencies

Install the required dependencies the usual way you
[install software on NetBSD](https://www.netbsd.org/docs/guide/en/chap-boot.html#chap-boot-pkgsrc).
The example commands below use `pkgin`.

```bash
pkgin install boost cmake git libevent ninja-build pkgconf

```

NetBSD currently ships with an older version of `gcc` than is needed to build.
Navio Core requires a compiler with C++20 support (see
[dependencies.md](dependencies.md) for the minimum versions). You should upgrade
your `gcc` and then pass this new version to CMake.

For example, grab `gcc12`:

```
pkgin install gcc12
```

Then, when configuring, pass the following:

```bash
cmake -B build -G Ninja \
    -DCMAKE_C_COMPILER=/usr/pkg/gcc12/bin/gcc \
    -DCMAKE_CXX_COMPILER=/usr/pkg/gcc12/bin/g++
```

See [dependencies.md](dependencies.md) for a complete overview.

### 2. Clone Navio Repo

Clone the Navio Core repository to a directory. All build scripts and commands
will run from this directory.

```bash
git clone https://github.com/nav-io/navio-core.git
```

### 3. Install Optional Dependencies

#### Wallet Dependencies

It is not necessary to build wallet functionality to run naviod.

###### Wallet Support

`sqlite3` is required to build the wallet (`-DENABLE_WALLET=ON`, the default).

```bash
pkgin install sqlite3
```

#### Test Suite Dependencies

There is an included test suite that is useful for testing code changes when
developing. To run the test suite (recommended), you will need to have Python
3.10 or newer installed, for example:

```bash
pkgin install python311
```

### Building Navio Core

### 1. Configuration

There are many ways to configure Navio Core. Here is an example that explicitly
disables the wallet:

```bash
cmake -B build -G Ninja -DENABLE_WALLET=OFF \
    -DCMAKE_CXX_FLAGS="-I/usr/pkg/include"
```

For a full list of configuration options, see the output of `cmake -B build -LH`

### 2. Compile

Build and run the tests:

```bash
cmake --build build         # use "-j N" here for N parallel jobs
ctest --test-dir build      # Run tests if Python 3 is available
```
