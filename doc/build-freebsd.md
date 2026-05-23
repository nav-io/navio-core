# FreeBSD Build Guide

**Updated for FreeBSD [12.3](https://www.freebsd.org/releases/12.3R/announce/)**

This guide describes how to build naviod, command-line utilities, and GUI on FreeBSD.

## Preparation

### 1. Install Required Dependencies
Run the following as root to install the base dependencies for building.

```bash
pkg install boost-libs cmake git libevent ninja pkgconf

```

See [dependencies.md](dependencies.md) for a complete overview.

### 2. Clone Navio Repo
Now that `git` and all the required dependencies are installed, let's clone the Navio Core repository to a directory. All build scripts and commands will run from this directory.
``` bash
git clone https://github.com/nav-io/navio-core.git
```

### 3. Install Optional Dependencies

#### Wallet Dependencies
It is not necessary to build wallet functionality to run `naviod`.

###### Descriptor Wallet Support

`sqlite3` is required to support [descriptor wallets](descriptors.md).
Skip if you don't intend to use descriptor wallets.
``` bash
pkg install sqlite3
```

#### Notifications
###### ZeroMQ

Navio Core can provide notifications via ZeroMQ. If the package is installed, support will be compiled in.
```bash
pkg install libzmq4
```

#### Test Suite Dependencies
There is an included test suite that is useful for testing code changes when developing.
To run the test suite (recommended), you will need to have Python 3 installed:

```bash
pkg install python3 databases/py-sqlite3
```
---

## Building Navio Core

### 1. Configuration

There are many ways to configure Navio Core, here are a few common examples:

##### Wallet:
```bash
cmake -B build -G Ninja
```

##### No Wallet or GUI
``` bash
cmake -B build -G Ninja -DENABLE_WALLET=OFF
```

### 2. Compile

```bash
cmake --build build         # use "-j N" for N parallel jobs
ctest --test-dir build      # Run tests if Python 3 is available
```
