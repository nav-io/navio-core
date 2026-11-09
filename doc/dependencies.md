# Dependencies

These are the dependencies used by Navio. You can find installation instructions
in the `build-*.md` file for your platform. "Runtime" and "Version used" are
both in reference to the release binaries, which are built with the
[depends](../depends) system.

| Dependency                                        | Minimum required |
| ------------------------------------------------- | ---------------- |
| [CMake](https://cmake.org)                        | 3.22             |
| [Clang](https://clang.llvm.org)                   | 14.0             |
| [GCC](https://gcc.gnu.org)                        | 10.1             |
| [Python](https://www.python.org) (scripts, tests) | 3.10             |

The compiler must support C++20.

## Required

| Dependency                                  | Releases                                              | Version used  | Minimum required | Runtime |
| ------------------------------------------- | ----------------------------------------------------- | ------------- | ---------------- | ------- |
| [Boost](../depends/packages/boost.mk)       | [link](https://www.boost.org/users/download/)         | 1.90.0        | 1.74.0           | No      |
| [libevent](../depends/packages/libevent.mk) | [link](https://github.com/libevent/libevent/releases) | 2.1.12-stable | 2.1.8            | No      |
| glibc                                       | [link](https://www.gnu.org/software/libc/)            | N/A           | 2.27             | Yes     |
| Linux Kernel                                | [link](https://www.kernel.org/)                       | N/A           | 3.17.0           | Yes     |

## Optional

### Notifications

Used only when CMake is configured with `-DWITH_ZMQ=ON`.

| Dependency                              | Releases                                          | Version used | Minimum required | Runtime |
| --------------------------------------- | ------------------------------------------------- | ------------ | ---------------- | ------- |
| [ZeroMQ](../depends/packages/zeromq.mk) | [link](https://github.com/zeromq/libzmq/releases) | 4.3.5        | 4.0.0            | No      |

### Tracing

Used only when CMake is configured with `-DWITH_USDT=ON`. See
[tracing](tracing.md).

| Dependency                                    | Releases                                  | Version used | Minimum required | Runtime |
| --------------------------------------------- | ----------------------------------------- | ------------ | ---------------- | ------- |
| [systemtap](../depends/packages/systemtap.mk) | [link](https://sourceware.org/systemtap/) | 5.3          | N/A              | No      |

### Wallet

Required unless CMake is configured with `-DENABLE_WALLET=OFF`.

| Dependency                              | Releases                   | Version used | Minimum required | Runtime |
| --------------------------------------- | -------------------------- | ------------ | ---------------- | ------- |
| [SQLite](../depends/packages/sqlite.mk) | [link](https://sqlite.org) | 3.50.4       | 3.7.17           | No      |
