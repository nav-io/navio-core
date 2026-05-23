# `build_msvc/`

This directory holds the [vcpkg](https://vcpkg.io) manifest
(`vcpkg.json`) used by the Win64 native CMake CI job
(`.github/workflows/ci.yml`, `win64-native:`).

The legacy MSBuild / `*.vcxproj` flow has been removed. To build Navio
Core on Windows, use the CMake build documented in
[`doc/build-windows.md`](../doc/build-windows.md).
