## CI Scripts

The CI jobs themselves are defined in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml). This directory only
holds the scripts those jobs call:

- `lint_run_all.sh` runs the lint job: `lint/04_install.sh` installs the lint
  tools and `lint/06_script.sh` runs the lint test runner from
  [`test/lint`](../test/lint/README.md). `lint_imagefile` builds the same
  environment as a container; see `test/lint/README.md` for running it locally.
- `smoke_test_binaries.sh [build_dir]` runs `-version` on every built binary in
  `<build_dir>/bin` (default `build`), to catch load-time failures that `ctest`
  does not exercise.
- `retry/retry` retries a command with backoff; the lint install step puts it on
  `PATH`.
