#!/usr/bin/env bash
# Regenerate the backend lockfiles from pyproject.toml.
#
#   ./lock.sh            re-lock, keeping every existing pin that still fits
#   ./lock.sh --upgrade  move every package to its newest allowed version
#   ./lock.sh --upgrade-package lxml   move just one package
#
# The Dockerfile installs from these files with --require-hashes, so they are
# exactly what ships. pyproject.toml stays the place you declare a dependency;
# run this after editing it and commit both. CI re-runs this script and fails
# if the output differs, so a pyproject edit without a re-lock cannot merge.
#
# --universal writes one file that installs on every platform (the linux/amd64
# prod host, the linux/arm64 dev containers on Apple silicon, a macOS venv),
# with hashes for every wheel of each pinned version.
#
# uv is pinned so the header and the resolution are byte-identical between a
# laptop and CI. Bump UV_VERSION here and in .github/workflows/ci.yml together.
set -euo pipefail

UV_VERSION=0.12.24
cd "$(dirname "$0")"

uv() { uvx --quiet "uv@${UV_VERSION}" "$@"; }

common=(--universal --python-version 3.14 --generate-hashes --quiet)

# Runtime first, then dev constrained to it, so the dev file is a strict
# superset with identical pins and the development image can layer it on top.
uv pip compile pyproject.toml "${common[@]}" "$@" \
  --custom-compile-command "./lock.sh" -o requirements.lock
uv pip compile pyproject.toml --extra dev -c requirements.lock "${common[@]}" "$@" \
  --custom-compile-command "./lock.sh" -o requirements-dev.lock
