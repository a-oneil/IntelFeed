#!/usr/bin/env bash
# Build metadata for `docker compose build`, derived from the checkout itself.
#
# Source it (don't run it) from the repo root, immediately before a build:
#
#   . scripts/ops/version.sh
#   docker compose -f docker-compose.prod.yml build
#
# Compose interpolates the exported vars into the api/frontend build args, which
# is the only way the values can get in: `.git` sits above both build contexts
# (./backend, ./frontend) and is .dockerignore'd on top of that, so nothing
# inside a build can work out what it is building.
#
# Every var falls back to "dev" / "" in compose, so a bare `docker compose
# build` without sourcing this still works — it just reports an unknown version.

# `--tags` counts lightweight tags too, `--always` degrades to a bare short SHA
# while the repo has no matching tag, and `--dirty` marks a build made from an
# edited working tree. Cutting the first `v0.2.0` tag upgrades every version
# string from "c684f22" to "v0.2.0" with no further work here.
#
# `--match` rather than a bare `--tags`, because this repo tags more than one
# artifact: CI publishes an `android-v<version>` tag for every APK release, and
# without a filter `git describe` takes whichever tag is nearest — so the web
# app's footer started reporting "android-v1.2-4-g7990e4d", the Android app's
# version. An allowlist beats excluding `android-v*` by name: the next artifact
# to get its own tag namespace will not quietly break this again.
APP_VERSION=$(git describe --tags --always --dirty --match='v*' 2>/dev/null || echo unknown)
GIT_SHA=$(git rev-parse --short=8 HEAD 2>/dev/null || echo unknown)
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

export APP_VERSION GIT_SHA BUILD_TIME
