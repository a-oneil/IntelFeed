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
# while the repo has no tags at all, and `--dirty` marks a build made from an
# edited working tree. Cutting the first `v0.2.0` tag upgrades every version
# string from "c684f22" to "v0.2.0" with no further work here.
APP_VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo unknown)
GIT_SHA=$(git rev-parse --short=8 HEAD 2>/dev/null || echo unknown)
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

export APP_VERSION GIT_SHA BUILD_TIME
