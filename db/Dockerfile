# PostgreSQL 16 + pgvector.
#
# Deliberately built on the same postgres 16 alpine image the stack has always run,
# rather than switching to the Debian-based pgvector/pgvector image: the data
# directory was initdb'd under musl, and moving it to glibc changes text
# collation, which silently corrupts every btree index on a text column until
# a full REINDEX. Same base, same libc, same major version — the existing
# pgdata volume is used as-is.
#
# `with_llvm=no` is required: the default target builds JIT bitcode against an
# LLVM the official image does not ship, and `make install` fails on it.
FROM postgres:16.15-alpine3.24 AS build

ARG PGVECTOR_VERSION=v0.8.1

RUN apk add --no-cache build-base git \
    && git clone --branch "${PGVECTOR_VERSION}" --depth 1 https://github.com/pgvector/pgvector.git /tmp/pgvector \
    && cd /tmp/pgvector \
    && make OPTFLAGS="" with_llvm=no \
    && make install with_llvm=no

FROM postgres:16.15-alpine3.24

COPY --from=build /usr/local/lib/postgresql/vector.so /usr/local/lib/postgresql/
COPY --from=build /usr/local/share/postgresql/extension/vector* /usr/local/share/postgresql/extension/
