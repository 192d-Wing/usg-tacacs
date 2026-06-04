# SPDX-License-Identifier: Apache-2.0
# Arch-native build of the TACACS+ server for local kind clusters.
#
# Unlike container/Dockerfile (which hard-codes x86_64-unknown-linux-musl),
# this builds for the builder's native target. rust:alpine is musl-native, so
# `cargo build --release` yields a musl static-ish binary matching the host
# arch (arm64 on Apple Silicon) that runs on the matching kind node.
#
# NIST SP 800-53 Rev. 5: SC-8 (binary serves TLS), SA-15 (reproducible build
# via committed Cargo.lock). Build context must be the repository root.
FROM rust:alpine AS builder
# openssl-libs-static is required because the musl target links statically
# (crt-static), so the openssl crate needs libcrypto.a / libssl.a.
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig build-base
WORKDIR /app
COPY . .
RUN cargo build --release -p usg-tacacs-server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
# Non-root runtime user (CM-6 secure defaults / AC-6 least privilege).
RUN adduser -D -H -s /sbin/nologin tacacs
COPY --from=builder /app/target/release/usg-tacacs-server /usr/local/bin/usg-tacacs
USER tacacs
EXPOSE 49/tcp 300/tcp 8080/tcp
ENTRYPOINT ["/usr/local/bin/usg-tacacs"]
CMD ["--help"]
