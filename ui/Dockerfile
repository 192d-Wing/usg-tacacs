# SPDX-License-Identifier: Apache-2.0
# tacacs-ui: Cloudscape SPA + Rust/axum BFF in one image.
# Build context = ui/ . Arch-native (build on arm64 for the k3s nodes).

# Stage 1: build the Cloudscape SPA.
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Stage 2: build the BFF (musl, native target). reqwest is HTTP-only so no
# TLS/native deps are required.
FROM rust:alpine AS bff
RUN apk add --no-cache musl-dev
WORKDIR /bff
COPY bff/ ./
RUN cargo build --release

# Stage 3: minimal runtime.
FROM alpine:3.21
RUN apk add --no-cache ca-certificates && adduser -D -H -s /sbin/nologin ui
COPY --from=bff /bff/target/release/tacacs-ui-bff /usr/local/bin/tacacs-ui-bff
COPY --from=web /web/dist /app/web
USER ui
EXPOSE 8088
ENV UI_STATIC_DIR=/app/web
ENTRYPOINT ["/usr/local/bin/tacacs-ui-bff"]
