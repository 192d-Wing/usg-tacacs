FROM rust:alpine AS builder

# TARGETARCH is injected by BuildKit: "amd64" or "arm64"
ARG TARGETARCH

RUN apk add --no-cache musl-dev openssl-dev pkgconfig build-base && \
    case "${TARGETARCH}" in \
      amd64) echo x86_64-unknown-linux-musl  > /rust-target ;; \
      arm64) echo aarch64-unknown-linux-musl > /rust-target ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2 && exit 1 ;; \
    esac && \
    rustup target add "$(cat /rust-target)"

WORKDIR /app
COPY . .
RUN RUST_TARGET="$(cat /rust-target)" && \
    cargo build --release --target "${RUST_TARGET}" -p usg-tacacs-server && \
    cp "target/${RUST_TARGET}/release/usg-tacacs-server" /usg-tacacs-server

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app

# Create non-root runtime user for tacacs
RUN adduser -D -H -s /sbin/nologin tacacs
USER tacacs

COPY --from=builder /usg-tacacs-server /usr/local/bin/usg-tacacs

EXPOSE 300/tcp 49/tcp
ENTRYPOINT ["/usr/local/bin/usg-tacacs"]
CMD ["--help"]
