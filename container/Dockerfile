FROM rust:1.95-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev pkgconfig build-base && \
    rustup target add x86_64-unknown-linux-musl

WORKDIR /app
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl \
    -p usg-tacacs-server \
    -p usg-tacacs-config

FROM registry1.dso.mil/ironbank/opensource/alpinelinux/alpine:3.22
RUN apk add --no-cache ca-certificates
WORKDIR /app

# Create non-root runtime user for tacacs
RUN adduser -D -H -s /sbin/nologin tacacs
USER tacacs

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/usg-tacacs-server /usr/local/bin/usg-tacacs
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/usg-tacacs-config-check /usr/local/bin/usg-tacacs-config-check

EXPOSE 300/tcp 49/tcp
ENTRYPOINT ["/usr/local/bin/usg-tacacs"]
CMD ["--help"]
