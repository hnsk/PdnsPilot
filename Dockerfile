FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
# cache deps layer
RUN mkdir -p src .sqlx && echo 'fn main(){}' > src/main.rs && SQLX_OFFLINE=true cargo build --release || true
RUN rm -f src/main.rs

COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx
RUN SQLX_OFFLINE=true cargo build --release

# ─── Runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates libgcc

WORKDIR /app
COPY --from=builder /build/target/release/pdnspilot /app/pdnspilot
COPY templates ./templates
COPY static ./static

RUN mkdir -p /data

ENV PDNSPILOT_DATABASE_PATH=/data/pdnspilot.db
ENV BIND_ADDR=0.0.0.0:8080

EXPOSE 8080

CMD ["/app/pdnspilot"]
