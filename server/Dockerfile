FROM rust:1.88-slim AS builder
WORKDIR /app

# Prime dependency layers first for faster rebuilds.
COPY Cargo.toml Cargo.lock ./
COPY crates/bonded-core/Cargo.toml crates/bonded-core/Cargo.toml
COPY crates/bonded-server/Cargo.toml crates/bonded-server/Cargo.toml
COPY crates/bonded-client/Cargo.toml crates/bonded-client/Cargo.toml
COPY crates/bonded-cli/Cargo.toml crates/bonded-cli/Cargo.toml
RUN mkdir -p crates/bonded-core/src crates/bonded-server/src crates/bonded-client/src crates/bonded-cli/src
RUN echo 'pub fn placeholder() {}' > crates/bonded-core/src/lib.rs
RUN echo 'fn main() {}' > crates/bonded-server/src/main.rs
RUN echo 'pub fn placeholder() {}' > crates/bonded-client/src/lib.rs
RUN echo 'fn main() {}' > crates/bonded-cli/src/main.rs
RUN cargo build --release -p bonded-server || true

COPY crates/ ./crates/
RUN cargo build --release -p bonded-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/bonded-server /usr/local/bin/bonded-server
RUN mkdir -p /etc/bonded /var/lib/bonded
ENV BONDED_CONFIG=/etc/bonded/server.toml
EXPOSE 8080 8081
ENTRYPOINT ["bonded-server"]
