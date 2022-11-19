FROM rust:buster

COPY . /workdir
workdir /workdir
RUN rustup component add rustfmt && cargo install --path teos