cargo build --release --target aarch64-unknown-linux-musl  --bins --examples
cp build/cargo_target/aarch64-unknown-linux-musl/release/firecracker ../run
