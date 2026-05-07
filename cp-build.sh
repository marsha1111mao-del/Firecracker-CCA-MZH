cargo build --release --target aarch64-unknown-linux-musl  --bins --examples
cp -v build/cargo_target/aarch64-unknown-linux-musl/release/firecracker /home/mzh/cca/gpu/GPU_SFTP/firecracker-bins/
