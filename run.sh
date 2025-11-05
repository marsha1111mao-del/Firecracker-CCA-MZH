CARGO_MANIFEST_DIR=/mnt/firecracker_src cargo test --features rme --target aarch64-unknown-linux-musl --package vmm --test integration_tests -- test_build_and_boot_microvm --exact
cp /home/xander/firecracker/build/cargo_target/aarch64-unknown-linux-musl/debug/deps/integration_tests-* ~/cca-v4
echo success
