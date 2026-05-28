#!/usr/bin/env bash
set -euo pipefail

TARGET=${TARGET:-aarch64-unknown-linux-musl}

cargo build --release --target "${TARGET}" --bins --examples
