// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo::rustc-link-search=/opt/aarch64-linux-musl-cross/aarch64-linux-musl/lib/");
    println!("cargo::rustc-link-lib=seccomp");
}
