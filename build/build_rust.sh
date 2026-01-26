#!/bin/sh
set -e

echo "Building Rust FFI..."

cd rust/ffi
cargo build --release

echo "Copying shared library..."

mkdir -p ../../lib
cp target/release/lib*leansig_ffi* ../../lib/
