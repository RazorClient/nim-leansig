#!/bin/sh
set -e

echo "Building Rust FFI..."

cd rust/ffi
cargo build --release

echo "Copying libraries..."

mkdir -p ../../lib

# Copy shared library (.so/.dylib/.dll)
if [ -f target/release/libleansig_ffi.so ]; then
  cp target/release/libleansig_ffi.so ../../lib/
fi
if [ -f target/release/libleansig_ffi.dylib ]; then
  cp target/release/libleansig_ffi.dylib ../../lib/
fi
if [ -f target/release/leansig_ffi.dll ]; then
  cp target/release/leansig_ffi.dll ../../lib/
fi

# Copy static library (.a/.lib)
if [ -f target/release/libleansig_ffi.a ]; then
  cp target/release/libleansig_ffi.a ../../lib/
fi
if [ -f target/release/leansig_ffi.lib ]; then
  cp target/release/leansig_ffi.lib ../../lib/
fi
