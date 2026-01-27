#!/bin/sh
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_HOME="${CARGO_HOME:-${ROOT_DIR}/.cargo}"
mkdir -p "${CARGO_HOME}"

cd "${ROOT_DIR}"

echo "Building Rust FFIs..."

pushd rust/ffi > /dev/null
cargo build --release
popd > /dev/null

echo "Copying libraries..."

mkdir -p lib

copy_libs() {
  local src_dir="$1"
  if [ -f "$src_dir/libleansig_ffi.so" ]; then cp "$src_dir/libleansig_ffi.so" lib/; fi
  if [ -f "$src_dir/libleansig_ffi.dylib" ]; then cp "$src_dir/libleansig_ffi.dylib" lib/; fi
  if [ -f "$src_dir/leansig_ffi.dll" ]; then cp "$src_dir/leansig_ffi.dll" lib/; fi
  if [ -f "$src_dir/libleansig_ffi.a" ]; then cp "$src_dir/libleansig_ffi.a" lib/; fi
  if [ -f "$src_dir/leansig_ffi.lib" ]; then cp "$src_dir/leansig_ffi.lib" lib/; fi
}

copy_libs "rust/ffi/target/release"
