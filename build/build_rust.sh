#!/bin/sh
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_HOME="${CARGO_HOME:-${ROOT_DIR}/.cargo}"
mkdir -p "${CARGO_HOME}"

cd "${ROOT_DIR}"

echo "Ensuring git submodules (rust/leansig, rust/Multisig) are initialized..."
if [ -d .git ]; then
  git submodule update --init --recursive rust/leansig rust/Multisig
else
  echo "Warning: no .git directory found; skipping submodule update"
fi

echo "Building Rust FFIs..."

# Use plain cd to stay POSIX-friendly; some /bin/sh implementations lack pushd/popd.
cd rust/ffi
cargo build --release
cd "${ROOT_DIR}"

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
