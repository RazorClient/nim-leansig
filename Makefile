# Copyright (c) 2019-2025 Status Research & Development GmbH.
# Licensed under either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

SHELL := bash

ROOT_DIR := $(realpath $(dir $(firstword $(MAKEFILE_LIST))))
BUILD_DIR := $(ROOT_DIR)/build
LIB_DIR := $(ROOT_DIR)/lib

NIM := nim
NIMBLE := nimble
NIMCACHE := $(BUILD_DIR)/nimcache
NIM_FLAGS := --path:$(ROOT_DIR)/src --nimcache:$(NIMCACHE)

RUST_FFI_DIR := $(ROOT_DIR)/rust/ffi
RUST_TARGET_DIR := $(RUST_FFI_DIR)/target/release

# Ensure git submodules (Rust deps) are present before any build
SUBMODULE_PATHS := rust/leansig rust/Multisig
GIT_SUBMODULE_UPDATE := git submodule update --init --recursive $(SUBMODULE_PATHS)

.DEFAULT_GOAL := all

.PHONY: all update ffi test nimble-test clean

all: ffi

update:
	@$(GIT_SUBMODULE_UPDATE)

# Build the Rust FFI and copy artifacts into ./lib
ffi: update
	@./build/build_rust.sh

# Run the Nim test suites (expects Rust FFI artifacts to be present)
test: ffi
	@$(NIM) c -r $(NIM_FLAGS) tests/test_basic.nim
	@$(NIM) c -r $(NIM_FLAGS) tests/test_multisig.nim

# Shortcut to delegate to nimble's built-in test task
nimble-test: ffi
	@$(NIMBLE) test

# Remove build outputs
clean:
	@rm -rf $(LIB_DIR) $(NIMCACHE) tests/test_basic tests/test_multisig
	@cargo clean --manifest-path=$(RUST_FFI_DIR)/Cargo.toml
