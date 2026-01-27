# Package

version       = "0.1.0"
author        = "Agnish Ghosh"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"
skipDirs      = @["tests"]

# Dependencies

requires "nim >= 2.2.0"

# Tasks

task test, "Run tests":
  exec "./build/build_rust.sh"
  exec "nim c -r --nimcache:./build/nimcache --path:./src tests/test_basic.nim"
  exec "nim c -r --nimcache:./build/nimcache --path:./src tests/test_multisig.nim"
