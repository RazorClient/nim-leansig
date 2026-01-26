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
  exec "nim c -r --path:./src tests/test_basic.nim"

task testStatic, "Run tests with static linking":
  exec "./build/build_rust.sh"
  exec "nim c -r --path:./src -d:useStaticLinking tests/test_basic.nim"
