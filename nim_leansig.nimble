# Package

version       = "0.1.0"
author        = "Agnish Ghosh"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.2.0"
before test:
  exec "./build/build_rust.sh"
