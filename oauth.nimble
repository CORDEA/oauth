# Package
version     = "0.11"
author      = "Yoshihiro Tanaka"
description = "OAuth library for nim"
license     = "Apache License 2.0"
srcDir      = "src"

# Deps
requires "nim >= 0.19.0"
requires "sha1"

task test, "Test oauth":
  exec "find test/ -name \"*.nim\" | xargs -I {} nim c -d:ssl -d:testing -r {}"
