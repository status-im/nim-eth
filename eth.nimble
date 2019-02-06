version       = "1.0.0"
author        = "Status Research & Development GmbH"
description   = "Ethereum Common library"
license       = "MIT"
skipDirs      = @["tests"]

requires "nim >= 0.19.0",
         "nimcrypto",
         "ranges",
         "stint",
         "byteutils",
         "secp256k1",
         "rocksdb",
         "package_visible_types",
         "https://github.com/status-im/chronos",
         "chronicles"

proc test(filename: string) =
  echo "Running: ", filename
  exec "nim c -r " & filename

import strutils
import oswalkdir, ospaths # In newer nim these are merged to os

task test, "run tests":
  for i in walkDirRec("tests"):
    let fn = splitPath(i).tail
    if fn.startsWith("test_") and fn.endsWith(".nim"):
      test(i)
