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
         "chronos",
         "chronicles",
         "std_shims"

import strutils
import oswalkdir, ospaths # In newer nim these are merged to os

proc test(path: string) =
  echo "Running: ", path
  exec "nim c -r " & path

proc run_tests(dir: string) =
  for path in walkDirRec(dir):
    let fname = splitPath(path).tail
    if fname.startsWith("test_") and fname.endsWith(".nim"):
      test(path)

task test, "run tests":
  run_tests("tests")

task test_keyfile, "run keyfile tests":
  run_tests("tests/keyfile")

task test_keys, "run keys tests":
  run_tests("tests/keys")

task test_p2p, "run p2p tests":
  run_tests("tests/p2p")

task test_rlp, "run rlp tests":
  run_tests("tests/rlp")

task test_trie, "run trie tests":
  run_tests("tests/trie")

