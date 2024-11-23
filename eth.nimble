mode = ScriptMode.Verbose

version       = "0.5.0"
author        = "Status Research & Development GmbH"
description   = "Ethereum Common library"
license       = "MIT"
skipDirs      = @["tests"]

requires "nim >= 2.0.10",
         "nimcrypto",
         "stint >= 0.8.0",
         "secp256k1",
         "chronos",
         "chronicles",
         "stew",
         "nat_traversal",
         "metrics",
         "sqlite3_abi",
         "confutils",
         "testutils",
         "unittest2",
         "results",
         "minilru",
         "snappy"

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]

let cfg =
  " --styleCheck:usages --styleCheck:error" &
  (if verbose: "" else: " --verbosity:0 --hints:off") &
  " --skipUserCfg --nimcache:build/nimcache -f" &
  " --warning[ObservableStores]:off -d:nimOldCaseObjects" &
  " -d:chronicles_log_level=TRACE" &
  " --threads:on -d:debug" &
  " --excessiveStackTrace:on"


proc build(args, path, outdir: string) =
  exec nimc & " " & lang & " " & cfg & " " & flags & " " & args &
    " --outdir:build/" & outdir & " " & path

proc run(path, outdir: string) =
  build "--mm:refc -r", path, outdir
  build "--mm:orc -r", path, outdir

task test_keyfile, "Run keyfile tests":
  run "tests/keyfile/all_tests", "keyfile"

task test_discv5, "Run discovery v5 tests":
  run "tests/p2p/all_discv5_tests", "p2p"

task test_discv4, "Run discovery v4 tests":
  run "tests/p2p/test_discovery", "p2p"

task test_p2p, "Run p2p tests":
  run "tests/p2p/all_tests", "p2p"

task test_rlp, "Run rlp tests":
  run "tests/rlp/all_tests", "rlp"

task test_trie, "Run trie tests":
  run "tests/trie/all_tests", "trie"

task test_db, "Run db tests":
  run "tests/db/all_tests", "db"

task test_utp, "Run utp tests":
  run "tests/utp/all_utp_tests", "utp"

task test_common, "Run common tests":
  run "tests/common/all_tests", "common"

task test, "Run all tests":
  run "tests/test_bloom", ""

  test_keyfile_task()
  test_rlp_task()
  test_p2p_task()
  test_trie_task()
  test_db_task()
  test_utp_task()
  test_common_task()

task test_discv5_full, "Run discovery v5 and its dependencies tests":
  test_rlp_task()
  test_discv5_task()

task build_dcli, "Build dcli":
  build "", "tools/dcli", ""

import os, strutils

task build_fuzzers, "Build fuzzer test cases":
  # This file is there to be able to quickly build the fuzzer test cases in
  # order to avoid bit rot (e.g. for CI). Not for actual fuzzing.
  # TODO: Building fuzzer test case one by one will make it take a bit longer,
  # but we cannot import them in one Nim file due to the usage of
  # `exportc: "AFLmain"` in the fuzzing test template for Windows:
  # https://github.com/status-im/nim-testutils/blob/master/testutils/fuzzing.nim#L100
  for file in walkDirRec("tests/fuzzing/"):
    if file.endsWith("nim"):
      build "", file, "fuzzing"
