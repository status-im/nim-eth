version       = "1.0.0"
author        = "Status Research & Development GmbH"
description   = "Ethereum Common library"
license       = "MIT"
skipDirs      = @["tests"]

requires "nim >= 1.6.0",
         "nimcrypto",
         "stint",
         "secp256k1",
         "chronos",
         "chronicles",
         "stew",
         "nat_traversal",
         "metrics",
         "sqlite3_abi",
         "confutils",
         "testutils",
         "unittest2"

let commonParams =
  " --skipUserCfg:on" &
  " --verbosity:0 --hints:off" &
  " --warning[ObservableStores]:off" &
  " --styleCheck:usages --styleCheck:error" &
  " " & getEnv("NIMFLAGS") &
  " -d:chronosStrictException" &
  " -d:chronicles_log_level=TRACE"

proc runTest(path: string, release: bool = true) =
  echo "\nBuilding and running: ", path
  let releaseMode = if release: " -d:release" else: ""

  exec "nim c -r" &
    releaseMode & commonParams & " " & path
  rmFile path

proc buildBinary(path: string) =
  echo "\nBuilding: ", path
  exec "nim c -d:release" & commonParams &
    " --warning[CaseTransition]:off" &
    " " & path

task test_keyfile, "Run keyfile tests":
  runTest("tests/keyfile/all_tests")

task test_keys, "Run keys tests":
  runTest("tests/keys/all_tests")

task test_discv5, "Run discovery v5 tests":
  runTest("tests/p2p/all_discv5_tests")

task test_discv4, "Run discovery v4 tests":
  runTest("tests/p2p/test_discovery")

task test_p2p, "Run p2p tests":
  runTest("tests/p2p/all_tests")

task test_rlp, "Run rlp tests":
  # workaround for github action CI
  # mysterious crash on windows-2019 64bit mode
  # cannot reproduce locally on windows-2019
  # running in virtualbox
  let releaseMode = if existsEnv"PLATFORM":
                      getEnv"PLATFORM" != "windows-amd64"
                    else: true

  runTest("tests/rlp/all_tests", releaseMode)

task test_trie, "Run trie tests":
  runTest("tests/trie/all_tests")

task test_db, "Run db tests":
  runTest("tests/db/all_tests")

task test_utp, "Run utp tests":
  runTest("tests/utp/all_utp_tests")

task test_common, "Run common tests":
  runTest("tests/common/all_tests")

task test, "Run all tests":
  for filename in [
      "test_bloom",
    ]:
    runTest("tests/" & filename)

  test_keyfile_task()
  test_keys_task()
  test_rlp_task()
  test_p2p_task()
  test_trie_task()
  test_db_task()
  test_utp_task()
  test_common_task()

task test_discv5_full, "Run discovery v5 and its dependencies tests":
  test_keys_task()
  test_rlp_task()
  test_discv5_task()

task build_dcli, "Build dcli":
  buildBinary("tools/dcli")

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
      buildBinary(file)
