version       = "1.0.0"
author        = "Status Research & Development GmbH"
description   = "Ethereum Common library"
license       = "MIT"
skipDirs      = @["tests"]

requires "nim >= 1.2.0",
         "nimcrypto",
         "stint",
         "secp256k1",
         "rocksdb",
         "chronos",
         "chronicles",
         "stew",
         "nat_traversal",
         "metrics",
         "sqlite3_abi",
         "confutils",
         "testutils"

proc runTest(path: string, release: bool = true, chronosStrict = true) =
  echo "\nRunning: ", path
  let releaseMode = if release: "-d:release" else: ""
  let chronosMode =
    if chronosStrict: "-d:chronosStrictException" else: ""
  exec "nim c -r " & releaseMode & " " & chronosMode &
    " -d:chronicles_log_level=ERROR --verbosity:0 --hints:off " & path
  rmFile path

task test_keyfile, "Run keyfile tests":
  runTest("tests/keyfile/all_tests")

task test_keys, "Run keys tests":
  runTest("tests/keys/all_tests")

task test_discv5, "Run discovery v5 tests":
  runTest("tests/p2p/all_discv5_tests")

task test_p2p, "Run p2p tests":
  test_discv5_task()

  for filename in [
      "les/test_flow_control",
      "test_auth",
      "test_crypt",
      "test_discovery",
      "test_ecies",
      "test_enode",
      "test_rlpx_thunk",
      "test_shh",
      "test_shh_config",
      "test_shh_connect",
      "test_protocol_handlers"
    ]:
    runTest("tests/p2p/" & filename, chronosStrict = false)

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

task test_discv5_full, "Run discovery v5 and its dependencies tests":
  test_keys_task()
  test_rlp_task()
  test_discv5_task()
