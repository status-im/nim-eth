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

proc runTest(path: string, release: bool = true) =
  echo "\nRunning: ", path
  let releaseMode = if release: "-d:release" else: ""
  exec "nim c -r " & releaseMode &
    " -d:chronicles_log_level=ERROR --verbosity:0 --hints:off " & path
  rmFile path

proc runKeyfileTests() =
  runTest("tests/keyfile/all_tests")

task test_keyfile, "run keyfile tests":
  runKeyfileTests()

proc runKeysTests() =
  runTest("tests/keys/all_tests")

task test_keys, "run keys tests":
  runKeysTests()

proc runP2pTests() =
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
      "test_protocol_handlers",
      "test_enr",
      "test_hkdf",
      "test_lru",
      "test_ip_vote",
      "test_discoveryv5",
      "test_discoveryv5_encoding",
      "test_routing_table"
    ]:
    runTest("tests/p2p/" & filename)

task test_p2p, "run p2p tests":
  runP2pTests()

proc runRlpTests() =
  # workaround for github action CI
  # mysterious crash on windows-2019 64bit mode
  # cannot reproduce locally on windows-2019
  # running in virtualbox
  let releaseMode = if existsEnv"PLATFORM":
                      getEnv"PLATFORM" != "windows-amd64"
                    else: true

  runTest("tests/rlp/all_tests", releaseMode)

task test_rlp, "run rlp tests":
  runRlpTests()

proc runTrieTests() =
  runTest("tests/trie/all_tests")

task test_trie, "run trie tests":
  runTrieTests()

proc runDbTests() =
  runTest("tests/db/all_tests")

task test_db, "run db tests":
  runDbTests()

task test, "run tests":
  for filename in [
      "test_bloom",
    ]:
    runTest("tests/" & filename)

  runKeyfileTests()
  runKeysTests()
  runP2pTests()
  runRlpTests()
  runTrieTests()
  runDbTests()

proc runDiscv5Tests() =
  for filename in [
      "test_enr",
      "test_hkdf",
      "test_lru",
      "test_ip_vote",
      "test_discoveryv5",
      "test_discoveryv5_encoding",
      "test_routing_table"
    ]:
    runTest("tests/p2p/" & filename)

task test_discv5, "run tests of discovery v5 and its dependencies":
  runKeysTests()
  runRlpTests()
  runDiscv5Tests()
