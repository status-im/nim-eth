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
         "metrics"

proc runTest(path: string) =
  echo "\nRunning: ", path
  exec "nim c -r -d:release -d:chronicles_log_level=ERROR --verbosity:0 --hints:off " & path
  rmFile path

proc runKeyfileTests() =
  for filename in [
      "test_keyfile",
      "test_uuid",
    ]:
    runTest("tests/keyfile/" & filename)

task test_keyfile, "run keyfile tests":
  runKeyfileTests()

proc runKeysTests() =
  for filename in [
      "test_keys",
      "test_private_public_key_consistency"
    ]:
    runTest("tests/keys/" & filename)

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
      "test_waku_connect",
      "test_waku_bridge",
      "test_waku_mail",
      "test_protocol_handlers",
      "test_enr",
      "test_discoveryv5",
      "test_discv5_encoding"
    ]:
    runTest("tests/p2p/" & filename)

task test_p2p, "run p2p tests":
  runP2pTests()

proc runRlpTests() =
  runTest("tests/rlp/all_tests")

task test_rlp, "run rlp tests":
  runRlpTests()

proc runTrieTests() =
  runTest("tests/trie/all_tests")

task test_trie, "run trie tests":
  runTrieTests()

task test, "run tests":
  for filename in [
      "test_bloom",
      "test_common",
    ]:
    runTest("tests/" & filename)

  runKeyfileTests()
  runKeysTests()
  runP2pTests()
  runRlpTests()
  runTrieTests()

