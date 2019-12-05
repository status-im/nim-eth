version       = "1.0.0"
author        = "Status Research & Development GmbH"
description   = "Ethereum Common library"
license       = "MIT"
skipDirs      = @["tests"]

requires "nim >= 0.19.0",
         "nimcrypto",
         "stint",
         "secp256k1",
         "rocksdb",
         "chronos",
         "chronicles",
         "stew",
         "result",
         "nat_traversal",
         "metrics"

proc runTest(path: string) =
  echo "\nRunning: ", path
  exec "nim c -r -d:release -d:chronicles_log_level=ERROR --verbosity:0 --hints:off --warnings:off " & path
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
      "test_waku_bridge",
      "test_waku_mail",
      "test_protocol_handlers",
    ]:
    runTest("tests/p2p/" & filename)

task test_p2p, "run p2p tests":
  runP2pTests()

proc runRlpTests() =
  for filename in [
      "test_api_usage",
      "test_json_suite",
      "test_object_serialization",
    ]:
    runTest("tests/rlp/" & filename)

task test_rlp, "run rlp tests":
  runRlpTests()

proc runTrieTests() =
  for filename in [
      "test_binaries_utils",
      "test_bin_trie",
      "test_branches_utils",
      "test_caching_db_backend",
      "test_examples",
      "test_hexary_trie",
      "test_json_suite",
      "test_nibbles",
      "test_sparse_binary_trie",
      "test_storage_backends",
      "test_transaction_db",
    ]:
    runTest("tests/trie/" & filename)

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

