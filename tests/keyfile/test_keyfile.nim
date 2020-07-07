#
#                  Ethereum KeyFile
#                 (c) Copyright 2018
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

{.used.}

import eth/keys, eth/keyfile/[keyfile], json, os, unittest

# Test vectors copied from
# https://github.com/ethereum/tests/blob/develop/KeyStoreTests/basic_tests.json

let rng = newRng()

var TestVectors = [
  %*{
    "keyfile": {
      "crypto" : {
        "cipher" : "aes-128-ctr",
        "cipherparams" : {"iv" : "6087dab2f9fdbbfaddc31a909735c1e6"},
        "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        "kdf" : "pbkdf2",
        "kdfparams" : {
          "c" : 262144,
          "dklen" : 32,
          "prf" : "hmac-sha256",
          "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
        },
        "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
      },
      "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
      "version" : 3
    },
    "name": "test1",
    "password": "testpassword",
    "priv": "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
  },
  %*{
    "keyfile": {
      "version": 3,
      "crypto": {
        "ciphertext": "ee75456c006b1e468133c5d2a916bacd3cf515ced4d9b021b5c59978007d1e87",
        "version": 1,
        "kdf": "pbkdf2",
        "kdfparams": {
          "dklen": 32,
          "c": 262144,
          "prf": "hmac-sha256",
          "salt": "504490577620f64f43d73f29479c2cf0"
        },
        "mac": "196815708465de9af7504144a1360d08874fc3c30bb0e648ce88fbc36830d35d",
        "cipherparams": {"iv": "514ccc8c4fb3e60e5538e0cf1e27c233"},
        "cipher": "aes-128-ctr"
      },
      "id": "98d193c7-5174-4c7c-5345-c1daf95477b5"
    },
    "name": "python_generated_test_with_odd_iv",
    "password": "foo",
    "priv": "0101010101010101010101010101010101010101010101010101010101010101"
  },
  %*{
    "keyfile": {
      "version": 3,
      "crypto": {
        "ciphertext": "d69313b6470ac1942f75d72ebf8818a0d484ac78478a132ee081cd954d6bd7a9",
        "cipherparams": {"iv": "ffffffffffffffffffffffffffffffff"},
        "kdf": "pbkdf2",
        "kdfparams": {
          "dklen": 32,
          "c": 262144,
          "prf": "hmac-sha256",
          "salt": "c82ef14476014cbf438081a42709e2ed"
        },
        "mac": "cf6bfbcc77142a22c4a908784b4a16f1023a1d0e2aff404c20158fa4f1587177",
        "cipher": "aes-128-ctr",
        "version": 1
      },
      "id": "abb67040-8dbe-0dad-fc39-2b082ef0ee5f"
    },
    "name": "evilnonce",
    "password": "bar",
    "priv": "0202020202020202020202020202020202020202020202020202020202020202"
  }
]

suite "KeyFile test suite":
  test "KeyStoreTests/basic_tests.json test1":

    var expectkey = PrivateKey.fromHex(TestVectors[0].getOrDefault("priv").getStr())[]
    let seckey =
      decodeKeyFileJson(TestVectors[0].getOrDefault("keyfile"),
                        TestVectors[0].getOrDefault("password").getStr())[]
    check:
      seckey.toRaw() == expectkey.toRaw()
  test "KeyStoreTests/basic_tests.json python_generated_test_with_odd_iv":
    var expectkey = PrivateKey.fromHex(TestVectors[1].getOrDefault("priv").getStr())[]
    let seckey =
      decodeKeyFileJson(TestVectors[1].getOrDefault("keyfile"),
                        TestVectors[1].getOrDefault("password").getStr())[]
    check:
      seckey.toRaw == expectkey.toRaw
  test "KeyStoreTests/basic_tests.json evilnonce":
    var expectkey = PrivateKey.fromHex(TestVectors[2].getOrDefault("priv").getStr())[]
    let seckey = decodeKeyFileJson(TestVectors[2].getOrDefault("keyfile"),
                      TestVectors[2].getOrDefault("password").getStr())[]
    check:
      seckey.toRaw == expectkey.toRaw
  test "KeyStoreTests/basic_tests.json evilnonce with wrong password":
    let seckey =
      decodeKeyFileJson(TestVectors[2].getOrDefault("keyfile"),
                        "wrongpassword")
    check:
      seckey.error == KeyFileError.IncorrectMac
  test "Create/Save/Load test":
    var seckey0 = PrivateKey.random(rng[])
    let jobject = createKeyFileJson(seckey0, "randompassword")[]

    check:
      saveKeyFile("test.keyfile", jobject).isOk()
    var seckey1 = loadKeyFile("test.keyfile", "randompassword")[]
    check:
      seckey0.toRaw == seckey1.toRaw
    removeFile("test.keyfile")
  test "Load non-existent pathname test":
    check:
      loadKeyFile("nonexistant.keyfile", "password").error ==
        KeyFileError.OsError
