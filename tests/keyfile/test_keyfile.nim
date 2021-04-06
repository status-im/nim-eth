#
#                  Ethereum KeyFile
#                 (c) Copyright 2018
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

{.used.}

import
  std/[json, os, unittest],
  ../../eth/keys, ../../eth/keyfile/[keyfile]

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
  },
  %*{
    "keyfile": {
      "version" : 3,
      "crypto" : {
          "cipher" : "aes-128-ctr",
          "cipherparams" : {
              "iv" : "83dbcc02d8ccb40e466191a123791e0e"
          },
          "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
          "kdf" : "scrypt",
          "kdfparams" : {
              "dklen" : 32,
              "n" : 262144,
              "r" : 1,
              "p" : 8,
              "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
          },
          "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
      },
      "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6"
    },
    "name" : "test2",
    "password": "testpassword",
    "priv": "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
  },
  %*{
    "keyfile": {
      "version": 3,
      "address": "460121576cc7df020759730751f92bd62fd78dd6",
      "crypto": {
          "ciphertext": "54ae683c6287fa3d58321f09d56e26d94e58a00d4f90bdd95782ae0e4aab618b",
          "cipherparams": {
              "iv": "681679cdb125bba9495d068b002816a4"
          },
          "cipher": "aes-128-ctr",
          "kdf": "scrypt",
          "kdfparams": {
              "dklen": 32,
              "salt": "c3407f363fce02a66e3c4bf4a8f6b7da1c1f54266cef66381f0625c251c32785",
              "n": 8192,
              "r": 8,
              "p": 1
          },
          "mac": "dea6bdf22a2f522166ed82808c22a6311e84c355f4bbe100d4260483ff675a46"
      },
      "id": "0eb785e0-340a-4290-9c42-90a11973ee47"
    },
    "name": "mycrypto",
    "password": "foobartest121",
    "priv": "05a4d3eb46c742cb8850440145ce70cbc80b59f891cf5f50fd3e9c280b50c4e4"
  },
  %*{
    "keyfile": {
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "7e7b02d2b4ef45d6c98cb885e75f48d5",
            },
            "ciphertext": "a7a5743a6c7eb3fa52396bd3fd94043b79075aac3ccbae8e62d3af94db00397c",
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": 8192,
                "p": 1,
                "r": 8,
                "salt": "247797c7a357b707a3bdbfaa55f4c553756bca09fec20ddc938e7636d21e4a20",
            },
            "mac": "5a3ba5bebfda2c384586eda5fcda9c8397d37c9b0cc347fea86525cf2ea3a468",
        },
        "address": "0b6f2de3dee015a95d3330dcb7baf8e08aa0112d",
        "id": "3c8efdd6-d538-47ec-b241-36783d3418b9",
        "version": 3
    },
    "password": "moomoocow",
    "priv": "21eac69b9a52f466bfe9047f0f21c9caf3a5cdaadf84e2750a9b3265d450d481",
    "name": "eth-keyfile-conftest"
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


  test "KeyStoreTests/basic_tests.json test2":
    var expectkey = PrivateKey.fromHex(TestVectors[3].getOrDefault("priv").getStr())[]
    let seckey =
      decodeKeyFileJson(TestVectors[3].getOrDefault("keyfile"),
                        TestVectors[3].getOrDefault("password").getStr())[]
    check:
      seckey.toRaw == expectkey.toRaw

  test "KeyStoreTests/basic_tests.json mycrypto":
    var expectkey = PrivateKey.fromHex(TestVectors[4].getOrDefault("priv").getStr())[]
    let seckey =
      decodeKeyFileJson(TestVectors[4].getOrDefault("keyfile"),
                        TestVectors[4].getOrDefault("password").getStr())[]
    check:
      seckey.toRaw == expectkey.toRaw

  test "eth-key/conftest.py":
    var expectkey = PrivateKey.fromHex(TestVectors[5].getOrDefault("priv").getStr())[]
    let seckey =
      decodeKeyFileJson(TestVectors[5].getOrDefault("keyfile"),
                        TestVectors[5].getOrDefault("password").getStr())[]
    check:
      seckey.toRaw == expectkey.toRaw

  test "eth-key/conftest.py with wrong password":
    let seckey =
      decodeKeyFileJson(TestVectors[5].getOrDefault("keyfile"),
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

  test "Scrypt roundtrip":
    let
      seckey1 = PrivateKey.random(rng[])
      jobject = createKeyFileJson(seckey1, "miawmiawcat", 3, AES128CTR, SCRYPT)[]
      privKey = decodeKeyFileJson(jobject, "miawmiawcat")[]

    check privKey.toRaw == secKey1.toRaw

  test "Load non-existent pathname test":
    check:
      loadKeyFile("nonexistant.keyfile", "password").error ==
        KeyFileError.OsError
