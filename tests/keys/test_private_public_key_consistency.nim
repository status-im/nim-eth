# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import  eth/keys,
        ./config

import unittest

suite "Testing private -> public key conversion":
  test "Known private to known public keys (test data from Ethereum eth-keys)":
    for person in [alice, bob, eve]:
      let
        privKey = PrivateKey.fromHex(person.privkey)[]
        pubKey = privKey.toPublicKey()

      check:
        # Compare as strings
        $pubKey == person.pubkey

        # Compare as keys
        pubKey == PublicKey.fromHex(person.pubkey)[]
