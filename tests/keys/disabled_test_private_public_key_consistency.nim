# Nim Eth-keys
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import  ../src/eth_keys,
        ./config

import unittest

suite "Testing private -> public key conversion":
  test "Known private to known public keys (test data from Ethereum eth-keys)":
    for person in [alice, bob, eve]:
      let privkey = initPrivateKey(person.privkey)

      let computed_pubkey = $privkey.public_key

      check: computed_pubkey == person.pubkey
