# nim-eth
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  stew/endians2,
  ../../eth/common/keys,
  ../../eth/p2p/discoveryv5/[sessions, node],
  ./discv5_test_helper

suite "Discovery v5.1 Sessions":
  setup:
    let rng = newRng()

  test "Sessions store/load":
    var sessions = Sessions.init(256)

    for i in 0..5:
      let
        key = PrivateKey.random(rng[])
        nodeId = key.toPublicKey().toNodeId()
        address = localAddress(9000+i)
        readKey, writeKey = rng[].generate(array[16, byte])

      sessions.store(nodeId, address, readKey, writeKey)

      let sessionOpt = sessions.load(nodeId, address)
      check:
        sessionOpt.isSome()
        sessionOpt.value().readKey == readKey
        sessionOpt.value().writeKey == writeKey
        sessionOpt.value().counter == 0

      let readKeyOpt = sessions.loadReadKey(nodeId, address)
      check:
        readKeyOpt.isSome()
        readKeyOpt.value() == readKey

  test "Session counter":
    let
      readKey, writeKey = rng[].generate(array[16, byte])
      session = Session(readKey: readKey, writeKey: writeKey, counter: 0)

    let nonce0 = session.nextNonce(rng[])
    check nonce0[0..3] == 0'u32.toBytesBE()

    let nonce1 = session.nextNonce(rng[])
    check nonce1[0..3] == 1'u32.toBytesBE()

  test "Sessions store/load - session counter":
    var sessions = Sessions.init(256)

    let
      key = PrivateKey.random(rng[])
      nodeId = key.toPublicKey().toNodeId()
      address = localAddress(9000)
      readKey, writeKey = rng[].generate(array[16, byte])

    sessions.store(nodeId, address, readKey, writeKey)

    block:
      let sessionOpt = sessions.load(nodeId, address)
      check sessionOpt.isSome()
      let session = sessionOpt.value()

      let nonce = session.nextNonce(rng[])
      check nonce[0..3] == 0'u32.toBytesBE()

    block:
      let sessionOpt = sessions.load(nodeId, address)
      check sessionOpt.isSome()
      let session = sessionOpt.value()

      let nonce = session.nextNonce(rng[])
      check nonce[0..3] == 1'u32.toBytesBE()
