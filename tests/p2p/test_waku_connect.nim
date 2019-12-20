#
#                   Waku
#              (c) Copyright 2019
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  sequtils, tables, unittest, chronos, eth/[keys, p2p],
  eth/p2p/rlpx_protocols/waku_protocol, eth/p2p/peer_pool,
  ./p2p_test_helper

const safeTTL = 5'u32

# TODO: Just repeat all the test_shh_connect tests here that are applicable or
# have some commonly shared test code for both protocols.
suite "Waku connections":
  asyncTest "Light node posting":
    var ln = setupTestNode(Waku)
    ln.setLightNode(true)
    var fn = setupTestNode(Waku)
    fn.startListening()
    await ln.peerPool.connectToNode(newNode(initENode(fn.keys.pubKey,
                                                      fn.address)))

    let topic = [byte 0, 0, 0, 0]

    check:
      ln.peerPool.connectedNodes.len() == 1
      # normal post
      ln.postMessage(ttl = safeTTL, topic = topic,
                      payload = repeat(byte 0, 10)) == true
      ln.protocolState(Waku).queue.items.len == 1
      # TODO: add test on message relaying
