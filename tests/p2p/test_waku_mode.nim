#
#                     Waku
#              (c) Copyright 2019
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  sequtils, options, unittest, chronos, eth/[keys, p2p],
  eth/p2p/rlpx_protocols/waku_protocol, eth/p2p/peer_pool,
  ./p2p_test_helper

const
  safeTTL = 5'u32
  waitInterval = messageInterval + 150.milliseconds

suite "Waku Mode":
  asyncTest "Test Waku-chan with Waku-san":
    var wakuChan = setupTestNode(Waku)
    var wakuSan = setupTestNode(Waku)

    let topic1 = [byte 0xDA, 0xDA, 0xDA, 0xAA]
    let topic2 = [byte 0xD0, 0xD0, 0xD0, 0x00]
    let wrongTopic = [byte 0x4B, 0x1D, 0x4B, 0x1D]

    wakuChan.protocolState(Waku).config.wakuMode = WakuChan
    wakuChan.protocolState(Waku).config.topics = @[topic1, topic2]
    wakuSan.protocolState(Waku).config.wakuMode = WakuSan

    wakuSan.startListening()
    await wakuChan.peerPool.connectToNode(newNode(initENode(wakuSan.keys.pubKey,
                                                            wakuSan.address)))

    let payload = repeat(byte 0, 10)
    check:
      wakuSan.postMessage(ttl = safeTTL, topic = topic1, payload = payload)
      wakuSan.postMessage(ttl = safeTTL, topic = topic2, payload = payload)
      wakuSan.postMessage(ttl = safeTTL, topic = wrongTopic, payload = payload)
      wakuSan.protocolState(Waku).queue.items.len == 3
    await sleepAsync(waitInterval)
    check:
      wakuChan.protocolState(Waku).queue.items.len == 2

  asyncTest "Test Waku connections":
    var n1 = setupTestNode(Waku)
    var n2 = setupTestNode(Waku)
    var n3 = setupTestNode(Waku)
    var n4 = setupTestNode(Waku)
    var n5 = setupTestNode(Waku)

    n1.protocolState(Waku).config.wakuMode = WakuMode.None
    n2.protocolState(Waku).config.wakuMode = WakuChan
    n3.protocolState(Waku).config.wakuMode = WakuChan
    n4.protocolState(Waku).config.wakuMode = WakuSan
    n5.protocolState(Waku).config.wakuMode = WakuSan

    n1.startListening()
    n3.startListening()
    n5.startListening()

    let p1 = await n2.rlpxConnect(newNode(initENode(n1.keys.pubKey,
                                                    n1.address)))
    let p2 = await n2.rlpxConnect(newNode(initENode(n3.keys.pubKey,
                                                    n3.address)))
    check:
      p1.isNil
      p2.isNil

    let p3 = await n4.rlpxConnect(newNode(initENode(n1.keys.pubKey,
                                                    n1.address)))
    let p4 = await n4.rlpxConnect(newNode(initENode(n5.keys.pubKey,
                                                    n5.address)))
    check:
      p3.isNil == false
      p4.isNil == false
