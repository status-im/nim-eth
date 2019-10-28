#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  sequtils, options, unittest, tables, chronos, eth/[keys, p2p],
  eth/p2p/rlpx_protocols/whisper_protocol, eth/p2p/peer_pool,
  ./p2p_test_helper

proc resetMessageQueues(nodes: varargs[EthereumNode]) =
  for node in nodes:
    node.resetMessageQueue()

let safeTTL = 5'u32
let waitInterval = messageInterval + 150.milliseconds

suite "Whisper connections":
  var node1 = setupTestNode(Whisper)
  var node2 = setupTestNode(Whisper)
  node2.startListening()
  waitFor node1.peerPool.connectToNode(newNode(initENode(node2.keys.pubKey,
                                                         node2.address)))
  asyncTest "Two peers connected":
    check:
      node1.peerPool.connectedNodes.len() == 1

  asyncTest "Filters with encryption and signing":
    let encryptKeyPair = newKeyPair()
    let signKeyPair = newKeyPair()
    var symKey: SymKey
    let topic = [byte 0x12, 0, 0, 0]
    var filters: seq[string] = @[]
    var payloads = [repeat(byte 1, 10), repeat(byte 2, 10),
                    repeat(byte 3, 10), repeat(byte 4, 10)]
    var futures = [newFuture[int](), newFuture[int](),
                   newFuture[int](), newFuture[int]()]

    proc handler1(msg: ReceivedMessage) =
      var count {.global.}: int
      check msg.decoded.payload == payloads[0] or msg.decoded.payload == payloads[1]
      count += 1
      if count == 2: futures[0].complete(1)
    proc handler2(msg: ReceivedMessage) =
      check msg.decoded.payload == payloads[1]
      futures[1].complete(1)
    proc handler3(msg: ReceivedMessage) =
      var count {.global.}: int
      check msg.decoded.payload == payloads[2] or msg.decoded.payload == payloads[3]
      count += 1
      if count == 2: futures[2].complete(1)
    proc handler4(msg: ReceivedMessage) =
      check msg.decoded.payload == payloads[3]
      futures[3].complete(1)

    # Filters
    # filter for encrypted asym
    filters.add(node1.subscribeFilter(newFilter(privateKey = some(encryptKeyPair.seckey),
                                                topics = @[topic]), handler1))
    # filter for encrypted asym + signed
    filters.add(node1.subscribeFilter(newFilter(some(signKeyPair.pubkey),
                                                privateKey = some(encryptKeyPair.seckey),
                                                topics = @[topic]), handler2))
    # filter for encrypted sym
    filters.add(node1.subscribeFilter(newFilter(symKey = some(symKey),
                                                topics = @[topic]), handler3))
    # filter for encrypted sym + signed
    filters.add(node1.subscribeFilter(newFilter(some(signKeyPair.pubkey),
                                                symKey = some(symKey),
                                                topics = @[topic]), handler4))
    # Messages
    check:
      # encrypted asym
      node2.postMessage(some(encryptKeyPair.pubkey), ttl = safeTTL,
                        topic = topic, payload = payloads[0]) == true
      # encrypted asym + signed
      node2.postMessage(some(encryptKeyPair.pubkey),
                        src = some(signKeyPair.seckey), ttl = safeTTL,
                        topic = topic, payload = payloads[1]) == true
      # encrypted sym
      node2.postMessage(symKey = some(symKey), ttl = safeTTL, topic = topic,
                        payload = payloads[2]) == true
      # encrypted sym + signed
      node2.postMessage(symKey = some(symKey),
                        src = some(signKeyPair.seckey),
                        ttl = safeTTL, topic = topic,
                        payload = payloads[3]) == true

      node2.protocolState(Whisper).queue.items.len == 4

    check:
      await allFutures(futures).withTimeout(waitInterval)
      node1.protocolState(Whisper).queue.items.len == 4

    for filter in filters:
      check node1.unsubscribeFilter(filter) == true

    resetMessageQueues(node1, node2)

  asyncTest "Filters with topics":
    let topic1 = [byte 0x12, 0, 0, 0]
    let topic2 = [byte 0x34, 0, 0, 0]
    var payloads = [repeat(byte 0, 10), repeat(byte 1, 10)]
    var futures = [newFuture[int](), newFuture[int]()]
    proc handler1(msg: ReceivedMessage) =
      check msg.decoded.payload == payloads[0]
      futures[0].complete(1)
    proc handler2(msg: ReceivedMessage) =
      check msg.decoded.payload == payloads[1]
      futures[1].complete(1)

    var filter1 = node1.subscribeFilter(newFilter(topics = @[topic1]), handler1)
    var filter2 = node1.subscribeFilter(newFilter(topics = @[topic2]), handler2)

    check:
      node2.postMessage(ttl = safeTTL + 1, topic = topic1,
                        payload = payloads[0]) == true
      node2.postMessage(ttl = safeTTL, topic = topic2,
                        payload = payloads[1]) == true
      node2.protocolState(Whisper).queue.items.len == 2

      await allFutures(futures).withTimeout(waitInterval)
      node1.protocolState(Whisper).queue.items.len == 2

      node1.unsubscribeFilter(filter1) == true
      node1.unsubscribeFilter(filter2) == true

    resetMessageQueues(node1, node2)

  asyncTest "Filters with PoW":
    let topic = [byte 0x12, 0, 0, 0]
    var payload = repeat(byte 0, 10)
    var futures = [newFuture[int](), newFuture[int]()]
    proc handler1(msg: ReceivedMessage) =
      check msg.decoded.payload == payload
      futures[0].complete(1)
    proc handler2(msg: ReceivedMessage) =
      check msg.decoded.payload == payload
      futures[1].complete(1)

    var filter1 = node1.subscribeFilter(newFilter(topics = @[topic], powReq = 0),
                                        handler1)
    var filter2 = node1.subscribeFilter(newFilter(topics = @[topic],
                                        powReq = 1_000_000), handler2)

    check:
      node2.postMessage(ttl = safeTTL, topic = topic, payload = payload) == true

      (await futures[0].withTimeout(waitInterval)) == true
      (await futures[1].withTimeout(waitInterval)) == false
      node1.protocolState(Whisper).queue.items.len == 1

      node1.unsubscribeFilter(filter1) == true
      node1.unsubscribeFilter(filter2) == true

    resetMessageQueues(node1, node2)

  asyncTest "Filters with queues":
    let topic = [byte 0, 0, 0, 0]
    let payload = repeat(byte 0, 10)

    var filter = node1.subscribeFilter(newFilter(topics = @[topic]))
    for i in countdown(10, 1):
      check node2.postMessage(ttl = safeTTL, topic = topic,
                              payload = payload) == true

    await sleepAsync(waitInterval)
    check:
      node1.getFilterMessages(filter).len() == 10
      node1.getFilterMessages(filter).len() == 0
      node1.unsubscribeFilter(filter) == true

    resetMessageQueues(node1, node2)

  asyncTest "Local filter notify":
    let topic = [byte 0, 0, 0, 0]

    var filter = node1.subscribeFilter(newFilter(topics = @[topic]))
    check:
      node1.postMessage(ttl = safeTTL, topic = topic,
                        payload = repeat(byte 4, 10)) == true
      node1.getFilterMessages(filter).len() == 1
      node1.unsubscribeFilter(filter) == true

    await sleepAsync(waitInterval)
    resetMessageQueues(node1, node2)

  asyncTest "Bloomfilter blocking":
    let sendTopic1 = [byte 0x12, 0, 0, 0]
    let sendTopic2 = [byte 0x34, 0, 0, 0]
    let filterTopics = @[[byte 0x34, 0, 0, 0],[byte 0x56, 0, 0, 0]]
    let payload = repeat(byte 0, 10)
    var f: Future[int] = newFuture[int]()
    proc handler(msg: ReceivedMessage) =
      check msg.decoded.payload == payload
      f.complete(1)
    var filter = node1.subscribeFilter(newFilter(topics = filterTopics), handler)
    await node1.setBloomFilter(node1.filtersToBloom())

    check:
      node2.postMessage(ttl = safeTTL, topic = sendTopic1,
                        payload = payload) == true
      node2.protocolState(Whisper).queue.items.len == 1

      (await f.withTimeout(waitInterval)) == false
      node1.protocolState(Whisper).queue.items.len == 0

    resetMessageQueues(node1, node2)

    f = newFuture[int]()

    check:
      node2.postMessage(ttl = safeTTL, topic = sendTopic2,
                        payload = payload) == true
      node2.protocolState(Whisper).queue.items.len == 1

      await f.withTimeout(waitInterval)
      f.read() == 1
      node1.protocolState(Whisper).queue.items.len == 1

      node1.unsubscribeFilter(filter) == true

    await node1.setBloomFilter(fullBloom())

    resetMessageQueues(node1, node2)

  asyncTest "PoW blocking":
    let topic = [byte 0, 0, 0, 0]
    let payload = repeat(byte 0, 10)

    await node1.setPowRequirement(1_000_000)
    check:
      node2.postMessage(ttl = safeTTL, topic = topic, payload = payload) == true
      node2.protocolState(Whisper).queue.items.len == 1
    await sleepAsync(waitInterval)
    check:
      node1.protocolState(Whisper).queue.items.len == 0

    resetMessageQueues(node1, node2)

    await node1.setPowRequirement(0.0)
    check:
      node2.postMessage(ttl = safeTTL, topic = topic, payload = payload) == true
      node2.protocolState(Whisper).queue.items.len == 1
    await sleepAsync(waitInterval)
    check:
      node1.protocolState(Whisper).queue.items.len == 1

    resetMessageQueues(node1, node2)

  asyncTest "Queue pruning":
    let topic = [byte 0, 0, 0, 0]
    let payload = repeat(byte 0, 10)
    # We need a minimum TTL of 2 as when set to 1 there is a small chance that
    # it is already expired after messageInterval due to rounding down of float
    # to uint32 in postMessage()
    let lowerTTL = 2'u32 # Lower TTL as we need to wait for messages to expire
    for i in countdown(10, 1):
      check node2.postMessage(ttl = lowerTTL, topic = topic, payload = payload) == true
    check node2.protocolState(Whisper).queue.items.len == 10

    await sleepAsync(waitInterval)
    check node1.protocolState(Whisper).queue.items.len == 10

    await sleepAsync(milliseconds((lowerTTL+1)*1000))
    check node1.protocolState(Whisper).queue.items.len == 0
    check node2.protocolState(Whisper).queue.items.len == 0

    resetMessageQueues(node1, node2)

  asyncTest "P2P post":
    let topic = [byte 0, 0, 0, 0]
    var f: Future[int] = newFuture[int]()
    proc handler(msg: ReceivedMessage) =
      check msg.decoded.payload == repeat(byte 4, 10)
      f.complete(1)

    var filter = node1.subscribeFilter(newFilter(topics = @[topic],
                                       allowP2P = true), handler)
    check:
      node1.setPeerTrusted(toNodeId(node2.keys.pubkey)) == true
      node2.postMessage(ttl = 10, topic = topic,
                        payload = repeat(byte 4, 10),
                        targetPeer = some(toNodeId(node1.keys.pubkey))) == true

      await f.withTimeout(waitInterval)
      f.read() == 1
      node1.protocolState(Whisper).queue.items.len == 0
      node2.protocolState(Whisper).queue.items.len == 0

      node1.unsubscribeFilter(filter) == true

  asyncTest "Light node posting":
    var ln1 = setupTestNode(Whisper)
    ln1.setLightNode(true)

    await ln1.peerPool.connectToNode(newNode(initENode(node2.keys.pubKey,
                                                       node2.address)))

    let topic = [byte 0, 0, 0, 0]

    check:
      # normal post
      ln1.postMessage(ttl = safeTTL, topic = topic,
                      payload = repeat(byte 0, 10)) == false
      ln1.protocolState(Whisper).queue.items.len == 0
      # P2P post
      ln1.postMessage(ttl = safeTTL, topic = topic,
                        payload = repeat(byte 0, 10),
                        targetPeer = some(toNodeId(node2.keys.pubkey))) == true
      ln1.protocolState(Whisper).queue.items.len == 0

  asyncTest "Connect two light nodes":
    var ln1 = setupTestNode(Whisper)
    var ln2 = setupTestNode(Whisper)

    ln1.setLightNode(true)
    ln2.setLightNode(true)

    ln2.startListening()
    let peer = await ln1.rlpxConnect(newNode(initENode(ln2.keys.pubKey,
                                                       ln2.address)))
    check peer.isNil == true

  asyncTest "Test Waku-chan with Waku-san":
    var wakuChan = setupTestNode(Whisper)
    var wakuSan = setupTestNode(Whisper)

    let topic1 = [byte 0xDA, 0xDA, 0xDA, 0xAA]
    let topic2 = [byte 0xD0, 0xD0, 0xD0, 0x00]
    let wrongTopic = [byte 0x4B, 0x1D, 0x4B, 0x1D]

    wakuChan.protocolState(Whisper).config.wakuMode = WakuChan
    wakuChan.protocolState(Whisper).config.topics = @[topic1, topic2]
    wakuSan.protocolState(Whisper).config.wakuMode = WakuSan

    wakuSan.startListening()
    await wakuChan.peerPool.connectToNode(newNode(initENode(wakuSan.keys.pubKey,
                                                            wakuSan.address)))

    check:
      wakuSan.postMessage(ttl = safeTTL, topic = topic1,
                          payload = repeat(byte 0, 10)) == true
      wakuSan.postMessage(ttl = safeTTL, topic = topic2,
                          payload = repeat(byte 0, 10)) == true
      wakuSan.postMessage(ttl = safeTTL, topic = wrongTopic,
                          payload = repeat(byte 0, 10)) == true
      wakuSan.protocolState(Whisper).queue.items.len == 3
    await sleepAsync(waitInterval)
    check:
      wakuChan.protocolState(Whisper).queue.items.len == 2

  asyncTest "Test Waku connections":
    var n1 = setupTestNode(Whisper)
    var n2 = setupTestNode(Whisper)
    var n3 = setupTestNode(Whisper)
    var n4 = setupTestNode(Whisper)
    var n5 = setupTestNode(Whisper)

    n1.protocolState(Whisper).config.wakuMode = WakuMode.None
    n2.protocolState(Whisper).config.wakuMode = WakuChan
    n3.protocolState(Whisper).config.wakuMode = WakuChan
    n4.protocolState(Whisper).config.wakuMode = WakuSan
    n5.protocolState(Whisper).config.wakuMode = WakuSan

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
