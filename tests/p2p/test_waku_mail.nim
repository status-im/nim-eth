import
  unittest, chronos, tables, sequtils, times, eth/p2p, eth/p2p/peer_pool,
  eth/p2p/rlpx_protocols/waku_protocol, chronicles,
  ./p2p_test_helper

suite "Waku Mail Client":
  var client = setupTestNode(Waku)
  var simpleServer = setupTestNode(Waku)

  simpleServer.startListening()
  let simpleServerNode = newNode(initENode(simpleServer.keys.pubKey,
    simpleServer.address))
  let clientNode = newNode(initENode(client.keys.pubKey, client.address))
  waitFor client.peerPool.connectToNode(simpleServerNode)

  asyncTest "Two peers connected":
    check:
      client.peerPool.connectedNodes.len() == 1

  asyncTest "Test Mail Request":
    let
      topic = [byte 0, 0, 0, 0]
      bloom = toBloom(@[topic])
      lower = 0'u32
      upper = epochTime().uint32
      limit = 100'u32
      request = MailRequest(lower: lower, upper: upper, bloom: @bloom,
        limit: limit)

    var symKey: SymKey
    check client.requestMail(simpleServerNode.id, request, symKey)

    # Simple mailserver part
    let peer = simpleServer.peerPool.connectedNodes[clientNode]
    var f = peer.nextMsg(Waku.p2pRequest)
    require await f.withTimeout(chronos.milliseconds(100))
    let response = f.read()
    let decoded = decode(response.envelope.data, symKey = some(symKey))
    require decoded.isSome()

    var rlp = rlpFromBytes(decoded.get().payload.toRange)
    let output = rlp.read(MailRequest)
    check:
      output.lower == lower
      output.upper == upper
      output.bloom == bloom
      output.limit == limit

  asyncTest "Test Mail Send":
    let topic = [byte 0x12, 0x34, 0x56, 0x78]
    let payload = repeat(byte 0, 10)
    var f = newFuture[int]()

    proc handler(msg: ReceivedMessage) =
      check msg.decoded.payload == payload
      f.complete(1)

    let filter = subscribeFilter(client,
      newFilter(topics = @[topic], allowP2P = true), handler)

    check:
      client.setPeerTrusted(simpleServerNode.id)
      # ttl 0 to show that ttl should be ignored
      # TODO: perhaps not the best way to test this, means no PoW calculation
      # may be done, and not sure if that is OK?
      simpleServer.postMessage(ttl = 0, topic = topic, payload = payload,
        targetPeer = some(clientNode.id))

      await f.withTimeout(chronos.milliseconds(100))

      client.unsubscribeFilter(filter)
