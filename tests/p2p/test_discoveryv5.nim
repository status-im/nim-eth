{.used.}

import
  std/tables,
  chronos, chronicles, stint, testutils/unittests, stew/shims/net,
  stew/byteutils, bearssl,
  ../../eth/keys,
  ../../eth/p2p/discoveryv5/[enr, node, routing_table, encoding, sessions, messages],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol,
  ./discv5_test_helper

procSuite "Discovery v5 Tests":
  let rng = newRng()

  asyncTest "GetNode":
    # TODO: This could be tested in just a routing table only context
    let
      node = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302))
      targetNode = generateNode(PrivateKey.random(rng[]))

    check node.addNode(targetNode)

    for i in 0..<1000:
      discard node.addNode(generateNode(PrivateKey.random(rng[])))

    let n = node.getNode(targetNode.id)
    check n.isSome()
    check n.get() == targetNode

    await node.closeWait()

  asyncTest "Node deletion":
    let
      bootnode = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20301))
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302),
        @[bootnode.localNode.record])
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303),
        @[bootnode.localNode.record])
      pong1 = await discv5_protocol.ping(node1, bootnode.localNode)
      pong2 = await discv5_protocol.ping(node1, node2.localNode)

    check pong1.isOk() and pong2.isOk()

    await bootnode.closeWait()
    await node2.closeWait()

    await node1.revalidateNode(bootnode.localNode)
    await node1.revalidateNode(node2.localNode)

    let n = node1.getNode(bootnode.localNode.id)
    check:
      n.isSome()
      n.get() == bootnode.localNode
      node1.getNode(node2.localNode.id).isNone()

    await node1.closeWait()

  test "Distance check":
    const
      targetId = "0x0000"
      testValues = [
        ("0x0001", 1'u32),
        ("0x0002", 2'u32),
        ("0x0003", 2'u32),
        ("0x0004", 3'u32),
        ("0x0007", 3'u32),
        ("0x0008", 4'u32),
        ("0x000f", 4'u32),
        ("0x0080", 8'u32),
        ("0x00ff", 8'u32),
        ("0x0100", 9'u32),
        ("0x01ff", 9'u32),
        ("0x8000", 16'u32),
        ("0xffff", 16'u32)
      ]

    for (id, d) in testValues:
      check logDist(parse(targetId, UInt256, 16), parse(id, UInt256, 16)) == d

  test "Distance check with keys":
    const
      targetKey = "5d485bdcbe9bc89314a10ae9231e429d33853e3a8fa2af39f5f827370a2e4185e344ace5d16237491dad41f278f1d3785210d29ace76cd627b9147ee340b1125"
      testValues = [
        ("29738ba0c1a4397d6a65f292eee07f02df8e58d41594ba2be3cf84ce0fc58169", 251'u32),
        ("1c9b1cafbec00848d2c174b858219914b42a7d5c9359b1ca03fd650e8239ae94", 252'u32),
        ("2d0511ae9bf590166597eeab86b6f27b1ab761761eaea8965487b162f8703847", 253'u32),
        ("dec742079ec00ff4ec1284d7905bc3de2366f67a0769431fd16f80fd68c58a7c", 254'u32),
        ("da8645f90826e57228d9ea72aff84500060ad111a5d62e4af831ed8e4b5acfb8", 255'u32),
        ("8c5b422155d33ea8e9d46f71d1ad3e7b24cb40051413ffa1a81cff613d243ba9", 256'u32)
      ]

    let targetId = toNodeId(PublicKey.fromHex(targetKey)[])

    for (key, d) in testValues:
      let id = toNodeId(PrivateKey.fromHex(key)[].toPublicKey())
      check logDist(targetId, id) == d

  test "Distance to id check":
    const
      targetId = "0x0000"
      testValues = [ # possible id in that distance range
        ("0x0001", 1'u32),
        ("0x0002", 2'u32),
        ("0x0004", 3'u32),
        ("0x0008", 4'u32),
        ("0x0080", 8'u32),
        ("0x0100", 9'u32),
        ("0x8000", 16'u32)
      ]

    for (id, d) in testValues:
      check idAtDistance(parse(targetId, UInt256, 16), d) == parse(id, UInt256, 16)

  test "Distance to id check with keys":
    const
      targetKey = "5d485bdcbe9bc89314a10ae9231e429d33853e3a8fa2af39f5f827370a2e4185e344ace5d16237491dad41f278f1d3785210d29ace76cd627b9147ee340b1125"
      testValues = [ # possible id in that distance range
        ("9e5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 251'u32),
        ("925b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 252'u32),
        ("8a5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 253'u32),
        ("ba5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 254'u32),
        ("da5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 255'u32),
        ("1a5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 256'u32)
      ]

    let targetId = toNodeId(PublicKey.fromHex(targetKey)[])

    for (id, d) in testValues:
      check idAtDistance(targetId, d) == parse(id, UInt256, 16)

  asyncTest "FindNode Test":
    const dist = 253'u32
    let
      mainNodeKey = PrivateKey.fromHex(
        "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
      testNodeKey = PrivateKey.fromHex(
        "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618")[]
      mainNode = initDiscoveryNode(rng, mainNodeKey, localAddress(20301))
      testNode = initDiscoveryNode(rng, testNodeKey, localAddress(20302))
      # logarithmic distance between mainNode and testNode is 256

    let nodes = nodesAtDistance(mainNode.localNode, rng[], dist, 10)
    for n in nodes:
      discard mainNode.addSeenNode(n) # for testing only!

    # ping in one direction to add, ping in the other to update seen.
    check (await testNode.ping(mainNode.localNode)).isOk()
    check (await mainNode.ping(testNode.localNode)).isOk()

    # Get ENR of the node itself
    var discovered =
      await findNode(testNode, mainNode.localNode, @[0'u32])
    check:
      discovered.isOk
      discovered[].len == 1
      discovered[][0] == mainNode.localNode
    # Get ENRs of nodes added at provided logarithmic distance
    discovered =
      await findNode(testNode, mainNode.localNode, @[dist])
    check discovered.isOk
    check discovered[].len == 10
    for n in nodes:
      check discovered[].contains(n)

    # Too high logarithmic distance, should return no nodes.
    discovered =
      await findNode(testNode, mainNode.localNode, @[4294967295'u32])
    check:
      discovered.isOk
      discovered[].len == 0

    # Logarithmic distance of 256 should only return the testNode
    discovered =
      await findNode(testNode, mainNode.localNode, @[256'u32])
    check:
      discovered.isOk
      discovered[].len == 1
      discovered[][0] == testNode.localNode

    # Empty bucket
    discovered =
      await findNode(testNode, mainNode.localNode, @[254'u32])
    check discovered.isOk
    check discovered[].len == 0

    let moreNodes = nodesAtDistance(mainNode.localNode, rng[], dist, 10)
    for n in moreNodes:
      discard mainNode.addSeenNode(n) # for testing only!

    # Full bucket
    discovered =
      await findNode(testNode, mainNode.localNode, @[dist])
    check discovered.isOk
    check discovered[].len == 16

    await mainNode.closeWait()
    await testNode.closeWait()

  asyncTest "FindNode with test table":

    let mainNode =
      initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301))

    # Generate 1000 random nodes and add to our main node's routing table
    for i in 0..<1000:
      discard mainNode.addSeenNode(generateNode(PrivateKey.random(rng[]))) # for testing only!

    let
      neighbours = mainNode.neighbours(mainNode.localNode.id)
      closest = neighbours[0]
      closestDistance = logDist(closest.id, mainNode.localNode.id)

    debug "Closest neighbour", closestDistance, id=closest.id.toHex()

    let
      testNode = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302),
        @[mainNode.localNode.record])
      discovered = await findNode(testNode, mainNode.localNode,
        @[closestDistance])

    check discovered.isOk
    check closest in discovered[]

    await mainNode.closeWait()
    await testNode.closeWait()

  asyncTest "Lookup targets":
    const
      nodeCount = 17

    let bootNode =
      initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301))
    bootNode.start()

    var nodes = newSeqOfCap[discv5_protocol.Protocol](nodeCount)
    nodes.add(bootNode)
    for i in 1 ..< nodeCount:
      nodes.add(initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301 + i),
        @[bootNode.localNode.record]))

    # Make sure all nodes have "seen" each other by forcing pings
    for n in nodes:
      for t in nodes:
        if n != t:
          let pong = await n.ping(t.localNode)
          check pong.isOk()
          if pong.isErr():
            echo pong.error
          # check (await n.ping(t.localNode)).isOk()

    for i in 1 ..< nodeCount:
      nodes[i].start()

    for i in 0..<nodeCount-1:
      let target = nodes[i]
      let discovered = await nodes[nodeCount-1].lookup(target.localNode.id)
      debug "Lookup result", target = target.localNode, discovered
      check discovered[0] == target.localNode

    for node in nodes:
      await node.closeWait()

  asyncTest "Resolve target":
    let
      mainNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301))
      lookupNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302))
      targetKey = PrivateKey.random(rng[])
      targetAddress = localAddress(20303)
      targetNode = initDiscoveryNode(rng, targetKey, targetAddress)
      targetId = targetNode.localNode.id

    var targetSeqNum = targetNode.localNode.record.seqNum

    # Populate routing table with target through a ping. Next, close target and
    # see if resolve works (only local getNode).
    block:
      let pong = await targetNode.ping(mainNode.localNode)
      check pong.isOk()
      await targetNode.closeWait()
      let n = await mainNode.resolve(targetId)
      check:
        n.isSome()
        n.get().id == targetId
        n.get().record.seqNum == targetSeqNum
    # Node will be removed because of failed findNode request.

    # Bring target back online, update seqNum in ENR, check if we get the
    # updated ENR.
    block:
      targetNode.open()
      # Request the target ENR and manually add it to the routing table.
      # Ping for handshake based ENR passing will not work as our previous
      # session will still be in the LRU cache.
      let nodes = await mainNode.findNode(targetNode.localNode, @[0'u32])
      check:
        nodes.isOk()
        nodes[].len == 1
        mainNode.addNode(nodes[][0])

      targetSeqNum.inc()
      # need to add something to get the enr sequence number incremented
      let update = targetNode.updateRecord({"addsomefield": @[byte 1]})
      check update.isOk()

      var n = mainNode.getNode(targetId)
      check:
        n.isSome()
        n.get().id == targetId
        n.get().record.seqNum == targetSeqNum - 1

      n = await mainNode.resolve(targetId)
      check:
        n.isSome()
        n.get().id == targetId
        n.get().record.seqNum == targetSeqNum

      # Add the updated version
      discard mainNode.addNode(n.get())

    # Update seqNum in ENR again, ping lookupNode to be added in routing table,
    # close targetNode, resolve should lookup, check if we get updated ENR.
    block:
      targetSeqNum.inc()
      let update = targetNode.updateRecord({"addsomefield": @[byte 2]})
      check update.isOk()

      # ping node so that its ENR gets added
      check (await targetNode.ping(lookupNode.localNode)).isOk()
      # ping node so that it becomes "seen" and thus will be forwarded on a
      # findNode request
      check (await lookupNode.ping(targetNode.localNode)).isOk()
      await targetNode.closeWait()

      check mainNode.addNode(lookupNode.localNode.record)
      let n = await mainNode.resolve(targetId)
      check:
        n.isSome()
        n.get().id == targetId
        n.get().record.seqNum == targetSeqNum

    await mainNode.closeWait()
    await lookupNode.closeWait()

  asyncTest "Random nodes with enr field filter":
    let
      lookupNode = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301))
      targetFieldPair = toFieldPair("test", @[byte 1,2,3,4])
      targetNode = generateNode(PrivateKey.random(rng[]), localEnrFields = [targetFieldPair])
      otherFieldPair = toFieldPair("test", @[byte 1,2,3,4,5])
      otherNode = generateNode(PrivateKey.random(rng[]), localEnrFields = [otherFieldPair])
      anotherNode = generateNode(PrivateKey.random(rng[]))

    check:
      lookupNode.addNode(targetNode)
      lookupNode.addNode(otherNode)
      lookupNode.addNode(anotherNode)

    let discovered = lookupNode.randomNodes(10)
    check discovered.len == 3
    let discoveredFiltered = lookupNode.randomNodes(10,
      ("test", @[byte 1,2,3,4]))
    check discoveredFiltered.len == 1 and discoveredFiltered.contains(targetNode)

    await lookupNode.closeWait()

  test "New protocol with enr":
    let
      privKey = PrivateKey.random(rng[])
      ip = some(ValidIpAddress.init("127.0.0.1"))
      port = Port(20301)
      node = newProtocol(privKey, ip, some(port), some(port), bindPort = port,
        rng = rng)
      noUpdatesNode = newProtocol(privKey, ip, some(port), some(port),
        bindPort = port, rng = rng, previousRecord = some(node.getRecord()))
      updatesNode = newProtocol(privKey, ip, some(port), some(Port(20302)),
        bindPort = port, rng = rng,
        previousRecord = some(noUpdatesNode.getRecord()))
      moreUpdatesNode = newProtocol(privKey, ip, some(port), some(port),
        bindPort = port, rng = rng, localEnrFields = {"addfield": @[byte 0]},
        previousRecord = some(updatesNode.getRecord()))
    check:
      node.getRecord().seqNum == 1
      noUpdatesNode.getRecord().seqNum == 1
      updatesNode.getRecord().seqNum == 2
      moreUpdatesNode.getRecord().seqNum == 3

    # Defect (for now?) on incorrect key use
    expect ResultDefect:
      let incorrectKeyUpdates = newProtocol(PrivateKey.random(rng[]),
        ip, some(port), some(port), bindPort = port, rng = rng,
        previousRecord = some(updatesNode.getRecord()))

  asyncTest "Update node record with revalidate":
    let
      mainNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301))
      testNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302))
      testNodeId = testNode.localNode.id

    check:
      # Get node with current ENR in routing table.
      # Handshake will get done here.
      (await testNode.ping(mainNode.localNode)).isOk()
      testNode.updateRecord({"test" : @[byte 1]}).isOk()
      testNode.localNode.record.seqNum == 2

    # Get the node from routing table, seqNum should still be 1.
    var n = mainNode.getNode(testNodeId)
    check:
      n.isSome()
      n.get.record.seqNum == 1

    # This should not do a handshake and thus the new ENR must come from the
    # findNode(0)
    await mainNode.revalidateNode(n.get)

    # Get the node from routing table, and check if record got updated.
    n = mainNode.getNode(testNodeId)
    check:
      n.isSome()
      n.get.record.seqNum == 2

    await mainNode.closeWait()
    await testNode.closeWait()

  asyncTest "Update node record with handshake":
    let
      mainNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301))
      testNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302))
      testNodeId = testNode.localNode.id

    # Add the node (from the record, so new node!) so no handshake is done yet.
    check: mainNode.addNode(testNode.localNode.record)

    check:
      testNode.updateRecord({"test" : @[byte 1]}).isOk()
      testNode.localNode.record.seqNum == 2

    # Get the node from routing table, seqNum should still be 1.
    var n = mainNode.getNode(testNodeId)
    check:
      n.isSome()
      n.get.record.seqNum == 1

    # This should do a handshake and update the ENR through that.
    check (await testNode.ping(mainNode.localNode)).isOk()

    # Get the node from routing table, and check if record got updated.
    n = mainNode.getNode(testNodeId)
    check:
      n.isSome()
      n.get.record.seqNum == 2

    await mainNode.closeWait()
    await testNode.closeWait()

  test "Verify records of nodes message":
    let
      port = Port(9000)
      fromNoderecord = enr.Record.init(1, PrivateKey.random(rng[]),
        some(ValidIpAddress.init("11.12.13.14")),
        some(port), some(port))[]
      fromNode = newNode(fromNoderecord)[]
      pk = PrivateKey.random(rng[])
      targetDistance = logDist(fromNode.id, pk.toPublicKey().toNodeId())

    block: # Duplicates
      let
        record = enr.Record.init(
          1, pk, some(ValidIpAddress.init("12.13.14.15")),
          some(port), some(port))[]

      # Exact duplicates
      var records = @[record, record]
      var nodes = verifyNodesRecords(records, fromNode, targetDistance)
      check nodes.len == 1

      # Node id duplicates
      let recordSameId = enr.Record.init(
        1, pk, some(ValidIpAddress.init("212.13.14.15")),
        some(port), some(port))[]
      records.add(recordSameId)
      nodes = verifyNodesRecords(records, fromNode, targetDistance)
      check nodes.len == 1

    block: # No address
      let
        recordNoAddress = enr.Record.init(
          1, pk, none(ValidIpAddress), some(port), some(port))[]
        records = [recordNoAddress]
        test = verifyNodesRecords(records, fromNode, targetDistance)
      check test.len == 0

    block: # Invalid address - site local
      let
        recordInvalidAddress = enr.Record.init(
          1, pk, some(ValidIpAddress.init("10.1.2.3")),
          some(port), some(port))[]
        records = [recordInvalidAddress]
        test = verifyNodesRecords(records, fromNode, targetDistance)
      check test.len == 0

    block: # Invalid address - loopback
      let
        recordInvalidAddress = enr.Record.init(
          1, pk, some(ValidIpAddress.init("127.0.0.1")),
          some(port), some(port))[]
        records = [recordInvalidAddress]
        test = verifyNodesRecords(records, fromNode, targetDistance)
      check test.len == 0

    block: # Invalid distance
      let
        recordInvalidDistance = enr.Record.init(
          1, pk, some(ValidIpAddress.init("12.13.14.15")),
          some(port), some(port))[]
        records = [recordInvalidDistance]
        test = verifyNodesRecords(records, fromNode, 0'u32)
      check test.len == 0

  asyncTest "Handshake cleanup: different ids":
    # Node to test the handshakes on.
    let receiveNode = initDiscoveryNode(
      rng, PrivateKey.random(rng[]), localAddress(20302))

    # Create random packets with same ip but different node ids
    # and "receive" them on receiveNode
    let a = localAddress(20303)
    for i in 0 ..< 5:
      let
        privKey = PrivateKey.random(rng[])
        enrRec = enr.Record.init(1, privKey,
          some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
          some(Port(9000))).expect("Properly intialized private key")
        sendNode = newNode(enrRec).expect("Properly initialized record")
      var codec = Codec(localNode: sendNode, privKey: privKey, sessions: Sessions.init(5))

      let (packet, _) = encodeMessagePacket(rng[], codec,
        receiveNode.localNode.id, receiveNode.localNode.address.get(), @[])
      receiveNode.receive(a, packet)

    # Checking different nodeIds but same address
    check receiveNode.codec.handshakes.len == 5
    # TODO: Could get rid of the sleep by storing the timeout future of the
    # handshake
    await sleepAsync(handshakeTimeout)
    # Checking handshake cleanup
    check receiveNode.codec.handshakes.len == 0

    await receiveNode.closeWait()

  asyncTest "Handshake cleanup: different ips":
    # Node to test the handshakes on.
    let receiveNode = initDiscoveryNode(
      rng, PrivateKey.random(rng[]), localAddress(20302))

    # Create random packets with same node ids but different ips
    # and "receive" them on receiveNode
    let
      privKey = PrivateKey.random(rng[])
      enrRec = enr.Record.init(1, privKey,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")
      sendNode = newNode(enrRec).expect("Properly initialized record")
    var codec = Codec(localNode: sendNode, privKey: privKey, sessions: Sessions.init(5))
    for i in 0 ..< 5:
      let a = localAddress(20303 + i)
      let (packet, _) = encodeMessagePacket(rng[], codec,
        receiveNode.localNode.id, receiveNode.localNode.address.get(), @[])
      receiveNode.receive(a, packet)

    # Checking different nodeIds but same address
    check receiveNode.codec.handshakes.len == 5
    # TODO: Could get rid of the sleep by storing the timeout future of the
    # handshake
    await sleepAsync(handshakeTimeout)
    # Checking handshake cleanup
    check receiveNode.codec.handshakes.len == 0

    await receiveNode.closeWait()

  asyncTest "Handshake duplicates":
    # Node to test the handshakes on.
    let receiveNode = initDiscoveryNode(
      rng, PrivateKey.random(rng[]), localAddress(20302))

    # Create random packets with same node ids and same ips
    # and "receive" them on receiveNode
    let
      a = localAddress(20303)
      privKey = PrivateKey.random(rng[])
      enrRec = enr.Record.init(1, privKey,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")
      sendNode = newNode(enrRec).expect("Properly initialized record")
    var codec = Codec(localNode: sendNode, privKey: privKey, sessions: Sessions.init(5))

    var firstRequestNonce: AESGCMNonce
    for i in 0 ..< 5:
      let (packet, requestNonce) = encodeMessagePacket(rng[], codec,
        receiveNode.localNode.id, receiveNode.localNode.address.get(), @[])
      receiveNode.receive(a, packet)
      if i == 0:
        firstRequestNonce = requestNonce

    # Check handshake duplicates
    check receiveNode.codec.handshakes.len == 1
    # Check if it is for the first packet that a handshake is stored
    let key = HandShakeKey(nodeId: sendNode.id, address: a)
    check receiveNode.codec.handshakes[key].whoareyouData.requestNonce ==
      firstRequestNonce

    await receiveNode.closeWait()

  asyncTest "Talkreq no protocol":
    let
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))
      talkresp = await discv5_protocol.talkreq(node1, node2.localNode,
        @[byte 0x01], @[])

    check:
      talkresp.isOk()
      talkresp.get().response.len == 0

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Talkreq echo protocol":
    let
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))
      talkProtocol = "echo".toBytes()

    proc handler(request: seq[byte]): seq[byte] {.gcsafe, raises: [Defect].} =
      request

    check node2.registerTalkProtocol(talkProtocol, handler).isOk()
    let talkresp = await discv5_protocol.talkreq(node1, node2.localNode,
      talkProtocol, "hello".toBytes())

    check:
      talkresp.isOk()
      talkresp.get().response == "hello".toBytes()

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Talkreq register protocols":
    let
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))
      talkProtocol = "echo".toBytes()

    proc handler(request: seq[byte]): seq[byte] {.gcsafe, raises: [Defect].} =
      request

    check:
      node2.registerTalkProtocol(talkProtocol, handler).isOk()
      node2.registerTalkProtocol(talkProtocol, handler).isErr()
      node2.registerTalkProtocol("test".toBytes(), handler).isOk()

    await node1.closeWait()
    await node2.closeWait()
