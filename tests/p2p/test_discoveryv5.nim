import
  chronos, chronicles, tables, stint, nimcrypto, testutils/unittests,
  stew/shims/net, eth/keys,
  eth/p2p/discoveryv5/[enr, node, types, routing_table, encoding],
  eth/p2p/discoveryv5/protocol as discv5_protocol,
  ./discv5_test_helper

procSuite "Discovery v5 Tests":
  asyncTest "GetNode":
    # TODO: This could be tested in just a routing table only context
    let
      node = initDiscoveryNode(PrivateKey.random()[], localAddress(20302))
      targetNode = generateNode()

    check node.addNode(targetNode)

    for i in 0..<1000:
      discard node.addNode(generateNode())

    let n = node.getNode(targetNode.id)
    check n.isSome()
    check n.get() == targetNode

    await node.closeWait()

  asyncTest "Node deletion":
    let
      bootnode = initDiscoveryNode(PrivateKey.random()[], localAddress(20301))
      node1 = initDiscoveryNode(PrivateKey.random()[], localAddress(20302),
        @[bootnode.localNode.record])
      node2 = initDiscoveryNode(PrivateKey.random()[], localAddress(20303),
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


  asyncTest "Handshake cleanup":
    let node = initDiscoveryNode(PrivateKey.random()[], localAddress(20302))
    var tag: PacketTag
    let a = localAddress(20303)

    for i in 0 ..< 5:
      check randomBytes(tag) == tag.len
      node.receive(a, randomPacket(tag))

    # Checking different nodeIds but same address
    check node.codec.handshakes.len == 5
    # TODO: Could get rid of the sleep by storing the timeout future of the
    # handshake
    await sleepAsync(handshakeTimeout)
    # Checking handshake cleanup
    check node.codec.handshakes.len == 0

    await node.closeWait()

  asyncTest "Handshake different address":
    let node = initDiscoveryNode(PrivateKey.random()[], localAddress(20302))
    var tag: PacketTag

    for i in 0 ..< 5:
      let a = localAddress(20303 + i)
      node.receive(a, randomPacket(tag))

    check node.codec.handshakes.len == 5

    await node.closeWait()

  asyncTest "Handshake duplicates":
    let node = initDiscoveryNode(PrivateKey.random()[], localAddress(20302))
    var tag: PacketTag
    let a = localAddress(20303)

    for i in 0 ..< 5:
      node.receive(a, randomPacket(tag))

    # Checking handshake duplicates
    check node.codec.handshakes.len == 1

    # TODO: add check that gets the Whoareyou value and checks if its authTag
    # is that of the first packet.

    await node.closeWait()

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
    const dist = 253
    let
      mainNodeKey = PrivateKey.fromHex(
        "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
      testNodeKey = PrivateKey.fromHex(
        "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618")[]
      mainNode = initDiscoveryNode(mainNodeKey, localAddress(20301))
      testNode = initDiscoveryNode(testNodeKey, localAddress(20302))
      # logarithmic distance between mainNode and testNode is 256

    let nodes = nodesAtDistance(mainNode.localNode, dist, 10)
    for n in nodes:
      discard mainNode.addSeenNode(n) # for testing only!

    # ping in one direction to add, ping in the other to update seen.
    check (await testNode.ping(mainNode.localNode)).isOk()
    check (await mainNode.ping(testNode.localNode)).isOk()

    # Get ENR of the node itself
    var discovered =
      await discv5_protocol.findNode(testNode, mainNode.localNode, 0)
    check:
      discovered.isOk
      discovered[].len == 1
      discovered[][0] == mainNode.localNode
    # Get ENRs of nodes added at provided logarithmic distance
    discovered =
      await discv5_protocol.findNode(testNode, mainNode.localNode, dist)
    check discovered.isOk
    check discovered[].len == 10
    for n in nodes:
      check discovered[].contains(n)

    # Too high logarithmic distance, caps at 256
    discovered =
      await discv5_protocol.findNode(testNode, mainNode.localNode, 4294967295'u32)
    check:
      discovered.isOk
      discovered[].len == 1
      discovered[][0] == testNode.localNode

    # Empty bucket
    discovered =
      await discv5_protocol.findNode(testNode, mainNode.localNode, 254)
    check discovered.isOk
    check discovered[].len == 0

    let moreNodes = nodesAtDistance(mainNode.localNode, dist, 10)
    for n in moreNodes:
      discard mainNode.addSeenNode(n) # for testing only!

    # Full bucket
    discovered =
      await discv5_protocol.findNode(testNode, mainNode.localNode, dist)
    check discovered.isOk
    check discovered[].len == 16

    await mainNode.closeWait()
    await testNode.closeWait()

  asyncTest "FindNode with test table":

    let mainNode = initDiscoveryNode(PrivateKey.random()[], localAddress(20301))

    # Generate 1000 random nodes and add to our main node's routing table
    for i in 0..<1000:
      discard mainNode.addSeenNode(generateNode()) # for testing only!

    let
      neighbours = mainNode.neighbours(mainNode.localNode.id)
      closest = neighbours[0]
      closestDistance = logDist(closest.id, mainNode.localNode.id)

    debug "Closest neighbour", closestDistance, id=closest.id.toHex()

    let
      testNode = initDiscoveryNode(PrivateKey.random()[], localAddress(20302),
        @[mainNode.localNode.record])
      discovered = await discv5_protocol.findNode(testNode, mainNode.localNode,
        closestDistance)

    check discovered.isOk
    check closest in discovered[]

    await mainNode.closeWait()
    await testNode.closeWait()

  asyncTest "Lookup targets":
    const
      nodeCount = 17

    let bootNode = initDiscoveryNode(PrivateKey.random()[], localAddress(20301))
    bootNode.start()

    var nodes = newSeqOfCap[discv5_protocol.Protocol](nodeCount)
    nodes.add(bootNode)
    for i in 1 ..< nodeCount:
      nodes.add(initDiscoveryNode(PrivateKey.random()[], localAddress(20301 + i),
        @[bootNode.localNode.record]))

    # Make sure all nodes have "seen" each other by forcing pings
    for n in nodes:
      for t in nodes:
        if n != t:
          check (await n.ping(t.localNode)).isOk()

    for i in 1 ..< nodeCount:
      nodes[i].start()

    for i in 0..<nodeCount-1:
      let target = nodes[i]
      let discovered = await nodes[nodeCount-1].lookup(target.localNode.id)
      debug "Lookup result", target = target.localNode, discovered
      # if lookUp would return ordered on distance we could check discovered[0]
      check discovered.contains(target.localNode)

    for node in nodes:
      await node.closeWait()

  asyncTest "Resolve target":
    let
      mainNode = initDiscoveryNode(PrivateKey.random()[], localAddress(20301))
      lookupNode = initDiscoveryNode(PrivateKey.random()[], localAddress(20302))
      targetKey = PrivateKey.random()[]
      targetAddress = localAddress(20303)
      targetNode = initDiscoveryNode(targetKey, targetAddress)
      targetId = targetNode.localNode.id

    var targetSeqNum = targetNode.localNode.record.seqNum

    # Populate DHT with target through a ping. Next, close target and see
    # if resolve works (only local lookup)
    block:
      let pong = await targetNode.ping(mainNode.localNode)
      check pong.isOk()
      await targetNode.closeWait()
      let n = await mainNode.resolve(targetId)
      check:
        n.isSome()
        n.get().id == targetId
        n.get().record.seqNum == targetSeqNum

    # Bring target back online, update seqNum in ENR, check if we get the
    # updated ENR.
    block:
      targetNode.open()
      # ping to node again to add as it was removed after failed findNode in
      # resolve in previous test block
      let pong = await targetNode.ping(mainNode.localNode)
      check pong.isOk()
      # TODO: need to add some logic to update ENRs properly
      targetSeqNum.inc()
      let r = enr.Record.init(targetSeqNum, targetKey,
        some(targetAddress.ip), targetAddress.port, targetAddress.port)[]
      targetNode.localNode.record = r
      let n = await mainNode.resolve(targetId)
      check:
        n.isSome()
        n.get().id == targetId
        n.get().record.seqNum == targetSeqNum

    # Update seqNum in ENR again, ping lookupNode to be added in DHT,
    # close targetNode, resolve should lookup, check if we get updated ENR.
    block:
      targetSeqNum.inc()
      let r = enr.Record.init(targetSeqNum, targetKey, some(targetAddress.ip),
        targetAddress.port, targetAddress.port)[]
      targetNode.localNode.record = r

      # ping node so that its ENR gets added
      check (await targetNode.ping(lookupNode.localNode)).isOk()
      # ping node so that it becomes "seen" and thus will be forwarded on a
      # findNode request
      check (await lookupNode.ping(targetNode.localNode)).isOk()
      await targetNode.closeWait()
      # TODO: This step should eventually not be needed and ENRs with new seqNum
      # should just get updated in the lookup.
      await mainNode.revalidateNode(targetNode.localNode)

      check mainNode.addNode(lookupNode.localNode)
      let n = await mainNode.resolve(targetId)
      check:
        n.isSome()
        n.get().id == targetId
        n.get().record.seqNum == targetSeqNum

    await mainNode.closeWait()
    await lookupNode.closeWait()

  asyncTest "Random nodes with enr field filter":
    let
      lookupNode = initDiscoveryNode(PrivateKey.random()[], localAddress(20301))
      targetFieldPair = toFieldPair("test", @[byte 1,2,3,4])
      targetNode = generateNode(localEnrFields = [targetFieldPair])
      otherFieldPair = toFieldPair("test", @[byte 1,2,3,4,5])
      otherNode = generateNode(localEnrFields = [otherFieldPair])
      anotherNode = generateNode()

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
