# nim-eth
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[tables, sequtils, net],
  chronos, chronicles, stint, testutils/unittests,
  stew/byteutils,
  ../../eth/common/keys,
  ../../eth/p2p/discoveryv5/[enr, node, routing_table, encoding, sessions,
    messages],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol,
  ../stubloglevel,
  ./discv5_test_helper

suite "Discovery v5 Ban Nodes Enabled Tests":
  setup:
    let rng {.used.} = newRng()

  asyncTest "GetNode":
    # TODO: This could be tested in just a routing table only context
    let
      node = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
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
        rng, PrivateKey.random(rng[]), localAddress(20301), banNodes = true)
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302),
        @[bootnode.localNode.record], banNodes = true)
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303),
        @[bootnode.localNode.record], banNodes = true)
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

  asyncTest "FindNode Test":
    const dist = 253'u16
    let
      mainNodeKey = PrivateKey.fromHex(
        "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
      testNodeKey = PrivateKey.fromHex(
        "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618")[]
      mainNode = initDiscoveryNode(rng, mainNodeKey, localAddress(20301), banNodes = true)
      testNode = initDiscoveryNode(rng, testNodeKey, localAddress(20302), banNodes = true)
      # logarithmic distance between mainNode and testNode is 256

    let nodes = nodesAtDistance(mainNode.localNode, rng[], dist, 10)
    for n in nodes:
      discard mainNode.addSeenNode(n) # for testing only!

    # ping in one direction to add, ping in the other to update seen.
    check (await testNode.ping(mainNode.localNode)).isOk()
    check (await mainNode.ping(testNode.localNode)).isOk()

    # Get ENR of the node itself
    var discovered =
      await findNode(testNode, mainNode.localNode, @[0'u16])
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
      await findNode(testNode, mainNode.localNode, @[high(uint16)])
    check:
      discovered.isOk
      discovered[].len == 0

    # Logarithmic distance of 256 should only return the testNode
    discovered =
      await findNode(testNode, mainNode.localNode, @[256'u16])
    check:
      discovered.isOk
      discovered[].len == 1
      discovered[][0] == testNode.localNode

    # Empty bucket
    discovered =
      await findNode(testNode, mainNode.localNode, @[254'u16])
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
      initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301), banNodes = true)

    # Generate 1000 random nodes and add to our main node's routing table
    for i in 0..<1000:
      discard mainNode.addSeenNode(generateNode(PrivateKey.random(rng[]))) # for testing only!

    let
      neighbours = mainNode.neighbours(mainNode.localNode.id)
      closest = neighbours[0]
      closestDistance = logDistance(closest.id, mainNode.localNode.id)

    debug "Closest neighbour", closestDistance, id=closest.id.toHex()

    let
      testNode = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302),
        @[mainNode.localNode.record], banNodes = true)
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
      initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301), banNodes = true)
    bootNode.start()

    var nodes = newSeqOfCap[discv5_protocol.Protocol](nodeCount)
    nodes.add(bootNode)
    for i in 1 ..< nodeCount:
      nodes.add(initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301 + i),
        @[bootNode.localNode.record], banNodes = true))

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
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301), banNodes = true)
      lookupNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
      targetKey = PrivateKey.random(rng[])
      targetAddress = localAddress(20303)
      targetNode = initDiscoveryNode(rng, targetKey, targetAddress, banNodes = true)
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
    # Node will be banned because of failed findNode request.

    # Bring target back online, update seqNum in ENR, check if we get the
    # updated ENR.
    block:
      targetNode.open()
      # Request the target ENR and manually add it to the routing table.
      # Ping for handshake based ENR passing will not work as our previous
      # session will still be in the LRU cache.
      let nodes = await mainNode.findNode(targetNode.localNode, @[0'u16])
      check:
        nodes.isErr() # Node is banned

      targetSeqNum.inc()
      # need to add something to get the enr sequence number incremented
      let update = targetNode.updateRecord({"addsomefield": @[byte 1]})
      check update.isOk()

      var n = mainNode.getNode(targetId)
      check:
        n.isNone() # Node was removed when banned

      n = await mainNode.resolve(targetId)
      check:
        n.isNone() # Node is banned

    await mainNode.closeWait()
    await lookupNode.closeWait()
    await targetNode.closeWait()

  asyncTest "Random nodes with enr field filter":
    let
      lookupNode = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301), banNodes = true)
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
    let discoveredEmpty = lookupNode.randomNodes(10,
      proc(n: Node) : bool = false)
    check discoveredEmpty.len == 0

    await lookupNode.closeWait()

  asyncTest "Update node record with revalidate":
    let
      mainNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301), banNodes = true)
      testNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
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
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301), banNodes = true)
      testNode =
        initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
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

  asyncTest "Handshake cleanup: different ids":
    # Node to test the handshakes on.
    let receiveNode = initDiscoveryNode(
      rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)

    # Create random packets with same ip but different node ids
    # and "receive" them on receiveNode
    let a = localAddress(20303)
    for i in 0 ..< 5:
      let
        privKey = PrivateKey.random(rng[])
        enrRec = enr.Record.init(1, privKey,
          Opt.some(parseIpAddress("127.0.0.1")), Opt.some(Port(9000)),
          Opt.some(Port(9000))).expect("Properly initialized private key")
        sendNode = Node.fromRecord(enrRec)
      var codec = Codec(localNode: sendNode, privKey: privKey, sessions: Sessions.init(5))

      let (packet, _) = encodeMessagePacket(rng[], codec,
        receiveNode.localNode.id, receiveNode.localNode.address.get(), @[])
      receiveNode.receive(a, packet)

    # Checking different nodeIds but same address
    check receiveNode.codec.handshakes.len == 5
    # TODO: Could get rid of the sleep by storing the timeout future of the
    # handshake
    await sleepAsync(defaultHandshakeTimeout)
    # Checking handshake cleanup
    check receiveNode.codec.handshakes.len == 0

    await receiveNode.closeWait()

  asyncTest "Handshake cleanup: different ips":
    # Node to test the handshakes on.
    let receiveNode = initDiscoveryNode(
      rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)

    # Create random packets with same node ids but different ips
    # and "receive" them on receiveNode
    let
      privKey = PrivateKey.random(rng[])
      enrRec = enr.Record.init(1, privKey,
        Opt.some(parseIpAddress("127.0.0.1")), Opt.some(Port(9000)),
        Opt.some(Port(9000))).expect("Properly initialized private key")
      sendNode = Node.fromRecord(enrRec)
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
    await sleepAsync(defaultHandshakeTimeout)
    # Checking handshake cleanup
    check receiveNode.codec.handshakes.len == 0

    await receiveNode.closeWait()

  asyncTest "Handshake duplicates":
    # Node to test the handshakes on.
    let receiveNode = initDiscoveryNode(
      rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)

    # Create random packets with same node ids and same ips
    # and "receive" them on receiveNode
    let
      a = localAddress(20303)
      privKey = PrivateKey.random(rng[])
      enrRec = enr.Record.init(1, privKey,
        Opt.some(parseIpAddress("127.0.0.1")), Opt.some(Port(9000)),
        Opt.some(Port(9000))).expect("Properly initialized private key")
      sendNode = Node.fromRecord(enrRec)
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
    let key = HandshakeKey(nodeId: sendNode.id, address: a)
    check receiveNode.codec.handshakes[key].whoareyouData.requestNonce ==
      firstRequestNonce

    await receiveNode.closeWait()

  asyncTest "Talkreq no protocol":
    let
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303), banNodes = true)
      talkresp = await discv5_protocol.talkReq(node1, node2.localNode,
        @[byte 0x01], @[])

    check:
      talkresp.isOk()
      talkresp.get().len == 0

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Talkreq echo protocol":
    let
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303), banNodes = true)
      talkProtocol = "echo".toBytes()

    proc handler(
        protocol: TalkProtocol, request: seq[byte],
        fromId: NodeId, fromUdpAddress: Address,
        node: Opt[Node]):
        seq[byte] {.gcsafe, raises: [].} =
      request

    let echoProtocol = TalkProtocol(protocolHandler: handler)

    check node2.registerTalkProtocol(talkProtocol, echoProtocol).isOk()
    let talkresp = await discv5_protocol.talkReq(node1, node2.localNode,
      talkProtocol, "hello".toBytes())

    check:
      talkresp.isOk()
      talkresp.get() == "hello".toBytes()

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Talkreq register protocols":
    let
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303), banNodes = true)
      talkProtocol = "echo".toBytes()

    proc handler(
        protocol: TalkProtocol, request: seq[byte],
        fromId: NodeId, fromUdpAddress: Address,
        node: Opt[Node]):
        seq[byte] {.gcsafe, raises: [].} =
      request

    let echoProtocol = TalkProtocol(protocolHandler: handler)

    check:
      node2.registerTalkProtocol(talkProtocol, echoProtocol).isOk()
      node2.registerTalkProtocol(talkProtocol, echoProtocol).isErr()
      node2.registerTalkProtocol("test".toBytes(), echoProtocol).isOk()

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Max packet size: Request":
    let
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303), banNodes = true)
      talkProtocol = "echo".toBytes()

    proc handler(
        protocol: TalkProtocol, request: seq[byte],
        fromId: NodeId, fromUdpAddress: Address,
        node: Opt[Node]):
        seq[byte] {.gcsafe, raises: [].} =
      request

    let echoProtocol = TalkProtocol(protocolHandler: handler)

    check node2.registerTalkProtocol(talkProtocol, echoProtocol).isOk()
    # Do a ping first so a session is created, that makes the next message to
    # be an ordinary message and more easy to reverse calculate packet sizes for
    # than for a handshake message.
    check (await node1.ping(node2.localNode)).isOk()

    block: # 1172 = 1280 - 103 - 4 - 1 = max - talkreq - "echo" - rlp blob
      let talkresp = await discv5_protocol.talkReq(node1, node2.localNode,
        talkProtocol, repeat(byte 6, 1172))

      check:
        talkresp.isOk()

    block: # > 1280 -> should fail
      let talkresp = await discv5_protocol.talkReq(node1, node2.localNode,
        talkProtocol, repeat(byte 6, 1173))

      check:
        talkresp.isErr()

    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Max packet size: Response":
    let
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303), banNodes = true)
      talkProtocol = "echo".toBytes()

    proc handler(
        protocol: TalkProtocol, request: seq[byte],
        fromId: NodeId, fromUdpAddress: Address,
        node: Opt[Node]):
        seq[byte] {.gcsafe, raises: [].} =
      # Return the request + same protocol id + 2 bytes, to make it 1 byte
      # bigger than the request
      request & "echo12".toBytes()

    let echoProtocol = TalkProtocol(protocolHandler: handler)

    check node2.registerTalkProtocol(talkProtocol, echoProtocol).isOk()
    # Do a ping first so a session is created, that makes the next message to
    # be an ordinary message and more easy to reverse calculate packet sizes for
    # than for a handshake message.
    check (await node1.ping(node2.localNode)).isOk()

    block: # 1171 -> response will be 1 byte bigger thus this should pass
      let talkresp = await discv5_protocol.talkReq(node1, node2.localNode,
        talkProtocol, repeat(byte 6, 1171))

      check:
        talkresp.isOk()

    block: # 1172 -> response will be 1 byte bigger thus this should fail
      let talkresp = await discv5_protocol.talkReq(node1, node2.localNode,
        talkProtocol, repeat(byte 6, 1172))

      check:
        talkresp.isErr()

    await node1.closeWait()
    await node2.closeWait()
