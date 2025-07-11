# nim-eth
# Copyright (c) 2020-2025 Status Research & Development GmbH
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
    messages, nodes_verification],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol,
  ../stubloglevel,
  ./discv5_test_helper

suite "Discovery v5.1 Tests":
  setup:
    let rng {.used.} = newRng()

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
        ("0x0000", 0'u16),
        ("0x0001", 1'u16),
        ("0x0002", 2'u16),
        ("0x0003", 2'u16),
        ("0x0004", 3'u16),
        ("0x0007", 3'u16),
        ("0x0008", 4'u16),
        ("0x000f", 4'u16),
        ("0x0080", 8'u16),
        ("0x00ff", 8'u16),
        ("0x0100", 9'u16),
        ("0x01ff", 9'u16),
        ("0x8000", 16'u16),
        ("0xffff", 16'u16)
      ]

    for (id, d) in testValues:
      check logDistance(parse(targetId, UInt256, 16), parse(id, UInt256, 16)) == d

  test "Distance check with keys":
    # Values for this test are taken from
    # https://github.com/ethereum/go-ethereum/blob/d8ff53dfb8a516f47db37dbc7fd7ad18a1e8a125/p2p/discover/v4_lookup_test.go#L176
    const
      targetKey = "5d485bdcbe9bc89314a10ae9231e429d33853e3a8fa2af39f5f827370a2e4185e344ace5d16237491dad41f278f1d3785210d29ace76cd627b9147ee340b1125"
      testValues = [
        ("29738ba0c1a4397d6a65f292eee07f02df8e58d41594ba2be3cf84ce0fc58169", 251'u16),
        ("511b1686e4e58a917f7f848e9bf5539d206a68f5ad6b54b552c2399fe7d174ae", 251'u16),
        ("d09e5eaeec0fd596236faed210e55ef45112409a5aa7f3276d26646080dcfaeb", 251'u16),
        ("c1e20dbbf0d530e50573bd0a260b32ec15eb9190032b4633d44834afc8afe578", 251'u16),
        ("ed5f38f5702d92d306143e5d9154fb21819777da39af325ea359f453d179e80b", 251'u16),

        ("1c9b1cafbec00848d2c174b858219914b42a7d5c9359b1ca03fd650e8239ae94", 252'u16),
        ("e0e1e8db4a6f13c1ffdd3e96b72fa7012293ced187c9dcdcb9ba2af37a46fa10", 252'u16),
        ("3d53823e0a0295cb09f3e11d16c1b44d07dd37cec6f739b8df3a590189fe9fb9", 252'u16),

        ("2d0511ae9bf590166597eeab86b6f27b1ab761761eaea8965487b162f8703847", 253'u16),
        ("6cfbd7b8503073fc3dbdb746a7c672571648d3bd15197ccf7f7fef3d904f53a2", 253'u16),
        ("a30599b12827b69120633f15b98a7f6bc9fc2e9a0fd6ae2ebb767c0e64d743ab", 253'u16),
        ("14a98db9b46a831d67eff29f3b85b1b485bb12ae9796aea98d91be3dc78d8a91", 253'u16),
        ("2369ff1fc1ff8ca7d20b17e2673adc3365c3674377f21c5d9dafaff21fe12e24", 253'u16),
        ("9ae91101d6b5048607f41ec0f690ef5d09507928aded2410aabd9237aa2727d7", 253'u16),
        ("05e3c59090a3fd1ae697c09c574a36fcf9bedd0afa8fe3946f21117319ca4973", 253'u16),
        ("06f31c5ea632658f718a91a1b1b9ae4b7549d7b3bc61cbc2be5f4a439039f3ad", 253'u16),

        ("dec742079ec00ff4ec1284d7905bc3de2366f67a0769431fd16f80fd68c58a7c", 254'u16),
        ("ff02c8861fa12fbd129d2a95ea663492ef9c1e51de19dcfbbfe1c59894a28d2b", 254'u16),
        ("4dded9e4eefcbce4262be4fd9e8a773670ab0b5f448f286ec97dfc8cf681444a", 254'u16),
        ("750d931e2a8baa2c9268cb46b7cd851f4198018bed22f4dceb09dd334a2395f6", 254'u16),
        ("ce1435a956a98ffec484cd11489c4f165cf1606819ab6b521cee440f0c677e9e", 254'u16),
        ("996e7f8d1638be92d7328b4770f47e5420fc4bafecb4324fd33b1f5d9f403a75", 254'u16),
        ("46bd1eddcf6431bea66fc19ebc45df191c1c7d6ed552dcdc7392885009c322f0", 254'u16),

        ("da8645f90826e57228d9ea72aff84500060ad111a5d62e4af831ed8e4b5acfb8", 255'u16),
        ("3c944c5d9af51d4c1d43f5d0f3a1a7ef65d5e82744d669b58b5fed242941a566", 255'u16),
        ("5ebcde76f1d579eebf6e43b0ffe9157e65ffaa391175d5b9aa988f47df3e33da", 255'u16),
        ("97f78253a7d1d796e4eaabce721febcc4550dd68fb11cc818378ba807a2cb7de", 255'u16),
        ("a38cd7dc9b4079d1c0406afd0fdb1165c285f2c44f946eca96fc67772c988c7d", 255'u16),
        ("d64cbb3ffdf712c372b7a22a176308ef8f91861398d5dbaf326fd89c6eaeef1c", 255'u16),
        ("d269609743ef29d6446e3355ec647e38d919c82a4eb5837e442efd7f4218944f", 255'u16),
        ("d8f7bcc4a530efde1d143717007179e0d9ace405ddaaf151c4d863753b7fd64c", 255'u16),

        ("8c5b422155d33ea8e9d46f71d1ad3e7b24cb40051413ffa1a81cff613d243ba9", 256'u16),
        ("937b1af801def4e8f5a3a8bd225a8bcff1db764e41d3e177f2e9376e8dd87233", 256'u16),
        ("120260dce739b6f71f171da6f65bc361b5fad51db74cf02d3e973347819a6518", 256'u16),
        ("1fa56cf25d4b46c2bf94e82355aa631717b63190785ac6bae545a88aadc304a9", 256'u16),
        ("3c38c503c0376f9b4adcbe935d5f4b890391741c764f61b03cd4d0d42deae002", 256'u16),
        ("3a54af3e9fa162bc8623cdf3e5d9b70bf30ade1d54cc3abea8659aba6cff471f", 256'u16),
        ("6799a02ea1999aefdcbcc4d3ff9544478be7365a328d0d0f37c26bd95ade0cda", 256'u16),
        ("e24a7bc9051058f918646b0f6e3d16884b2a55a15553b89bab910d55ebc36116", 256'u16)
      ]

    let targetId = toNodeId(PublicKey.fromHex(targetKey)[])

    for (key, d) in testValues:
      let id = toNodeId(PrivateKey.fromHex(key)[].toPublicKey())
      check logDistance(targetId, id) == d

  test "Distance to id check":
    const
      targetId = "0x0000"
      testValues = [ # possible id in that distance range
        ("0x0001", 1'u16),
        ("0x0002", 2'u16),
        ("0x0004", 3'u16),
        ("0x0008", 4'u16),
        ("0x0080", 8'u16),
        ("0x0100", 9'u16),
        ("0x8000", 16'u16)
      ]

    for (id, d) in testValues:
      check idAtDistance(parse(targetId, UInt256, 16), d) == parse(id, UInt256, 16)

  test "Distance to id check with keys":
    const
      targetKey = "5d485bdcbe9bc89314a10ae9231e429d33853e3a8fa2af39f5f827370a2e4185e344ace5d16237491dad41f278f1d3785210d29ace76cd627b9147ee340b1125"
      testValues = [ # possible id in that distance range
        ("9e5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 251'u16),
        ("925b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 252'u16),
        ("8a5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 253'u16),
        ("ba5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 254'u16),
        ("da5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 255'u16),
        ("1a5b34809116e3790b2258a45e7ef03b11af786503fb1a6d4b4a8ca021ad653c", 256'u16)
      ]

    let targetId = toNodeId(PublicKey.fromHex(targetKey)[])

    for (id, d) in testValues:
      check idAtDistance(targetId, d) == parse(id, UInt256, 16)

  asyncTest "FindNode Test":
    const dist = 253'u16
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
      initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301))

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
      let nodes = await mainNode.findNode(targetNode.localNode, @[0'u16])
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
    let discoveredEmpty = lookupNode.randomNodes(10,
      proc(n: Node) : bool = false)
    check discoveredEmpty.len == 0

    await lookupNode.closeWait()

  test "New protocol with enr":
    let
      privKey = PrivateKey.random(rng[])
      ip = Opt.some(parseIpAddress("127.0.0.1"))
      port = Port(20301)
      node = newProtocol(privKey, ip, Opt.some(port), Opt.some(port), bindPort = port,
        rng = rng)
      noUpdatesNode = newProtocol(privKey, ip, Opt.some(port), Opt.some(port),
        bindPort = port, rng = rng, previousRecord = Opt.some(node.getRecord()))
      updatesNode = newProtocol(privKey, ip, Opt.some(port), Opt.some(Port(20302)),
        bindPort = port, rng = rng,
        previousRecord = Opt.some(noUpdatesNode.getRecord()))
      moreUpdatesNode = newProtocol(privKey, ip, Opt.some(port), Opt.some(port),
        bindPort = port, rng = rng, localEnrFields = {"addfield": @[byte 0]},
        previousRecord = Opt.some(updatesNode.getRecord()))
    check:
      node.getRecord().seqNum == 1
      noUpdatesNode.getRecord().seqNum == 2
      updatesNode.getRecord().seqNum == 3
      moreUpdatesNode.getRecord().seqNum == 4

    # Defect (for now?) on incorrect key use
    expect ResultDefect:
      discard newProtocol(PrivateKey.random(rng[]),
        ip, Opt.some(port), Opt.some(port), bindPort = port, rng = rng,
        previousRecord = Opt.some(updatesNode.getRecord()))

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

  test "Verify records of Nodes message - global src":
    let
      port = Port(9000)
      srcRecord = enr.Record.init(1, PrivateKey.random(rng[]),
        Opt.some(parseIpAddress("11.12.13.14")),
        Opt.some(port), Opt.some(port))[]
      srcNode = Node.fromRecord(srcRecord)
      pk = PrivateKey.random(rng[])
      targetDistance = @[logDistance(srcNode.id, pk.toPublicKey().toNodeId())]
      limit = 16

    block: # Duplicates
      let
        record = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("12.13.14.15")),
          Opt.some(port), Opt.some(port))[]

      # Exact duplicates
      var records = @[record, record]
      var nodes = verifyNodesRecords(records, srcNode, limit, targetDistance)
      check nodes.len == 1

      # Node id duplicates
      let recordSameId = enr.Record.init(
        1, pk, Opt.some(parseIpAddress("212.13.14.15")),
        Opt.some(port), Opt.some(port))[]
      records.add(recordSameId)
      nodes = verifyNodesRecords(records, srcNode, limit, targetDistance)
      check nodes.len == 1

    block: # No address
      let
        recordNoAddress = enr.Record.init(
          1, pk, Opt.none(IpAddress), Opt.some(port), Opt.some(port))[]
        records = [recordNoAddress]
        test = verifyNodesRecords(records, srcNode, limit, targetDistance)
      check test.len == 0

    block: # Invalid address - any local
      let
        recordInvalidAddress = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("0.0.0.0")),
          Opt.some(port), Opt.some(port))[]
        records = [recordInvalidAddress]
        test = verifyNodesRecords(records, srcNode, limit, targetDistance)
      check test.len == 0

    block: # Invalid address - site local
      let
        recordInvalidAddress = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("10.1.2.3")),
          Opt.some(port), Opt.some(port))[]
        records = [recordInvalidAddress]
        test = verifyNodesRecords(records, srcNode, limit, targetDistance)
      check test.len == 0

    block: # Invalid address - loopback
      let
        recordInvalidAddress = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("127.0.0.1")),
          Opt.some(port), Opt.some(port))[]
        records = [recordInvalidAddress]
        test = verifyNodesRecords(records, srcNode, limit, targetDistance)
      check test.len == 0

    block: # Invalid distance
      let
        recordInvalidDistance = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("12.13.14.15")),
          Opt.some(port), Opt.some(port))[]
        records = [recordInvalidDistance]
        test = verifyNodesRecords(records, srcNode, limit, @[0'u16])
      check test.len == 0

    block: # Invalid distance but distance validation is disabled
      let
        recordInvalidDistance = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("12.13.14.15")),
          Opt.some(port), Opt.some(port))[]
        records = [recordInvalidDistance]
        test = verifyNodesRecords(records, srcNode, limit)
      check test.len == 1

  test "Verify records of Nodes message - loopback src":
    let
      port = Port(9000)
      srcRecord = enr.Record.init(1, PrivateKey.random(rng[]),
        Opt.some(parseIpAddress("127.0.0.0")),
        Opt.some(port), Opt.some(port))[]
      srcNode = Node.fromRecord(srcRecord)
      pk = PrivateKey.random(rng[])
      targetDistance = @[logDistance(srcNode.id, pk.toPublicKey().toNodeId())]
      limit = 16

    block: # valid address - lo with lo src
      let
        record = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("127.0.0.1")),
          Opt.some(port), Opt.some(port))[]
        test = verifyNodesRecords([record], srcNode, limit, targetDistance)
      check test.len == 1

    block: # valid address - global with lo src
      let
        record = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("1.2.3.4")),
          Opt.some(port), Opt.some(port))[]
        test = verifyNodesRecords([record], srcNode, limit, targetDistance)
      check test.len == 1

  test "Verify records of Nodes message - site local src":
    let
      port = Port(9000)
      srcRecord = enr.Record.init(1, PrivateKey.random(rng[]),
        Opt.some(parseIpAddress("192.168.1.1")),
        Opt.some(port), Opt.some(port))[]
      srcNode = Node.fromRecord(srcRecord)
      pk = PrivateKey.random(rng[])
      targetDistance = @[logDistance(srcNode.id, pk.toPublicKey().toNodeId())]
      limit = 16

    block: # valid address - site local with site local src
      let
        record = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("192.168.1.2")),
          Opt.some(port), Opt.some(port))[]
        test = verifyNodesRecords([record], srcNode, limit, targetDistance)
      check test.len == 1

    block: # valid address - global with site local src
      let
        record = enr.Record.init(
          1, pk, Opt.some(parseIpAddress("1.2.3.4")),
          Opt.some(port), Opt.some(port))[]
        test = verifyNodesRecords([record], srcNode, limit, targetDistance)
      check test.len == 1

  test "Calculate lookup distances":
    let rng = newRng()
    let node = generateNode(PrivateKey.random(rng[]))

    # Log distance between zeros is zero
    let dist = lookupDistances(u256(0), u256(0))
    check dist == @[0'u16, 1, 2]

    # Log distance between zero and one is one
    let dist1 = lookupDistances(u256(0), u256(1))
    check dist1 == @[1'u16, 2, 3]

    # Ensure that distances are in expected order
    let dist2 = lookupDistances(node.id, idAtDistance(node.id, 128))
    check dist2 == @[128'u16, 129, 127]

    # Test target distance of 256
    let dist3 = lookupDistances(node.id, idAtDistance(node.id, 256))
    check dist3 == @[256'u16, 255, 254]

    # Test target distance of 255
    let dist4 = lookupDistances(node.id, idAtDistance(node.id, 255))
    check dist4 == @[255'u16, 256, 254]

    # Test target distance of 254
    let dist5 = lookupDistances(node.id, idAtDistance(node.id, 254))
    check dist5 == @[254'u16, 255, 253]

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
      rng, PrivateKey.random(rng[]), localAddress(20302))

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
      rng, PrivateKey.random(rng[]), localAddress(20302))

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
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))
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
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))
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
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))
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
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))
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
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))
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

  asyncTest "Banned nodes are removed and cannot be added":
    let
      node = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302), banNodes = true)
      targetNode = generateNode(PrivateKey.random(rng[]))

    # add the node
    check:
      node.addNode(targetNode) == true
      node.getNode(targetNode.id).isSome()

    # banning the node should remove it from the routing table
    node.banNode(targetNode, 1.minutes)
    check node.getNode(targetNode.id).isNone()

    # cannot add a banned node
    check:
      node.addNode(targetNode) == false
      node.getNode(targetNode.id).isNone()

    await node.closeWait()

  asyncTest "FindNode filters out banned nodes":
    let
      mainNode = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301),
          banNodes = true)
      testNode = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302),
          @[mainNode.localNode.record], banNodes = true)

    # Generate 100 random nodes and add to our main node's routing table
    for i in 0 ..< 100:
      discard mainNode.addSeenNode(generateNode(PrivateKey.random(rng[])))

    let
      neighbours = mainNode.neighbours(mainNode.localNode.id)
      closest = neighbours[0]
      closestDistance = logDistance(closest.id, mainNode.localNode.id)

    block:
      # the closest node is returned
      let discovered = await testNode.findNode(mainNode.localNode, @[closestDistance])
      check discovered.isOk
      check closest in discovered[]

    # ban the closest node
    mainNode.banNode(closest, 1.minutes)

    block:
      # the banned node is not returned
      let discovered = await testNode.findNode(mainNode.localNode, @[closestDistance])
      check discovered.isOk
      check closest notin discovered[]

    await mainNode.closeWait()
    await testNode.closeWait()

  asyncTest "Cannot send messages to banned nodes":
    let
      node1 = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302),
          banNodes = true)
      node2 = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301),
          banNodes = true)

    # ban node2 in node1's routing table
    node1.banNode(node2.localNode, 1.minutes)

    block:
      let pong = await node1.ping(node2.localNode)
      check:
        pong.isErr()
        pong.error() == "toNode is banned"

    block:
      let nodes = await node1.findNode(node2.localNode, @[0.uint16])
      check:
        nodes.isErr()
        nodes.error() == "toNode is banned"

    block:
      let node = await node1.resolve(node2.localNode.id)
      check node.isNone()

    await node2.closeWait()
    await node1.closeWait()

  asyncTest "Ignore messages from banned nodes":
    let
      node1 = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302),
          banNodes = true)
      node2 = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20301),
          banNodes = true)

    # ban node1 in node2's routing table
    node2.banNode(node1.localNode, 1.minutes)

    block:
      let pong = await node1.ping(node2.localNode)
      check:
        pong.isErr()
        pong.error() == "Pong message not received in time"

    block:
      let nodes = await node1.findNode(node2.localNode, @[0.uint16])
      check:
        nodes.isErr()
        nodes.error() == "Nodes message not received in time"

    block:
      let node = await node1.resolve(node2.localNode.id)
      check node.isNone()

    await node2.closeWait()
    await node1.closeWait()
