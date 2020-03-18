import
  random, unittest, chronos, sequtils, chronicles, tables, stint,
  eth/[keys, rlp], eth/p2p/enode, eth/trie/db,
  eth/p2p/discoveryv5/[discovery_db, enr, node, types, routing_table, encoding],
  eth/p2p/discoveryv5/protocol as discv5_protocol,
  ./p2p_test_helper

proc initDiscoveryNode*(privKey: PrivateKey, address: Address,
                        bootstrapRecords: seq[Record]):
                        discv5_protocol.Protocol =
  var db = DiscoveryDB.init(newMemoryDB())
  result = newProtocol(privKey, db,
                       parseIpAddress("127.0.0.1"),
                       address.tcpPort, address.udpPort,
                       bootstrapRecords)

  result.open()

proc nodeIdInNodes(id: NodeId, nodes: openarray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

# Creating a random packet with specific nodeid each time
proc randomPacket(tag: PacketTag): seq[byte] =
  var
    authTag: AuthTag
    msg: array[44, byte]

  randomBytes(authTag)
  randomBytes(msg)
  result.add(tag)
  result.add(rlp.encode(authTag))
  result.add(msg)

suite "Discovery v5 Tests":
  asyncTest "Random nodes":
    let
      bootNodeKey = initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")
      bootNode = initDiscoveryNode(bootNodeKey, localAddress(20301), @[])

    let nodeKeys = [
        initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618"),
        initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a619"),
        initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a620")
      ]
    var nodeAddrs = newSeqOfCap[Address](nodeKeys.len)
    for i in 0 ..< nodeKeys.len: nodeAddrs.add(localAddress(20302 + i))

    var nodes = zip(nodeKeys, nodeAddrs).mapIt(
      initDiscoveryNode(it[0], it[1], @[bootNode.localNode.record]))
    nodes.add(bootNode)

    for node in nodes:
      let discovered = await node.lookupRandom()
      check discovered.len < nodes.len
      debug "Lookup from random id", node = node.localNode, discovered

    # Check for each node if the other nodes shows up in the routing table
    for i in nodes:
      for j in nodes:
        if j != i:
          check(nodeIdInNodes(i.localNode.id, j.randomNodes(nodes.len - 1)))

    for node in nodes:
      await node.closeWait()

  asyncTest "Lookup targets":
    const
      nodeCount = 17

    let bootNode = initDiscoveryNode(newPrivateKey(), localAddress(20301), @[])
    bootNode.start()

    var nodes = newSeqOfCap[discv5_protocol.Protocol](nodeCount)
    nodes.add(bootNode)
    for i in 1 ..< nodeCount:
      nodes.add(initDiscoveryNode(newPrivateKey(), localAddress(20301 + i),
        @[bootNode.localNode.record]))
      nodes[i].start()

    for i in 0..<nodeCount-1:
      let target = nodes[i]
      let discovered = await nodes[nodeCount-1].lookup(target.localNode.id)
      debug "Lookup result", target = target.localNode, discovered
      # if lookUp would return ordered on distance we could check discovered[0]
      check discovered.contains(target.localNode)

    for node in nodes:
      await node.closeWait()

  asyncTest "Handshake cleanup":
    let node = initDiscoveryNode(newPrivateKey(), localAddress(20302), @[])
    var tag: PacketTag
    let a = localAddress(20303)

    for i in 0 ..< 5:
      randomBytes(tag)
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
    let node = initDiscoveryNode(newPrivateKey(), localAddress(20302), @[])
    var tag: PacketTag

    for i in 0 ..< 5:
      let a = localAddress(20303 + i)
      node.receive(a, randomPacket(tag))

    check node.codec.handshakes.len == 5

    await node.closeWait()

  asyncTest "Handshake duplicates":
    let node = initDiscoveryNode(newPrivateKey(), localAddress(20302), @[])
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
        ("0x0008", 4'u32),
        ("0x00ff", 8'u32),
        ("0x0100", 9'u32),
        ("0xf000", 16'u32)
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

    let targetId = toNodeId(initPublicKey(targetKey))

    for (key, d) in testValues:
      let id = toNodeId(initPrivateKey(key).getPublicKey())
      check logDist(targetId, id) == d
