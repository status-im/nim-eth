import
  random, unittest, chronos, sequtils, chronicles, tables,
  eth/[keys, rlp], eth/p2p/enode, eth/trie/db,
  eth/p2p/discoveryv5/[discovery_db, enr, node, types, routing_table, encoding],
  eth/p2p/discoveryv5/protocol as discv5_protocol,
  ./p2p_test_helper

proc initDiscoveryNode*(privKey: PrivateKey, address: Address,
                           bootnodes: seq[Record]): discv5_protocol.Protocol =
  var db = DiscoveryDB.init(newMemoryDB())
  result = newProtocol(privKey, db,
                       parseIpAddress("127.0.0.1"),
                       address.tcpPort, address.udpPort)

  for node in bootnodes:
    result.addNode(node)

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

    var nodes = newSeqOfCap[discv5_protocol.Protocol](nodeCount)
    nodes.add(bootNode)
    for i in 1 ..< nodeCount:
      nodes.add(initDiscoveryNode(newPrivateKey(), localAddress(20301 + i),
        @[bootNode.localNode.record]))

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
