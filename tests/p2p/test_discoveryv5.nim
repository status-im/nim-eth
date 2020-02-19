import
  unittest, chronos, sequtils, chronicles,
  eth/keys, eth/p2p/enode, eth/trie/db,
  eth/p2p/discoveryv5/[discovery_db, enr, node, types],
  eth/p2p/discoveryv5/protocol as discv5_protocol,
  ./p2p_test_helper

proc startDiscoveryv5Node*(privKey: PrivateKey, address: Address,
                           bootnodes: seq[Record]): discv5_protocol.Protocol =
  var db = DiscoveryDB.init(newMemoryDB())
  result = newProtocol(privKey, db, address.tcpPort, address.udpPort)

  for node in bootnodes:
    result.addNode(node)

  result.open()
  result.start()

proc nodeIdInNodes(id: NodeId, nodes: openarray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

suite "Discovery v5 Tests":
  asyncTest "Discover nodes":
    let
      bootNodeKey = initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")
      bootNodeAddr = localAddress(20301)
      bootNode = startDiscoveryv5Node(bootNodeKey, bootNodeAddr, @[])
      bootNodeRecord = initRecord(1, bootNodeKey,
        {"udp": bootNodeAddr.udpPort.uint16, "ip": [byte 127, 0, 0, 1]})

    let nodeKeys = [
        initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618"),
        initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a619"),
        initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a620")
      ]
    var nodeAddrs = newSeqOfCap[Address](nodeKeys.len)
    for i in 0 ..< nodeKeys.len: nodeAddrs.add(localAddress(20302 + i))

    var nodes = zip(nodeKeys, nodeAddrs).mapIt(
      startDiscoveryv5Node(it.a, it.b, @[bootNodeRecord]))
    nodes.add(bootNode)

    for node in nodes:
      let discovered = await node.lookupRandom()
      check discovered.len < nodes.len
      debug "Lookup from random id", node=node.localNode, discovered

    # Check for each node if the other nodes shows up in the routing table
    for i in nodes:
      for j in nodes:
        if j != i:
          check(nodeIdInNodes(i.localNode.id, j.randomNodes(nodes.len - 1)))
