import
  testutils/unittests, stew/shims/net, nimcrypto,
  eth/[keys, rlp, trie/db],
  eth/p2p/discoveryv5/[discovery_db, enr, node, types, routing_table, encoding],
  eth/p2p/discoveryv5/protocol as discv5_protocol


proc localAddress*(port: int): Address =
  Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(port))

proc initDiscoveryNode*(privKey: PrivateKey, address: Address,
                        bootstrapRecords: openarray[Record] = [],
                        localEnrFields: openarray[FieldPair] = []):
                        discv5_protocol.Protocol =
  var db = DiscoveryDB.init(newMemoryDB())
  result = newProtocol(privKey, db,
                       some(address.ip),
                       address.port, address.port,
                       bootstrapRecords = bootstrapRecords,
                       localEnrFields = localEnrFields)

  result.open()

proc nodeIdInNodes*(id: NodeId, nodes: openarray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

# Creating a random packet with specific nodeid each time
proc randomPacket*(tag: PacketTag): seq[byte] =
  var
    authTag: AuthTag
    msg: array[44, byte]

  check randomBytes(authTag) == authTag.len
  check randomBytes(msg) == msg.len
  result.add(tag)
  result.add(rlp.encode(authTag))
  result.add(msg)

proc generateNode*(privKey = PrivateKey.random()[], port: int = 20302,
    localEnrFields: openarray[FieldPair] = []): Node =
  let port = Port(port)
  let enr = enr.Record.init(1, privKey, some(ValidIpAddress.init("127.0.0.1")),
    port, port, localEnrFields).expect("Properly intialized private key")
  result = newNode(enr).expect("Properly initialized node")

proc nodeAtDistance*(n: Node, d: uint32): Node =
  while true:
    let node = generateNode()
    if logDist(n.id, node.id) == d:
      return node

proc nodesAtDistance*(n: Node, d: uint32, amount: int): seq[Node] =
  for i in 0..<amount:
    result.add(nodeAtDistance(n, d))

proc addSeenNode*(d: discv5_protocol.Protocol, n: Node): bool =
  # Add it as a seen node, warning: for testing convenience only!
  n.seen = true
  d.addNode(n)
