import
  stew/shims/net, bearssl,
  eth/keys,
  eth/p2p/discoveryv5/[enr, node, routing_table],
  eth/p2p/discoveryv5/protocol as discv5_protocol

proc localAddress*(port: int): Address =
  Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(port))

proc initDiscoveryNode*(rng: ref BrHmacDrbgContext, privKey: PrivateKey,
                        address: Address,
                        bootstrapRecords: openarray[Record] = [],
                        localEnrFields: openarray[(string, seq[byte])] = [],
                        previousRecord = none[enr.Record]()):
                        discv5_protocol.Protocol =
  result = newProtocol(privKey,
                       some(address.ip),
                       address.port, address.port,
                       bootstrapRecords = bootstrapRecords,
                       localEnrFields = localEnrFields,
                       previousRecord = previousRecord, rng = rng)

  result.open()

proc nodeIdInNodes*(id: NodeId, nodes: openarray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

proc generateNode*(privKey: PrivateKey, port: int = 20302,
    localEnrFields: openarray[FieldPair] = []): Node =
  let port = Port(port)
  let enr = enr.Record.init(1, privKey, some(ValidIpAddress.init("127.0.0.1")),
    port, port, localEnrFields).expect("Properly intialized private key")
  result = newNode(enr).expect("Properly initialized node")

proc nodeAtDistance*(n: Node, rng: var BrHmacDrbgContext, d: uint32): Node =
  while true:
    let node = generateNode(PrivateKey.random(rng))
    if logDist(n.id, node.id) == d:
      return node

proc nodesAtDistance*(
    n: Node, rng: var BrHmacDrbgContext, d: uint32, amount: int): seq[Node] =
  for i in 0..<amount:
    result.add(nodeAtDistance(n, rng, d))

proc addSeenNode*(d: discv5_protocol.Protocol, n: Node): bool =
  # Add it as a seen node, warning: for testing convenience only!
  n.seen = true
  d.addNode(n)
