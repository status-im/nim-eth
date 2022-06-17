import
  stew/shims/net, chronos,
  ../../eth/keys,
  ../../eth/p2p/discoveryv5/[enr, node, routing_table],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol

export net

proc localAddress*(port: int): Address =
  Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(port))

proc initDiscoveryNode*(
    rng: ref HmacDrbgContext,
    privKey: PrivateKey,
    address: Address,
    bootstrapRecords: openArray[Record] = [],
    localEnrFields: openArray[(string, seq[byte])] = [],
    previousRecord = none[enr.Record]()):
    discv5_protocol.Protocol =
  # set bucketIpLimit to allow bucket split
  let config = DiscoveryConfig.init(1000, 24, 5)

  let protocol = newProtocol(
    privKey,
    some(address.ip),
    some(address.port), some(address.port),
    bindPort = address.port,
    bootstrapRecords = bootstrapRecords,
    localEnrFields = localEnrFields,
    previousRecord = previousRecord,
    config = config,
    rng = rng)

  protocol.open()

  protocol

proc nodeIdInNodes*(id: NodeId, nodes: openArray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

proc generateNode*(privKey: PrivateKey, port: int = 20302,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1"),
    localEnrFields: openArray[FieldPair] = []): Node =
  let port = Port(port)
  let enr = enr.Record.init(1, privKey, some(ip),
    some(port), some(port), localEnrFields).expect("Properly intialized private key")
  result = newNode(enr).expect("Properly initialized node")

proc generateNRandomNodes*(rng: var HmacDrbgContext, n: int): seq[Node] =
  var res = newSeq[Node]()
  for i in 1..n:
    let node = generateNode(PrivateKey.random(rng))
    res.add(node)
  res

proc nodeAndPrivKeyAtDistance*(n: Node, rng: var HmacDrbgContext, d: uint32,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): (Node, PrivateKey) =
  while true:
    let pk = PrivateKey.random(rng)
    let node = generateNode(pk, ip = ip)
    if logDistance(n.id, node.id) == d:
      return (node, pk)

proc nodeAtDistance*(n: Node, rng: var HmacDrbgContext, d: uint32,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): Node =
  let (node, _) = n.nodeAndPrivKeyAtDistance(rng, d, ip)
  node

proc nodesAtDistance*(
    n: Node, rng: var HmacDrbgContext, d: uint32, amount: int,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): seq[Node] =
  for i in 0..<amount:
    result.add(nodeAtDistance(n, rng, d, ip))

proc nodesAtDistanceUniqueIp*(
    n: Node, rng: var HmacDrbgContext, d: uint32, amount: int,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): seq[Node] =
  var ta = initTAddress(ip, Port(0))
  for i in 0..<amount:
    ta.inc()
    result.add(nodeAtDistance(n, rng, d, ValidIpAddress.init(ta.address())))

proc addSeenNode*(d: discv5_protocol.Protocol, n: Node): bool =
  # Add it as a seen node, warning: for testing convenience only!
  n.seen = true
  d.addNode(n)
