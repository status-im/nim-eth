# nim-eth
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/net,
  chronos,
  ../../eth/p2p/discoveryv5/[enr, node, routing_table],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol

export net

func localAddress*(port: int): Address =
  Address(ip: parseIpAddress("127.0.0.1"), port: Port(port))

proc initDiscoveryNode*(
    rng: ref HmacDrbgContext,
    privKey: PrivateKey,
    address: Address,
    bootstrapRecords: openArray[Record] = [],
    localEnrFields: openArray[(string, seq[byte])] = [],
    previousRecord = Opt.none(enr.Record),
    banNodes = false):
    discv5_protocol.Protocol =
  # set bucketIpLimit to allow bucket split
  let config = DiscoveryConfig.init(1000, 24, 5)

  let protocol = newProtocol(
    privKey,
    Opt.some(address.ip),
    Opt.some(address.port), Opt.some(address.port),
    bindPort = address.port,
    bootstrapRecords = bootstrapRecords,
    localEnrFields = localEnrFields,
    previousRecord = previousRecord,
    config = config,
    rng = rng,
    banNodes = banNodes)

  protocol.open()

  protocol

func nodeIdInNodes*(id: NodeId, nodes: openArray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

func generateNode*(privKey: PrivateKey, port: int = 20302,
    ip: IpAddress = parseIpAddress("127.0.0.1"),
    localEnrFields: openArray[FieldPair] = []): Node =
  let port = Port(port)
  let enr = enr.Record.init(1, privKey, Opt.some(ip),
    Opt.some(port), Opt.some(port), localEnrFields).expect("Properly initialized private key")
  result = Node.fromRecord(enr)

proc generateNRandomNodes*(rng: var HmacDrbgContext, n: int): seq[Node] =
  var res = newSeq[Node]()
  for i in 1..n:
    let node = generateNode(PrivateKey.random(rng))
    res.add(node)
  res

proc nodeAndPrivKeyAtDistance*(n: Node, rng: var HmacDrbgContext, d: uint32,
    ip: IpAddress = parseIpAddress("127.0.0.1")): (Node, PrivateKey) =
  while true:
    let pk = PrivateKey.random(rng)
    let node = generateNode(pk, ip = ip)
    if logDistance(n.id, node.id) == d:
      return (node, pk)

proc nodeAtDistance*(n: Node, rng: var HmacDrbgContext, d: uint32,
    ip: IpAddress = parseIpAddress("127.0.0.1")): Node =
  let (node, _) = n.nodeAndPrivKeyAtDistance(rng, d, ip)
  node

proc nodesAtDistance*(
    n: Node, rng: var HmacDrbgContext, d: uint32, amount: int,
    ip: IpAddress = parseIpAddress("127.0.0.1")): seq[Node] =
  for i in 0..<amount:
    result.add(nodeAtDistance(n, rng, d, ip))

proc nodesAtDistanceUniqueIp*(
    n: Node, rng: var HmacDrbgContext, d: uint32, amount: int,
    ip: IpAddress = parseIpAddress("127.0.0.1")): seq[Node] =
  var ta = initTAddress(ip, Port(0))
  for i in 0..<amount:
    ta.inc()
    result.add(nodeAtDistance(n, rng, d, ta.address()))

proc addSeenNode*(d: discv5_protocol.Protocol, n: Node): bool =
  # Add it as a seen node, warning: for testing convenience only!
  n.seen = true
  d.addNode(n)
