# nim-eth
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/net,
  chronos,
  ../../eth/net/utils,
  ../../eth/enr/enr,
  ../../eth/p2p/discoveryv5/[node, routing_table],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol

export net

func localAddress*(port: int): Address {.raises: [ValueError].} =
  Address(ip: parseIpAddress("127.0.0.1"), port: Port(port))

proc initDiscoveryNode*(
    rng: ref HmacDrbgContext,
    privKey: PrivateKey,
    address: Address,
    bootstrapRecords: openArray[Record] = [],
    localEnrFields: openArray[(string, seq[byte])] = [],
    previousRecord = Opt.none(enr.Record),
    config: DiscoveryConfig = DiscoveryConfig.init(1000, 24, 5)): # default increase bucketIpLimit to allow bucket split
    discv5_protocol.Protocol {.raises: [TransportOsError].} =
  let protocol = newProtocol(
    privKey,
    Opt.some(address.ip),
    Opt.some(address.port),
    Opt.some(address.port),
    Opt.some(address.port),
    bindPort = address.port,
    bootstrapRecords = bootstrapRecords,
    localEnrFields = localEnrFields,
    previousRecord = previousRecord,
    config = config,
    rng = rng)

  protocol.open()

  protocol

func nodeIdInNodes*(id: NodeId, nodes: openArray[DiscoveryNode]): bool =
  for n in nodes:
    if id == n.id: return true

func generateNode*(privKey: PrivateKey, port: int = 20302,
    ip: IpAddress = parseIpAddress("127.0.0.1"),
    localEnrFields: openArray[FieldPair] = []): DiscoveryNode {.raises: [ValueError].} =
  let port = Port(port)
  let enr = enr.Record.init(1, privKey, Opt.some(ip),
    Opt.some(port), Opt.some(port), Opt.some(port), localEnrFields).expect("Properly initialized private key")
  result = DiscoveryNode.fromRecord(enr)

func updatedNode*(n: DiscoveryNode, privKey: PrivateKey, ip: IpAddress,
    port: Port): DiscoveryNode =
  ## The same peer with a new record: a higher sequence number and the given
  ## endpoint.
  var record = n.record
  record.update(privKey, Opt.some(ip), Opt.some(port), Opt.some(port))
    .expect("Valid record update")
  DiscoveryNode.fromRecord(record)

proc generateNRandomNodes*(
    rng: var HmacDrbgContext, n: int
): seq[DiscoveryNode] {.raises: [ValueError].} =
  var res = newSeq[DiscoveryNode]()
  for i in 1..n:
    let node = generateNode(PrivateKey.random(rng))
    res.add(node)
  res

proc nodeAndPrivKeyAtDistance*(n: DiscoveryNode, rng: var HmacDrbgContext, d: uint32,
    ip: IpAddress = parseIpAddress("127.0.0.1")
): (DiscoveryNode, PrivateKey) {.raises: [ValueError].} =
  while true:
    let pk = PrivateKey.random(rng)
    let node = generateNode(pk, ip = ip)
    if logDistance(n.id, node.id) == d:
      return (node, pk)

proc nodeAtDistance*(n: DiscoveryNode, rng: var HmacDrbgContext, d: uint32,
    ip: IpAddress = parseIpAddress("127.0.0.1")): DiscoveryNode {.raises: [ValueError].} =
  let (node, _) = n.nodeAndPrivKeyAtDistance(rng, d, ip)
  node

proc nodesAtDistance*(
    n: DiscoveryNode, rng: var HmacDrbgContext, d: uint32, amount: int,
    ip: IpAddress = parseIpAddress("127.0.0.1")): seq[DiscoveryNode] {.raises: [ValueError].} =
  for i in 0..<amount:
    result.add(nodeAtDistance(n, rng, d, ip))

proc nodesAtDistanceUniqueIp*(
    n: DiscoveryNode, rng: var HmacDrbgContext, d: uint32, amount: int,
    ip: IpAddress = parseIpAddress("127.0.0.1")): seq[DiscoveryNode] {.raises: [ValueError].} =
  ## Nodes of which the addresses are each in a different subnet, as that is
  ## what the ip limits are counted on.
  var ta = initTAddress(ip, Port(0))
  for i in 0..<amount:
    ta.inc(1 shl (32 - IpLimitSubnetV4))
    result.add(nodeAtDistance(n, rng, d, ta.address()))

proc addSeenNode*(d: discv5_protocol.Protocol, n: DiscoveryNode): bool =
  # Add it as a seen node, warning: for testing convenience only!
  n.seen = true
  d.addNode(n)
