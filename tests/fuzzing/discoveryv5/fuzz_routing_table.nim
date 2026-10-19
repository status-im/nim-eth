import
  std/[net, sets, tables],
  testutils/fuzzing,
  ../../../eth/net/utils,
  ../../../eth/p2p/discoveryv5/[node, routing_table]

{.push raises: [].}

const
  numIdentities = 256
  maxHistory = 4
  sharedSubnets = [[1'u8, 2, 3], [5'u8, 6, 7], [8'u8, 8, 8]]
  localSubnet = [192'u8, 168, 0]
  banPeriods = [ZeroDuration, 1.hours]

func ipv4(subnet: array[3, byte], host: byte): IpAddress =
  IpAddress(
    family: IpAddressFamily.IPv4,
    address_v4: [subnet[0], subnet[1], subnet[2], host])

func recordIp(id: int, sel: byte): Opt[IpAddress] =
  case sel mod 4
  of 0: Opt.some(ipv4(sharedSubnets[sel mod sharedSubnets.len], sel))
  of 1: Opt.some(ipv4([20'u8, 0, byte(id)], sel))
  of 2: Opt.some(ipv4(localSubnet, byte(id)))
  else: Opt.none(IpAddress)

func discoveryNode(
    pk: PrivateKey, seqNum: uint64, ip: Opt[IpAddress]): DiscoveryNode =
  DiscoveryNode.fromRecord(Record.init(
    seqNum, pk, ip, Opt.some(Port(9000)), Opt.some(Port(9000)))
    .expect("valid record"))

let
  privKeys = block:
    var res: seq[PrivateKey]
    for i in 0 ..< numIdentities:
      var raw: array[32, byte]
      raw[0] = 1
      raw[31] = byte(i)
      res.add PrivateKey.fromRaw(raw).expect("valid private key")
    res
  nodeIds = block:
    var res: seq[NodeId]
    for pk in privKeys:
      res.add pk.toPublicKey().toNodeId()
    res

proc checkInvariants(table: RoutingTable, ipLimits: TableIpLimits) =
  var
    ids: HashSet[NodeId]
    tableIps: CountTable[IpAddress]
    numNodes = 0
  for b in table.buckets:
    doAssert b.nodes.len <= BUCKET_SIZE, "bucket overflow"

    var bucketIps: CountTable[IpAddress]
    for n in b.nodes:
      doAssert n.id != table.localId, "local node in table"
      doAssert not ids.containsOrIncl(n.id), "duplicate entry in table"
      doAssert not table.isBanned(n.id), "banned node in table"
      doAssert n.address.isSome(), "entry without address"
      let ip = n.address.get().ip
      if not ip.isLocallyAssigned():
        bucketIps.inc(ip.subnet())
        tableIps.inc(ip.subnet())
    for _, count in bucketIps:
      doAssert uint(count) <= ipLimits.bucketIpLimit, "bucket IP limit exceeded"
    numNodes += b.nodes.len

  for _, count in tableIps:
    doAssert uint(count) <= ipLimits.tableIpLimit, "table IP limit exceeded"
  doAssert numNodes == table.len()

proc checkQueries(
    table: RoutingTable, target: NodeId, k: int, dist: uint16,
    seenOnly: bool) =
  let closest = table.neighbours(target, k, seenOnly)
  doAssert closest.len <= k
  for i, n in closest:
    doAssert n in table and (n.seen or not seenOnly)
    if i > 0:
      doAssert distance(closest[i - 1].id, target) <= distance(n.id, target),
        "neighbours must be sorted by distance"

  for n in table.neighboursAtDistances(@[dist], k, seenOnly):
    doAssert n in table and logDistance(n.id, table.localId) == dist

  let
    amount = min(k, table.len())
    picked = table.randomNodes(amount)
  doAssert picked.len == amount and picked.toHashSet().len == amount
  for n in picked:
    doAssert n in table

  let n = table.getNode(target)
  doAssert n.isNone() or n.get() in table

test:
  var i = 0
  template nextByte(): byte =
    if i < payload.len:
      inc i
      payload[i - 1]
    else:
      0'u8

  let
    bitsPerHop = 1 + int(nextByte() mod 5)
    ipLimits = TableIpLimits(
      bucketIpLimit: 1 + uint(nextByte() mod 4),
      tableIpLimit: 1 + uint(nextByte() mod 16))
    rng = (ref HmacDrbgContext)()
  rng[] = HmacDrbgContext.init(
    [nextByte(), nextByte(), nextByte(), nextByte()])

  var
    table = RoutingTable.init(nodeIds[0], bitsPerHop, ipLimits, rng)
    seqNums: array[numIdentities, uint64]
    history: array[numIdentities, seq[DiscoveryNode]]

  while i < payload.len:
    let id = int(nextByte())

    template heldNode(): DiscoveryNode =
      history[id][int(nextByte()) mod history[id].len]

    case nextByte() mod 13
    of 0 .. 3:
      inc seqNums[id]
      let n = discoveryNode(
        privKeys[id], seqNums[id], recordIp(id, nextByte()))
      if history[id].len >= maxHistory:
        history[id].delete(0)
      history[id].add n
      discard table.addNode(n)
    of 4:
      if history[id].len > 0:
        discard table.addNode(heldNode())
    of 5:
      if history[id].len > 0:
        table.replaceNode(heldNode())
    of 6:
      if history[id].len > 0:
        table.replaceNode(heldNode())
    of 7:
      if history[id].len > 0:
        table.setJustSeen(heldNode())
    of 8:
      let n = table.nodeToRevalidate()
      if not n.isNil:
        table.setJustSeen(n)
    of 9:
      let n = table.nodeToRevalidate()
      if not n.isNil:
        table.replaceNode(n)
    of 10:
      table.banNode(nodeIds[id], banPeriods[nextByte() mod banPeriods.len])
    of 11:
      table.cleanupExpiredBans()
    else:
      checkQueries(
        table, nodeIds[id], k = int(nextByte() mod 20),
        dist = uint16(256 - int(nextByte() mod 16)),
        seenOnly = nextByte() mod 2 == 1)

    checkInvariants(table, ipLimits)
