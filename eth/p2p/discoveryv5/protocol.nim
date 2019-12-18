import
  tables, sets, endians, options, math,
  stew/byteutils, eth/[rlp, keys], chronicles, chronos, stint,
  ../enode, types, encoding, node, routing_table, enr

import nimcrypto except toHex

type
  Protocol* = ref object
    transp: DatagramTransport
    localNode: Node
    privateKey: PrivateKey
    whoareyouMagic: array[32, byte]
    idHash: array[32, byte]
    pendingRequests: Table[array[12, byte], PendingRequest]
    db: Database
    routingTable: RoutingTable
    codec: Codec
    awaitedPackets: Table[(Node, RequestId), Future[Option[Packet]]]

  PendingRequest = object
    node: Node
    packet: seq[byte]

const
  lookupRequestLimit = 15
  findnodeResultLimit = 15 # applies in FINDNODE handler

proc whoareyouMagic(toNode: NodeId): array[32, byte] =
  let srcId = toNode.toByteArrayBE()
  var data: seq[byte]
  data.add(srcId)
  for c in "WHOAREYOU": data.add(byte(c))
  sha256.digest(data).data

proc newProtocol*(privKey: PrivateKey, db: Database, port: Port): Protocol =
  result = Protocol(privateKey: privKey, db: db)
  var a: Address
  a.ip = parseIpAddress("127.0.0.1")
  a.udpPort = port
  var ipAddr: int32
  bigEndian32(addr ipAddr, addr a.ip.address_v4)

  result.localNode = newNode(initENode(result.privateKey.getPublicKey(), a))
  result.localNode.record = initRecord(12, result.privateKey, {"udp": int(a.udpPort), "ip": ipAddr})

  let srcId = result.localNode.id.toByteArrayBE()
  result.whoareyouMagic = whoareyouMagic(result.localNode.id)

  result.idHash = sha256.digest(srcId).data
  result.routingTable.init(result.localNode)

  result.codec = Codec(localNode: result.localNode, privKey: result.privateKey, db: result.db)

proc start*(p: Protocol) =
  discard

proc send(d: Protocol, a: Address, data: seq[byte]) =
  # echo "Sending ", data.len, " bytes to ", a
  let ta = initTAddress(a.ip, a.udpPort)
  let f = d.transp.sendTo(ta, data)
  f.callback = proc(data: pointer) {.gcsafe.} =
    if f.failed:
      debug "Discovery send failed", msg = f.readError.msg

proc send(d: Protocol, n: Node, data: seq[byte]) =
  d.send(n.node.address, data)

proc randomBytes(v: var openarray[byte]) =
  if nimcrypto.randomBytes(v) != v.len:
    raise newException(Exception, "Could not randomize bytes") # TODO:

proc `xor`[N: static[int], T](a, b: array[N, T]): array[N, T] =
  for i in 0 .. a.high:
    result[i] = a[i] xor b[i]

proc isWhoAreYou(d: Protocol, msg: Bytes): bool =
  if msg.len > d.whoareyouMagic.len:
    result = d.whoareyouMagic == msg.toOpenArray(0, 31)

proc decodeWhoAreYou(d: Protocol, msg: Bytes): Whoareyou =
  result = Whoareyou()
  result[] = rlp.decode(msg.toRange[32 .. ^1], WhoareyouObj)

proc sendWhoareyou(d: Protocol, address: Address, toNode: NodeId, authTag: array[12, byte]) =
  let challenge = Whoareyou(authTag: authTag, recordSeq: 1)
  randomBytes(challenge.idNonce)
  d.codec.handshakes[$toNode] = challenge
  var data = @(whoareyouMagic(toNode))
  data.add(rlp.encode(challenge[]))
  d.send(address, data)

proc sendNodes(d: Protocol, toNode: Node, reqId: RequestId, nodes: openarray[Node]) =
  proc sendNodes(d: Protocol, toNode: Node, packet: NodesPacket, reqId: RequestId) {.nimcall.} =
    let (data, _) = d.codec.encodeEncrypted(toNode, encodePacket(packet, reqId), challenge = nil)
    d.send(toNode, data)

  const maxNodesPerPacket = 3

  var packet: NodesPacket
  packet.total = ceil(nodes.len / maxNodesPerPacket).uint32

  for i in 0 ..< nodes.len:
    packet.enrs.add(nodes[i].record)
    if packet.enrs.len == 3:
      d.sendNodes(toNode, packet, reqId)
      packet.enrs.setLen(0)

  if packet.enrs.len != 0:
    d.sendNodes(toNode, packet, reqId)

proc handlePing(d: Protocol, fromNode: Node, ping: PingPacket, reqId: RequestId) =
  let a = fromNode.address
  var pong: PongPacket
  pong.enrSeq = ping.enrSeq
  pong.ip = case a.ip.family
    of IpAddressFamily.IPv4: @(a.ip.address_v4)
    of IpAddressFamily.IPv6: @(a.ip.address_v6)
  pong.port = a.udpPort.uint16

  let (data, _) = d.codec.encodeEncrypted(fromNode, encodePacket(pong, reqId), challenge = nil)
  d.send(fromNode, data)

proc handleFindNode(d: Protocol, fromNode: Node, fn: FindNodePacket, reqId: RequestId) =
  if fn.distance == 0:
    d.sendNodes(fromNode, reqId, [d.localNode])
  else:
    let distance = min(fn.distance, 256)
    d.sendNodes(fromNode, reqId, d.routingTable.neighboursAtDistance(distance))

proc receive*(d: Protocol, a: Address, msg: Bytes) {.gcsafe.} =
  ## Can raise `DiscProtocolError` and all of `RlpError`
  # Note: export only needed for testing
  if msg.len < 32:
    return # Invalid msg

  try:
    # echo "Packet received: ", msg.len

    if d.isWhoAreYou(msg):
      let whoareyou = d.decodeWhoAreYou(msg)
      var pr: PendingRequest
      if d.pendingRequests.take(whoareyou.authTag, pr):
        let toNode = pr.node

        let (data, _) = d.codec.encodeEncrypted(toNode, pr.packet, challenge = whoareyou)
        d.send(toNode, data)

    else:
      var tag: array[32, byte]
      tag[0 .. ^1] = msg.toOpenArray(0, 31)
      let senderData = tag xor d.idHash
      let sender = readUintBE[256](senderData)

      var authTag: array[12, byte]
      var node: Node
      var packet: Packet

      if d.codec.decodeEncrypted(sender, a, msg, authTag, node, packet):
        if node.isNil:
          node = d.routingTable.getNode(sender)
        else:
          echo "Adding new node to routing table"
          discard d.routingTable.addNode(node)

        doAssert(not node.isNil, "No node in the routing table (internal error?)")

        case packet.kind
        of ping:
          d.handlePing(node, packet.ping, packet.reqId)
        of findNode:
          d.handleFindNode(node, packet.findNode, packet.reqId)
        else:
          var waiter: Future[Option[Packet]]
          if d.awaitedPackets.take((node, packet.reqId), waiter):
            waiter.complete(packet.some)
          else:
            echo "TODO: handle packet: ", packet.kind, " from ", node

      else:
        d.sendWhoareyou(a, sender, authTag)
        echo "Could not decode, respond with whoareyou"

  except Exception as e:
    echo "Exception: ", e.msg
    echo e.getStackTrace()

proc waitPacket(d: Protocol, fromNode: Node, reqId: RequestId): Future[Option[Packet]] =
  result = newFuture[Option[Packet]]("waitPacket")
  let res = result
  let key = (fromNode, reqId)
  sleepAsync(1000).addCallback() do(data: pointer):
    d.awaitedPackets.del(key)
    if not res.finished:
      res.complete(none(Packet))
  d.awaitedPackets[key] = result

proc addNodesFromENRs(result: var seq[Node], enrs: openarray[Record]) =
  for r in enrs: result.add(newNode(r))

proc waitNodes(d: Protocol, fromNode: Node, reqId: RequestId): Future[seq[Node]] {.async.} =
  var op = await d.waitPacket(fromNode, reqId)
  if op.isSome and op.get.kind == nodes:
    result.addNodesFromENRs(op.get.nodes.enrs)
    let total = op.get.nodes.total
    for i in 1 ..< total:
      op = await d.waitPacket(fromNode, reqId)
      if op.isSome and op.get.kind == nodes:
        result.addNodesFromENRs(op.get.nodes.enrs)
      else:
        break

proc findNode(d: Protocol, toNode: Node, distance: uint32): Future[seq[Node]] {.async.} =
  let reqId = newRequestId()
  let packet = encodePacket(FindNodePacket(distance: distance), reqId)
  let (data, nonce) = d.codec.encodeEncrypted(toNode, packet, challenge = nil)
  d.pendingRequests[nonce] = PendingRequest(node: toNode, packet: packet)
  d.send(toNode, data)
  result = await d.waitNodes(toNode, reqId)

proc lookupDistances(target, dest: NodeId): seq[uint32] =
  let td = logDist(target, dest)
  result.add(td)
  var i = 1'u32
  while result.len < lookupRequestLimit:
    if td + i < 256:
      result.add(td + i)
    if td - i > 0'u32:
      result.add(td - i)
    inc i

proc lookupWorker(p: Protocol, destNode: Node, target: NodeId): Future[seq[Node]] {.async.} =
  let dists = lookupDistances(target, destNode.id)
  var i = 0
  while i < lookupRequestLimit and result.len < findNodeResultLimit:
    let r = await p.findNode(destNode, dists[i])
    # TODO: Handle falures
    result.add(r)
    inc i

  for n in result:
    discard p.routingTable.addNode(n)

proc lookup(p: Protocol, target: NodeId): Future[seq[Node]] {.async.} =
  result = p.routingTable.neighbours(target, 16)
  var asked = initHashSet[NodeId]()
  asked.incl(p.localNode.id)
  var seen = asked

  const alpha = 3

  var pendingQueries = newSeqOfCap[Future[seq[Node]]](alpha)

  while true:
    var i = 0
    while i < result.len and pendingQueries.len < alpha:
      let n = result[i]
      if not asked.containsOrIncl(n.id):
        pendingQueries.add(p.lookupWorker(n, target))
      inc i

    if pendingQueries.len == 0:
      break

    let idx = await oneIndex(pendingQueries)

    let nodes = pendingQueries[idx].read
    pendingQueries.del(idx)
    for n in nodes:
      if not seen.containsOrIncl(n.id):
        if result.len < BUCKET_SIZE:
          result.add(n)

proc lookupRandom*(p: Protocol): Future[seq[Node]] =
  var id: NodeId
  discard randomBytes(addr id, sizeof(id))
  p.lookup(id)

proc processClient(transp: DatagramTransport,
                   raddr: TransportAddress): Future[void] {.async, gcsafe.} =
  var proto = getUserData[Protocol](transp)
  try:
    # TODO: Maybe here better to use `peekMessage()` to avoid allocation,
    # but `Bytes` object is just a simple seq[byte], and `ByteRange` object
    # do not support custom length.
    var buf = transp.getMessage()
    let a = Address(ip: raddr.address, udpPort: raddr.port, tcpPort: raddr.port)
    proto.receive(a, buf)
  except RlpError:
    debug "Receive failed", err = getCurrentExceptionMsg()
  except:
    debug "Receive failed", err = getCurrentExceptionMsg()
    raise

proc open*(d: Protocol) =
  # TODO allow binding to specific IP / IPv6 / etc
  let ta = initTAddress(IPv4_any(), d.localNode.node.address.udpPort)
  d.transp = newDatagramTransport(processClient, udata = d, local = ta)

proc addNode*(d: Protocol, r: Record) =
  discard d.routingTable.addNode(newNode(r))

proc addNode*(d: Protocol, enr: EnrUri) =
  var r: Record
  let res = r.fromUri(enr)
  doAssert(res)
  discard d.routingTable.addNode(newNode(r))

when isMainModule:
  import discovery_db
  import eth/trie/db

  proc genDiscoveries(n: int): seq[Protocol] =
    var pks = ["98b3d4d4fe348ac5192d16b46aa36c41f847b9f265ba4d56f6326669449a968b", "88d125288fbb19ecd7b6a355faf3e842e3c6158d38af14bb97ac8d957ec9cb58", "c9a24471d2f84efa103b9abbdedd4c0fea8402f94e5ceb3ca4d9cff951fc407f"]
    for i in 0 ..< n:
      var pk: PrivateKey
      if i < pks.len:
        pk = initPrivateKey(pks[i])
      else:
        pk = newPrivateKey()

      let d = newProtocol(pk, DiscoveryDB.init(newMemoryDB()), Port(12001 + i))
      d.open()
      result.add(d)

  proc addNode(d: openarray[Protocol], enr: string) =
    for dd in d: dd.addNode(EnrUri(enr))

  proc test() {.async.} =
    block:
      let d = genDiscoveries(3)
      d.addNode("enr:-IS4QPvi3TdAUd2Jdrx-8ScRbCzrV1kVsTTM02mfz8Fx7CtrAfYN7AjxTx3MWbY2efRmAhS-Yyv4nhyzKu_YS6jSh08BgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQJeWTAJhJYN2q3BvcQwsyo7pIi8KnfwDIrhNdflCFvqr4N1ZHCCD6A")

      for i, dd in d:
        let nodes = await dd.lookupRandom()
        echo "NODES ", i, ": ", nodes

    # block:
    #   var d = genDiscoveries(4)
    #   let rootD = d[0]
    #   d.del(0)


    #   d.addNode(rootD.localNode.record.toUri)

    #   for i, dd in d:
    #     let nodes = await dd.lookupRandom()
    #     echo "NODES ", i, ": ", nodes

  waitFor test()
  runForever()
