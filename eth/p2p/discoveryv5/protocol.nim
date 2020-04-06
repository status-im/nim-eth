import
  std/[tables, sets, options, math, random],
  json_serialization/std/net,
  stew/[byteutils, endians2], chronicles, chronos, stint,
  eth/[rlp, keys], ../enode, types, encoding, node, routing_table, enr

import nimcrypto except toHex

export options

logScope:
  topics = "discv5"

const
  alpha = 3 ## Kademlia concurrency factor
  lookupRequestLimit = 3
  findNodeResultLimit = 15 # applies in FINDNODE handler
  maxNodesPerPacket = 3
  lookupInterval = 60.seconds ## Interval of launching a random lookup to
  ## populate the routing table. go-ethereum seems to do 3 runs every 30
  ## minutes. Trinity starts one every minute.
  handshakeTimeout* = 2.seconds ## timeout for the reply on the
  ## whoareyou message
  responseTimeout* = 2.seconds ## timeout for the response of a request-response
  ## call
  magicSize = 32 ## size of the magic which is the start of the whoareyou
  ## message

type
  Protocol* = ref object
    transp: DatagramTransport
    localNode*: Node
    privateKey: PrivateKey
    whoareyouMagic: array[magicSize, byte]
    idHash: array[32, byte]
    pendingRequests: Table[AuthTag, PendingRequest]
    db: Database
    routingTable: RoutingTable
    codec*: Codec
    awaitedPackets: Table[(NodeId, RequestId), Future[Option[Packet]]]
    lookupLoop: Future[void]
    revalidateLoop: Future[void]
    bootstrapRecords*: seq[Record]

  PendingRequest = object
    node: Node
    packet: seq[byte]

proc addNode*(d: Protocol, node: Node) =
  discard d.routingTable.addNode(node)

template addNode*(d: Protocol, enode: ENode) =
  addNode d, newNode(enode)

template addNode*(d: Protocol, r: Record) =
  addNode d, newNode(r)

proc addNode*(d: Protocol, enr: EnrUri) =
  var r: Record
  let res = r.fromUri(enr)
  doAssert(res)
  d.addNode newNode(r)

proc getNode*(d: Protocol, id: NodeId): Node =
  d.routingTable.getNode(id)

proc randomNodes*(d: Protocol, count: int): seq[Node] =
  d.routingTable.randomNodes(count)

proc neighbours*(d: Protocol, id: NodeId, k: int = BUCKET_SIZE): seq[Node] =
  d.routingTable.neighbours(id, k)

proc nodesDiscovered*(d: Protocol): int {.inline.} = d.routingTable.len

func privKey*(d: Protocol): lent PrivateKey =
  d.privateKey

proc send(d: Protocol, a: Address, data: seq[byte]) =
  # debug "Sending bytes", amount = data.len, to = a
  let ta = initTAddress(a.ip, a.udpPort)
  let f = d.transp.sendTo(ta, data)
  f.callback = proc(data: pointer) {.gcsafe.} =
    if f.failed:
      debug "Discovery send failed", msg = f.readError.msg

proc send(d: Protocol, n: Node, data: seq[byte]) =
  d.send(n.node.address, data)

proc `xor`[N: static[int], T](a, b: array[N, T]): array[N, T] =
  for i in 0 .. a.high:
    result[i] = a[i] xor b[i]

proc whoareyouMagic(toNode: NodeId): array[magicSize, byte] =
  const prefix = "WHOAREYOU"
  var data: array[prefix.len + sizeof(toNode), byte]
  data[0 .. sizeof(toNode) - 1] = toNode.toByteArrayBE()
  for i, c in prefix: data[sizeof(toNode) + i] = byte(c)
  sha256.digest(data).data

proc isWhoAreYou(d: Protocol, msg: Bytes): bool =
  if msg.len > d.whoareyouMagic.len:
    result = d.whoareyouMagic == msg.toOpenArray(0, magicSize - 1)

proc decodeWhoAreYou(d: Protocol, msg: Bytes): Whoareyou =
  result = Whoareyou()
  result[] = rlp.decode(msg.toRange[magicSize .. ^1], WhoareyouObj)

proc sendWhoareyou(d: Protocol, address: Address, toNode: NodeId, authTag: AuthTag) =
  trace "sending who are you", to = $toNode, toAddress = $address
  let challenge = Whoareyou(authTag: authTag, recordSeq: 0)
  encoding.randomBytes2(challenge.idNonce)
  # If there is already a handshake going on for this nodeid then we drop this
  # new one. Handshake will get cleaned up after `handshakeTimeout`.
  # If instead overwriting the handshake would be allowed, the handshake timeout
  # will need to be canceled each time.
  # TODO: could also clean up handshakes in a seperate call, e.g. triggered in
  # a loop.
  # Use toNode + address to make it more difficult for an attacker to occupy
  # the handshake of another node.

  let key = HandShakeKey(nodeId: toNode, address: $address)
  if not d.codec.handshakes.hasKeyOrPut(key, challenge):
    sleepAsync(handshakeTimeout).addCallback() do(data: pointer):
      # TODO: should we still provide cancellation in case handshake completes
      # correctly?
      d.codec.handshakes.del(key)

    var data = @(whoareyouMagic(toNode))
    data.add(rlp.encode(challenge[]))
    d.send(address, data)

proc sendNodes(d: Protocol, toId: NodeId, toAddr: Address, reqId: RequestId,
    nodes: openarray[Node]) =
  proc sendNodes(d: Protocol, toId: NodeId, toAddr: Address,
      packet: NodesPacket, reqId: RequestId) {.nimcall.} =
    let (data, _) = d.codec.encodeEncrypted(toId, toAddr,
      encodePacket(packet, reqId), challenge = nil)
    d.send(toAddr, data)

  var packet: NodesPacket
  packet.total = ceil(nodes.len / maxNodesPerPacket).uint32

  for i in 0 ..< nodes.len:
    packet.enrs.add(nodes[i].record)
    if packet.enrs.len == 3:
      d.sendNodes(toId, toAddr, packet, reqId)
      packet.enrs.setLen(0)

  if packet.enrs.len != 0:
    d.sendNodes(toId, toAddr, packet, reqId)

proc handlePing(d: Protocol, fromId: NodeId, fromAddr: Address,
    ping: PingPacket, reqId: RequestId) =
  let a = fromAddr
  var pong: PongPacket
  pong.enrSeq = ping.enrSeq
  pong.ip = case a.ip.family
    of IpAddressFamily.IPv4: @(a.ip.address_v4)
    of IpAddressFamily.IPv6: @(a.ip.address_v6)
  pong.port = a.udpPort.uint16

  let (data, _) = d.codec.encodeEncrypted(fromId, fromAddr,
    encodePacket(pong, reqId), challenge = nil)
  d.send(fromAddr, data)

proc handleFindNode(d: Protocol, fromId: NodeId, fromAddr: Address,
    fn: FindNodePacket, reqId: RequestId) =
  if fn.distance == 0:
    d.sendNodes(fromId, fromAddr, reqId, [d.localNode])
  else:
    let distance = min(fn.distance, 256)
    d.sendNodes(fromId, fromAddr, reqId,
      d.routingTable.neighboursAtDistance(distance))

proc receive*(d: Protocol, a: Address, msg: Bytes) {.gcsafe,
  raises: [
    Defect,
    # TODO This is now coming from Chronos's callSoon
    Exception,
    # TODO All of these should probably be handled here
    RlpError,
    IOError,
    TransportAddressError,
  ].} =
  if msg.len < tagSize: # or magicSize, can be either
    return # Invalid msg

  # debug "Packet received: ", length = msg.len

  if d.isWhoAreYou(msg):
    trace "Received whoareyou", localNode = $d.localNode, address = a
    let whoareyou = d.decodeWhoAreYou(msg)
    var pr: PendingRequest
    if d.pendingRequests.take(whoareyou.authTag, pr):
      let toNode = pr.node
      whoareyou.pubKey = toNode.node.pubkey # TODO: Yeah, rather ugly this.
      try:
        let (data, _) = d.codec.encodeEncrypted(toNode.id, toNode.address,
          pr.packet, challenge = whoareyou)
        d.send(toNode, data)
      except RandomSourceDepleted as err:
        debug "Failed to respond to a who-you-are msg " &
              "due to randomness source depletion."

  else:
    var tag: array[tagSize, byte]
    tag[0 .. ^1] = msg.toOpenArray(0, tagSize - 1)
    let senderData = tag xor d.idHash
    let sender = readUintBE[256](senderData)

    var authTag: AuthTag
    var node: Node
    var packet: Packet
    let decoded = d.codec.decodeEncrypted(sender, a, msg, authTag, node, packet)
    if decoded == DecodeStatus.Success:
      if node.isNil:
        node = d.routingTable.getNode(sender)
      else:
        # Not filling table with nodes without correct IP in the ENR
        if a.ip == node.address.ip:
          debug "Adding new node to routing table", node = $node,
            localNode = $d.localNode
          discard d.routingTable.addNode(node)

      case packet.kind
      of ping:
        d.handlePing(sender, a, packet.ping, packet.reqId)
      of findNode:
        d.handleFindNode(sender, a, packet.findNode, packet.reqId)
      else:
        var waiter: Future[Option[Packet]]
        if d.awaitedPackets.take((sender, packet.reqId), waiter):
          waiter.complete(packet.some)
        else:
          debug "TODO: handle packet: ", packet = packet.kind, origin = $node
    elif decoded == DecodeStatus.DecryptError:
      debug "Could not decrypt packet, respond with whoareyou",
        localNode = $d.localNode, address = a
      # only sendingWhoareyou in case it is a decryption failure
      d.sendWhoareyou(a, sender, authTag)
    elif decoded == DecodeStatus.PacketError:
      # Still adding the node in case there is a packet error (could be
      # unsupported packet)
      if not node.isNil:
        if a.ip == node.address.ip:
          debug "Adding new node to routing table", node = $node,
            localNode = $d.localNode
          discard d.routingTable.addNode(node)

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
  except RlpError as e:
    debug "Receive failed", exception = e.name, msg = e.msg
  # TODO: what else can be raised? Figure this out and be more restrictive?
  except CatchableError as e:
    debug "Receive failed", exception = e.name, msg = e.msg,
      stacktrace = e.getStackTrace()

proc validIp(sender, address: IpAddress): bool =
  let
    s = initTAddress(sender, Port(0))
    a = initTAddress(address, Port(0))
  if a.isAnyLocal():
    return false
  if a.isMulticast():
    return false
  if a.isLoopback() and not s.isLoopback():
    return false
  if a.isSiteLocal() and not s.isSiteLocal():
    return false
  # TODO: Also check for special reserved ip addresses:
  # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  # https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
  return true

# TODO: This could be improved to do the clean-up immediatily in case a non
# whoareyou response does arrive, but we would need to store the AuthTag
# somewhere
proc registerRequest(d: Protocol, n: Node, packet: seq[byte], nonce: AuthTag) =
  let request = PendingRequest(node: n, packet: packet)
  if not d.pendingRequests.hasKeyOrPut(nonce, request):
    sleepAsync(responseTimeout).addCallback() do(data: pointer):
      d.pendingRequests.del(nonce)

proc waitPacket(d: Protocol, fromNode: Node, reqId: RequestId): Future[Option[Packet]] =
  result = newFuture[Option[Packet]]("waitPacket")
  let res = result
  let key = (fromNode.id, reqId)
  sleepAsync(responseTimeout).addCallback() do(data: pointer):
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

proc sendPing(d: Protocol, toNode: Node): RequestId =
  let
    reqId = newRequestId()
    ping = PingPacket(enrSeq: d.localNode.record.seqNum)
    packet = encodePacket(ping, reqId)
    (data, nonce) = d.codec.encodeEncrypted(toNode.id, toNode.address, packet,
      challenge = nil)
  d.registerRequest(toNode, packet, nonce)
  d.send(toNode, data)
  return reqId

proc ping*(d: Protocol, toNode: Node): Future[Option[PongPacket]] {.async.} =
  let reqId = d.sendPing(toNode)
  let resp = await d.waitPacket(toNode, reqId)

  if resp.isSome() and resp.get().kind == pong:
    return some(resp.get().pong)

proc sendFindNode(d: Protocol, toNode: Node, distance: uint32): RequestId =
  let reqId = newRequestId()
  let packet = encodePacket(FindNodePacket(distance: distance), reqId)
  let (data, nonce) = d.codec.encodeEncrypted(toNode.id, toNode.address, packet,
    challenge = nil)
  d.registerRequest(toNode, packet, nonce)

  d.send(toNode, data)
  return reqId

proc findNode*(d: Protocol, toNode: Node, distance: uint32): Future[seq[Node]] {.async.} =
  let reqId = sendFindNode(d, toNode, distance)
  let nodes = await d.waitNodes(toNode, reqId)

  for n in nodes:
    if validIp(toNode.address.ip, n.address.ip):
      result.add(n)

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

proc lookupWorker(d: Protocol, destNode: Node, target: NodeId): Future[seq[Node]] {.async.} =
  let dists = lookupDistances(target, destNode.id)
  var i = 0
  while i < lookupRequestLimit and result.len < findNodeResultLimit:
    # TODO: Handle failures
    let r = await d.findNode(destNode, dists[i])
    # TODO: I guess it makes sense to limit here also to `findNodeResultLimit`?
    result.add(r)
    inc i

  for n in result:
    discard d.routingTable.addNode(n)

proc lookup*(d: Protocol, target: NodeId): Future[seq[Node]] {.async.} =
  ## Perform a lookup for the given target, return the closest n nodes to the
  ## target. Maximum value for n is `BUCKET_SIZE`.
  # TODO: Sort the returned nodes on distance
  result = d.routingTable.neighbours(target, BUCKET_SIZE)
  var asked = initHashSet[NodeId]()
  asked.incl(d.localNode.id)
  var seen = asked
  for node in result:
    seen.incl(node.id)

  var pendingQueries = newSeqOfCap[Future[seq[Node]]](alpha)

  while true:
    var i = 0
    while i < result.len and pendingQueries.len < alpha:
      let n = result[i]
      if not asked.containsOrIncl(n.id):
        pendingQueries.add(d.lookupWorker(n, target))
      inc i

    trace "discv5 pending queries", total = pendingQueries.len

    if pendingQueries.len == 0:
      break

    let idx = await oneIndex(pendingQueries)
    trace "Got discv5 lookup response", idx

    let nodes = pendingQueries[idx].read
    pendingQueries.del(idx)
    for n in nodes:
      if not seen.containsOrIncl(n.id):
        if result.len < BUCKET_SIZE:
          result.add(n)

proc lookupRandom*(d: Protocol): Future[seq[Node]]
    {.raises:[RandomSourceDepleted, Defect, Exception].} =
  var id: NodeId
  if randomBytes(addr id, sizeof(id)) != sizeof(id):
    raise newException(RandomSourceDepleted, "Could not randomize bytes")
  d.lookup(id)

proc revalidateNode*(d: Protocol, n: Node)
    {.async, raises:[Defect, Exception].} = # TODO: Exception
  trace "Ping to revalidate node", node = $n
  let pong = await d.ping(n)

  if pong.isSome():
    if pong.get().enrSeq > n.record.seqNum:
      # TODO: Request new ENR
      discard

    d.routingTable.setJustSeen(n)
    trace "Revalidated node", node = $n
  else:
    # For now we never remove bootstrap nodes. It might make sense to actually
    # do so and to retry them only in case we drop to a really low amount of
    # peers in the DHT
    if n.record notin d.bootstrapRecords:
      trace "Revalidation of node failed, removing node", record = n.record
      d.routingTable.removeNode(n)
      # Remove shared secrets when removing the node from routing table.
      # This might be to direct, so we could keep these longer. But better
      # would be to simply not remove the nodes immediatly but only after x
      # amount of failures.
      discard d.codec.db.deleteKeys(n.id, n.address)
    else:
      debug "Revalidation of bootstrap node failed", enr = toURI(n.record)

proc revalidateLoop(d: Protocol) {.async.} =
  try:
    # TODO: We need to handle actual errors still, which might just allow to
    # continue the loop. However, currently `revalidateNode` raises a general
    # `Exception` making this rather hard.
    while true:
      await sleepAsync(rand(10 * 1000).milliseconds)
      let n = d.routingTable.nodeToRevalidate()
      if not n.isNil:
        # TODO: Should we do these in parallel and/or async to be certain of how
        # often nodes are revalidated?
        await d.revalidateNode(n)
  except CancelledError:
    trace "revalidateLoop canceled"

proc lookupLoop(d: Protocol) {.async.} =
  ## TODO: Same story as for `revalidateLoop`
  try:
    while true:
      # lookup self (neighbour nodes)
      var nodes = await d.lookup(d.localNode.id)
      trace "Discovered nodes in self lookup", nodes = $nodes

      nodes = await d.lookupRandom()
      trace "Discovered nodes in random lookup", nodes = $nodes
      await sleepAsync(lookupInterval)
  except CancelledError:
    trace "lookupLoop canceled"

proc newProtocol*(privKey: PrivateKey, db: Database,
                  externalIp: Option[IpAddress], tcpPort, udpPort: Port,
                  bootstrapRecords: openarray[Record] = []): Protocol =
  let
    a = Address(ip: externalIp.get(IPv4_any()),
                tcpPort: tcpPort, udpPort: udpPort)
    enode = ENode(pubkey: privKey.toPublicKey().tryGet(), address: a)
    enrRec = enr.Record.init(1, privKey, externalIp, tcpPort, udpPort)
    node = newNode(enode, enrRec)

  result = Protocol(
    privateKey: privKey,
    db: db,
    localNode: node,
    whoareyouMagic: whoareyouMagic(node.id),
    idHash: sha256.digest(node.id.toByteArrayBE).data,
    codec: Codec(localNode: node, privKey: privKey, db: db),
    bootstrapRecords: @bootstrapRecords)

  result.routingTable.init(node)

proc open*(d: Protocol) =
  info "Starting discovery node", node = $d.localNode,
    uri = toURI(d.localNode.record)
  # TODO allow binding to specific IP / IPv6 / etc
  let ta = initTAddress(IPv4_any(), d.localNode.node.address.udpPort)
  d.transp = newDatagramTransport(processClient, udata = d, local = ta)

  for record in d.bootstrapRecords:
    debug "Adding bootstrap node", uri = toURI(record)
    d.addNode(record)

proc start*(d: Protocol) =
  # Might want to move these to a separate proc if this turns out to be needed.
  d.lookupLoop = lookupLoop(d)
  d.revalidateLoop = revalidateLoop(d)

proc close*(d: Protocol) =
  doAssert(not d.transp.closed)

  debug "Closing discovery node", node = $d.localNode
  if not d.revalidateLoop.isNil:
    d.revalidateLoop.cancel()
  if not d.lookupLoop.isNil:
    d.lookupLoop.cancel()
  # TODO: unsure if close can't create issues in the not awaited cancellations
  # above
  d.transp.close()

proc closeWait*(d: Protocol) {.async.} =
  doAssert(not d.transp.closed)

  debug "Closing discovery node", node = $d.localNode
  if not d.revalidateLoop.isNil:
    await d.revalidateLoop.cancelAndWait()
  if not d.lookupLoop.isNil:
    await d.lookupLoop.cancelAndWait()

  await d.transp.closeWait()
