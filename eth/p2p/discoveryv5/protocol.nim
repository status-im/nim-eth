# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed under either of
#   * Apache License, version 2.0, (LICENSE-APACHEv2)
#   * MIT license (LICENSE-MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

## Node Discovery Protocol v5
##
## Node discovery protocol implementation as per specification:
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md
##
## This node discovery protocol implementation uses the same underlying
## implementation of routing table as is also used for the discovery v4
## implementation, which is the same or similar as the one described in the
## original Kademlia paper:
## https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf
##
## This might not be the most optimal implementation for the node discovery
## protocol v5. Why?
##
## The Kademlia paper describes an implementation that starts off from one
## k-bucket, and keeps splitting the bucket as more nodes are discovered and
## added. The bucket splits only on the part of the binary tree where our own
## node its id belongs too (same prefix). Resulting eventually in a k-bucket per
## logarithmic distance (log base2 distance). Well, not really, as nodes with
## ids in the closer distance ranges will never be found. And because of this an
## optimisation is done where buckets will also split sometimes even if the
## nodes own id does not have the same prefix (this is to avoid creating highly
## unbalanced branches which would require longer lookups).
##
## Now, some implementations take a more simplified approach. They just create
## directly a bucket for each possible logarithmic distance (e.g. here 1->256).
## Some implementations also don't create buckets with logarithmic distance
## lower than a certain value (e.g. only 1/15th of the highest buckets),
## because the closer to the node (the lower the distance), the less chance
## there is to still find nodes.
##
## The discovery protocol v4 its `FindNode` call will request the k closest
## nodes. As does original Kademlia. This effectively puts the work at the node
## that gets the request. This node will have to check its buckets and gather
## the closest. Some implementations go over all the nodes in all the buckets
## for this (e.g. go-ethereum discovery v4). However, in our bucket splitting
## approach, this search is improved.
##
## In the discovery protocol v5 the `FindNode` call is changed and now the
## logarithmic distance is passed as parameter instead of the NodeId. And only
## nodes that match that logarithmic distance are allowed to be returned.
## This change was made to not put the trust at the requested node for selecting
## the closest nodes. To counter a possible (mistaken) difference in
## implementation, but more importantly for security reasons. See also:
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5-rationale.md#115-guard-against-kademlia-implementation-flaws
##
## The result is that in an implementation which just stores buckets per
## logarithmic distance, it simply needs to return the right bucket. In our
## split-bucket implementation, this cannot be done as such and thus the closest
## neighbours search is still done. And to do this, a reverse calculation of an
## id at given logarithmic distance is needed (which is why there is the
## `idAtDistance` proc). Next, nodes with invalid distances need to be filtered
## out to be compliant to the specification. This can most likely get further
## optimised, but it sounds likely better to switch away from the split-bucket
## approach. I believe that the main benefit it has is improved lookups
## (due to no unbalanced branches), and it looks like this will be negated by
## limiting the returned nodes to only the ones of the requested logarithmic
## distance for the `FindNode` call.

## This `FindNode` change in discovery v5 will also have an effect on the
## efficiency of the network. Work will be moved from the receiver of
## `FindNodes` to the requester. But this also means more network traffic,
## as less nodes will potentially be passed around per `FindNode` call, and thus
## more requests will be needed for a lookup (adding bandwidth and latency).
## This might be a concern for mobile devices.

import
  std/[tables, sets, options, math, sequtils],
  stew/shims/net as stewNet, json_serialization/std/net,
  stew/[byteutils, endians2], chronicles, chronos, stint, bearssl,
  eth/[rlp, keys, async_utils],
  types, encoding, node, routing_table, enr, random2

import nimcrypto except toHex

export options

{.push raises: [Defect].}

logScope:
  topics = "discv5"

const
  alpha = 3 ## Kademlia concurrency factor
  lookupRequestLimit = 3
  findNodeResultLimit = 15 # applies in FINDNODE handler
  maxNodesPerMessage = 3
  lookupInterval = 60.seconds ## Interval of launching a random lookup to
  ## populate the routing table. go-ethereum seems to do 3 runs every 30
  ## minutes. Trinity starts one every minute.
  revalidateMax = 1000 ## Revalidation of a peer is done between 0 and this
  ## value in milliseconds
  handshakeTimeout* = 2.seconds ## timeout for the reply on the
  ## whoareyou message
  responseTimeout* = 4.seconds ## timeout for the response of a request-response
  ## call
  magicSize = 32 ## size of the magic which is the start of the whoareyou
  ## message

type
  Protocol* = ref object
    transp: DatagramTransport
    localNode*: Node
    privateKey: PrivateKey
    bindAddress: Address ## UDP binding address
    whoareyouMagic: array[magicSize, byte]
    idHash: array[32, byte]
    pendingRequests: Table[AuthTag, PendingRequest]
    db: Database
    routingTable: RoutingTable
    codec*: Codec
    awaitedMessages: Table[(NodeId, RequestId), Future[Option[Message]]]
    lookupLoop: Future[void]
    revalidateLoop: Future[void]
    bootstrapRecords*: seq[Record]
    rng*: ref BrHmacDrbgContext

  PendingRequest = object
    node: Node
    message: seq[byte]

  DiscResult*[T] = Result[T, cstring]

proc addNode*(d: Protocol, node: Node): bool =
  ## Add `Node` to discovery routing table.
  ##
  ## Returns false only if `Node` is not eligable for adding (no Address).
  if node.address.isSome():
    # Only add nodes with an address to the routing table
    discard d.routingTable.addNode(node)
    return true

proc addNode*(d: Protocol, r: Record): bool =
  ## Add `Node` from a `Record` to discovery routing table.
  ##
  ## Returns false only if no valid `Node` can be created from the `Record` or
  ## on the conditions of `addNode` from a `Node`.
  let node = newNode(r)
  if node.isOk():
    return d.addNode(node[])

proc addNode*(d: Protocol, enr: EnrUri): bool =
  ## Add `Node` from a ENR URI to discovery routing table.
  ##
  ## Returns false if no valid ENR URI, or on the conditions of `addNode` from
  ## an `Record`.
  var r: Record
  let res = r.fromUri(enr)
  if res:
    return d.addNode(r)

proc getNode*(d: Protocol, id: NodeId): Option[Node] =
  ## Get the node with id from the routing table.
  d.routingTable.getNode(id)

proc randomNodes*(d: Protocol, maxAmount: int): seq[Node] =
  ## Get a `maxAmount` of random nodes from the local routing table.
  d.routingTable.randomNodes(maxAmount)

proc randomNodes*(d: Protocol, maxAmount: int,
    pred: proc(x: Node): bool {.gcsafe, noSideEffect.}): seq[Node] =
  ## Get a `maxAmount` of random nodes from the local routing table with the
  ## `pred` predicate function applied as filter on the nodes selected.
  d.routingTable.randomNodes(maxAmount, pred)

proc randomNodes*(d: Protocol, maxAmount: int,
  enrField: (string, seq[byte])): seq[Node] =
  ## Get a `maxAmount` of random nodes from the local routing table. The
  ## the nodes selected are filtered by provided `enrField`.
  d.randomNodes(maxAmount, proc(x: Node): bool = x.record.contains(enrField))

proc neighbours*(d: Protocol, id: NodeId, k: int = BUCKET_SIZE): seq[Node] =
  ## Return up to k neighbours (closest node ids) of the given node id.
  d.routingTable.neighbours(id, k)

proc nodesDiscovered*(d: Protocol): int {.inline.} = d.routingTable.len

func privKey*(d: Protocol): lent PrivateKey =
  d.privateKey

func getRecord*(d: Protocol): Record =
  ## Get the ENR of the local node.
  d.localNode.record

proc updateRecord*(
    d: Protocol, enrFields: openarray[(string, seq[byte])]): DiscResult[void] =
  ## Update the ENR of the local node with provided `enrFields` k:v pairs.
  let fields = mapIt(enrFields, toFieldPair(it[0], it[1]))
  d.localNode.record.update(d.privateKey, fields)
  # TODO: Would it make sense to actively ping ("broadcast") to all the peers
  # we stored a handshake with in order to get that ENR updated?

proc send(d: Protocol, a: Address, data: seq[byte]) =
  let ta = initTAddress(a.ip, a.port)
  try:
    let f = d.transp.sendTo(ta, data)
    f.callback = proc(data: pointer) {.gcsafe.} =
      if f.failed:
        # Could be `TransportUseClosedError` in case the transport is already
        # closed, or could be `TransportOsError` in case of a socket error.
        # In the latter case this would probably mostly occur if the network
        # interface underneath gets disconnected or similar.
        # TODO: Should this kind of error be propagated upwards? Probably, but
        # it should not stop the process as that would reset the discovery
        # progress in case there is even a small window of no connection.
        # One case that needs this error available upwards is when revalidating
        # nodes. Else the revalidation might end up clearing the routing tabl
        # because of ping failures due to own network connection failure.
        debug "Discovery send failed", msg = f.readError.msg
  except Exception as e:
    # TODO: General exception still being raised from Chronos, but in practice
    # all CatchableErrors should be grabbed by the above `f.failed`.
    if e of Defect:
      raise (ref Defect)(e)
    else: doAssert(false)

proc send(d: Protocol, n: Node, data: seq[byte]) =
  doAssert(n.address.isSome())
  d.send(n.address.get(), data)

proc `xor`[N: static[int], T](a, b: array[N, T]): array[N, T] =
  for i in 0 .. a.high:
    result[i] = a[i] xor b[i]

proc whoareyouMagic(toNode: NodeId): array[magicSize, byte] =
  const prefix = "WHOAREYOU"
  var data: array[prefix.len + sizeof(toNode), byte]
  data[0 .. sizeof(toNode) - 1] = toNode.toByteArrayBE()
  for i, c in prefix: data[sizeof(toNode) + i] = byte(c)
  sha256.digest(data).data

proc isWhoAreYou(d: Protocol, packet: openArray[byte]): bool =
  if packet.len > d.whoareyouMagic.len:
    result = d.whoareyouMagic == packet.toOpenArray(0, magicSize - 1)

proc decodeWhoAreYou(d: Protocol, packet: openArray[byte]):
    Whoareyou {.raises: [RlpError].} =
  result = Whoareyou()
  result[] = rlp.decode(packet.toOpenArray(magicSize, packet.high), WhoareyouObj)

proc sendWhoareyou(d: Protocol, address: Address, toNode: NodeId,
    authTag: AuthTag): DiscResult[void] {.raises: [Exception, Defect].} =
  trace "sending who are you", to = $toNode, toAddress = $address
  let challenge = Whoareyou(authTag: authTag, recordSeq: 0)
  brHmacDrbgGenerate(d.rng[], challenge.idNonce)

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
    # TODO: raises: [Exception], but it shouldn't.
    sleepAsync(handshakeTimeout).addCallback() do(data: pointer):
      # TODO: should we still provide cancellation in case handshake completes
      # correctly?
      d.codec.handshakes.del(key)

    var data = @(whoareyouMagic(toNode))
    data.add(rlp.encode(challenge[]))
    d.send(address, data)
    ok()
  else:
    err("NodeId already has ongoing handshake")

proc sendNodes(d: Protocol, toId: NodeId, toAddr: Address, reqId: RequestId,
    nodes: openarray[Node]) =
  proc sendNodes(d: Protocol, toId: NodeId, toAddr: Address,
      message: NodesMessage, reqId: RequestId) {.nimcall.} =
    let (data, _) = encodePacket(
      d.rng[], d.codec, toId, toAddr,
      encodeMessage(message, reqId), challenge = nil)
    d.send(toAddr, data)

  if nodes.len == 0:
    # In case of 0 nodes, a reply is still needed
    d.sendNodes(toId, toAddr, NodesMessage(total: 1, enrs: @[]), reqId)
    return

  var message: NodesMessage
  # TODO: Do the total calculation based on the max UDP packet size we want to
  # send and the ENR size of all (max 16) nodes.
  # Which UDP packet size to take? 1280? 576?
  message.total = ceil(nodes.len / maxNodesPerMessage).uint32

  for i in 0 ..< nodes.len:
    message.enrs.add(nodes[i].record)
    if message.enrs.len == maxNodesPerMessage:
      d.sendNodes(toId, toAddr, message, reqId)
      message.enrs.setLen(0)

  if message.enrs.len != 0:
    d.sendNodes(toId, toAddr, message, reqId)

proc handlePing(d: Protocol, fromId: NodeId, fromAddr: Address,
    ping: PingMessage, reqId: RequestId) =
  let a = fromAddr
  var pong: PongMessage
  pong.enrSeq = d.localNode.record.seqNum
  pong.ip = case a.ip.family
    of IpAddressFamily.IPv4: @(a.ip.address_v4)
    of IpAddressFamily.IPv6: @(a.ip.address_v6)
  pong.port = a.port.uint16

  let (data, _) = encodePacket(d.rng[], d.codec, fromId, fromAddr,
    encodeMessage(pong, reqId), challenge = nil)

  d.send(fromAddr, data)

proc handleFindNode(d: Protocol, fromId: NodeId, fromAddr: Address,
    fn: FindNodeMessage, reqId: RequestId) =
  if fn.distance == 0:
    d.sendNodes(fromId, fromAddr, reqId, [d.localNode])
  else:
    let distance = min(fn.distance, 256)
    d.sendNodes(fromId, fromAddr, reqId,
      d.routingTable.neighboursAtDistance(distance, seenOnly = true))

proc receive*(d: Protocol, a: Address, packet: openArray[byte]) {.gcsafe,
  raises: [
    Defect,
    # This just comes now from a future.complete() and `sendWhoareyou` which
    # has it because of `sleepAsync` with `addCallback`, but practically, no
    # CatchableError should be raised here, we just can't enforce it for now.
    Exception
  ].} =
  if packet.len < tagSize: # or magicSize, can be either
    return # Invalid packet

  # debug "Packet received: ", length = packet.len

  if d.isWhoAreYou(packet):
    trace "Received whoareyou", localNode = $d.localNode, address = a
    var whoareyou: WhoAreYou
    try:
      whoareyou = d.decodeWhoAreYou(packet)
    except RlpError:
      debug "Invalid WhoAreYou packet, decoding failed"
      return

    var pr: PendingRequest
    if d.pendingRequests.take(whoareyou.authTag, pr):
      let toNode = pr.node
      whoareyou.pubKey = toNode.pubkey # TODO: Yeah, rather ugly this.
      doAssert(toNode.address.isSome())
      let (data, _) = encodePacket(d.rng[], d.codec, toNode.id, toNode.address.get(),
        pr.message, challenge = whoareyou)
      d.send(toNode, data)
    else:
      debug "Timed out or unrequested WhoAreYou packet"

  else:
    var tag: array[tagSize, byte]
    tag[0 .. ^1] = packet.toOpenArray(0, tagSize - 1)
    let senderData = tag xor d.idHash
    let sender = readUintBE[256](senderData)

    var authTag: AuthTag
    var node: Node
    let decoded = d.codec.decodePacket(sender, a, packet, authTag, node)
    if decoded.isOk:
      let message = decoded[]
      if not node.isNil:
        # Not filling table with nodes without correct IP in the ENR
        # TODO: Should we care about this???
        if node.address.isSome() and a == node.address.get():
          debug "Adding new node to routing table", node = $node,
            localNode = $d.localNode
          discard d.addNode(node)

      case message.kind
      of ping:
        d.handlePing(sender, a, message.ping, message.reqId)
      of findNode:
        d.handleFindNode(sender, a, message.findNode, message.reqId)
      else:
        var waiter: Future[Option[Message]]
        if d.awaitedMessages.take((sender, message.reqId), waiter):
          waiter.complete(some(message)) # TODO: raises: [Exception]
        else:
          trace "Timed out or unrequested message", message = message.kind,
            origin = a
    elif decoded.error == DecodeError.DecryptError:
      trace "Could not decrypt packet, respond with whoareyou",
        localNode = $d.localNode, address = a
      # only sendingWhoareyou in case it is a decryption failure
      let res = d.sendWhoareyou(a, sender, authTag)
      if res.isErr():
        trace "Sending WhoAreYou packet failed", err = res.error
    elif decoded.error == DecodeError.UnsupportedMessage:
      # Still adding the node in case failure is because of unsupported message.
      if not node.isNil:
        # Not filling table with nodes without correct IP in the ENR
        # TODO: Should we care about this???s
        if node.address.isSome() and a == node.address.get():
          debug "Adding new node to routing table", node = $node,
            localNode = $d.localNode
          discard d.addNode(node)
    # elif decoded.error == DecodeError.PacketError:
      # Not adding this node as from our perspective it is sending rubbish.

# TODO: Not sure why but need to pop the raises here as it is apparently not
# enough to put it in the raises pragma of `processClient` and other async procs.
{.pop.}
# Next, below there is no more effort done in catching the general `Exception`
# as async procs always require `Exception` in the raises pragma, see also:
# https://github.com/status-im/nim-chronos/issues/98
# So I don't bother for now and just add them in the raises pragma until this
# gets fixed. It does not mean that we expect these calls to be raising
# CatchableErrors, in fact, we really don't, but hey, they might, considering we
# can't enforce it.
proc processClient(transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async, gcsafe, raises: [Exception, Defect].} =
  let proto = getUserData[Protocol](transp)

  # TODO: should we use `peekMessage()` to avoid allocation?
  # TODO: This can still raise general `Exception` while it probably should
  # only give TransportOsError.
  let buf = try: transp.getMessage()
            except TransportOsError as e:
              # This is likely to be local network connection issues.
              error "Transport getMessage", exception = e.name, msg = e.msg
              return
            except Exception as e:
              if e of Defect:
                raise (ref Defect)(e)
              else: doAssert(false)
              return # Make compiler happy

  let ip = try: raddr.address()
           except ValueError as e:
             error "Not a valid IpAddress", exception = e.name, msg = e.msg
             return
  let a = Address(ip: ValidIpAddress.init(ip), port: raddr.port)

  try:
    proto.receive(a, buf)
  except Exception as e:
    if e of Defect:
      raise (ref Defect)(e)
    else: doAssert(false)

proc validIp(sender, address: IpAddress): bool {.raises: [Defect].} =
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

proc replaceNode(d: Protocol, n: Node) =
  if n.record notin d.bootstrapRecords:
    d.routingTable.replaceNode(n)
      # Remove shared secrets when removing the node from routing table.
      # TODO: This might be to direct, so we could keep these longer. But better
      # would be to simply not remove the nodes immediatly but use an LRU cache.
      # Also because some shared secrets will be with nodes not eligable for
      # the routing table, and these don't get deleted now, see issue:
      # https://github.com/status-im/nim-eth/issues/242
    discard d.codec.db.deleteKeys(n.id, n.address.get())
  else:
    # For now we never remove bootstrap nodes. It might make sense to actually
    # do so and to retry them only in case we drop to a really low amount of
    # peers in the routing table.
    debug "Message request to bootstrap node failed", enr = toURI(n.record)

# TODO: This could be improved to do the clean-up immediatily in case a non
# whoareyou response does arrive, but we would need to store the AuthTag
# somewhere
proc registerRequest(d: Protocol, n: Node, message: seq[byte], nonce: AuthTag)
    {.raises: [Exception, Defect].} =
  let request = PendingRequest(node: n, message: message)
  if not d.pendingRequests.hasKeyOrPut(nonce, request):
    # TODO: raises: [Exception]
    sleepAsync(responseTimeout).addCallback() do(data: pointer):
      d.pendingRequests.del(nonce)

proc waitMessage(d: Protocol, fromNode: Node, reqId: RequestId):
    Future[Option[Message]] {.raises: [Exception, Defect].} =
  result = newFuture[Option[Message]]("waitMessage")
  let res = result
  let key = (fromNode.id, reqId)
  # TODO: raises: [Exception]
  sleepAsync(responseTimeout).addCallback() do(data: pointer):
    d.awaitedMessages.del(key)
    if not res.finished:
      res.complete(none(Message)) # TODO: raises: [Exception]
  d.awaitedMessages[key] = result

proc addNodesFromENRs(result: var seq[Node], enrs: openarray[Record])
    {.raises: [Defect].} =
  for r in enrs:
    let node = newNode(r)
    if node.isOk():
      result.add(node[])

proc waitNodes(d: Protocol, fromNode: Node, reqId: RequestId):
    Future[DiscResult[seq[Node]]] {.async, raises: [Exception, Defect].} =
  var op = await d.waitMessage(fromNode, reqId)
  if op.isSome and op.get.kind == nodes:
    var res = newSeq[Node]()
    res.addNodesFromENRs(op.get.nodes.enrs)
    let total = op.get.nodes.total
    for i in 1 ..< total:
      op = await d.waitMessage(fromNode, reqId)
      if op.isSome and op.get.kind == nodes:
        res.addNodesFromENRs(op.get.nodes.enrs)
      else:
        # No error on this as we received some nodes.
        break
    return ok(res)
  else:
    return err("Nodes message not received in time")

proc sendMessage*[T: SomeMessage](d: Protocol, toNode: Node, m: T):
    RequestId {.raises: [Exception, Defect].} =
  doAssert(toNode.address.isSome())
  let
    reqId = RequestId.init(d.rng[])
    message = encodeMessage(m, reqId)
    (data, nonce) = encodePacket(d.rng[], d.codec, toNode.id, toNode.address.get(),
      message, challenge = nil)
  d.registerRequest(toNode, message, nonce)
  d.send(toNode, data)
  return reqId

proc ping*(d: Protocol, toNode: Node):
    Future[DiscResult[PongMessage]] {.async, raises: [Exception, Defect].} =
  ## Send a discovery ping message.
  ##
  ## Returns the received pong message or an error.
  let reqId = d.sendMessage(toNode,
    PingMessage(enrSeq: d.localNode.record.seqNum))
  let resp = await d.waitMessage(toNode, reqId)

  if resp.isSome() and resp.get().kind == pong:
    d.routingTable.setJustSeen(toNode)
    return ok(resp.get().pong)
  else:
    d.replaceNode(toNode)
    return err("Pong message not received in time")

proc findNode*(d: Protocol, toNode: Node, distance: uint32):
    Future[DiscResult[seq[Node]]] {.async, raises: [Exception, Defect].} =
  ## Send a discovery findNode message.
  ##
  ## Returns the received nodes or an error.
  ## Received ENRs are already validated and converted to `Node`.
  let reqId = d.sendMessage(toNode, FindNodeMessage(distance: distance))
  let nodes = await d.waitNodes(toNode, reqId)

  if nodes.isOk:
    var res = newSeq[Node]()
    for n in nodes[]:
      # Check if the node has an address and if the address is public or from
      # the same local network or lo network as the sender. The latter allows
      # for local testing.
      # Any port is allowed, also the so called "well-known" ports.
      if n.address.isSome() and
          validIp(toNode.address.get().ip, n.address.get().ip):
        res.add(n)

    d.routingTable.setJustSeen(toNode)
    return ok(res)
  else:
    d.replaceNode(toNode)
    return err(nodes.error)

proc lookupDistances(target, dest: NodeId): seq[uint32] {.raises: [Defect].} =
  let td = logDist(target, dest)
  result.add(td)
  var i = 1'u32
  while result.len < lookupRequestLimit:
    if td + i < 256:
      result.add(td + i)
    if td - i > 0'u32:
      result.add(td - i)
    inc i

proc lookupWorker(d: Protocol, destNode: Node, target: NodeId):
    Future[seq[Node]] {.async, raises: [Exception, Defect].} =
  let dists = lookupDistances(target, destNode.id)
  var i = 0
  while i < lookupRequestLimit and result.len < findNodeResultLimit:
    let r = await d.findNode(destNode, dists[i])
    # TODO: Handle failures better. E.g. stop on different failures than timeout
    if r.isOk:
      # TODO: I guess it makes sense to limit here also to `findNodeResultLimit`?
      result.add(r[])
    inc i

  for n in result:
    discard d.routingTable.addNode(n)

proc lookup*(d: Protocol, target: NodeId): Future[seq[Node]]
    {.async, raises: [Exception, Defect].} =
  ## Perform a lookup for the given target, return the closest n nodes to the
  ## target. Maximum value for n is `BUCKET_SIZE`.
  # TODO: Sort the returned nodes on distance
  # Also use unseen nodes as a form of validation.
  result = d.routingTable.neighbours(target, BUCKET_SIZE, seenOnly = false)
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
    {.async, raises:[Exception, Defect].} =
  ## Perform a lookup for a random target, return the closest n nodes to the
  ## target. Maximum value for n is `BUCKET_SIZE`.
  var id: NodeId
  var buf: array[sizeof(id), byte]
  brHmacDrbgGenerate(d.rng[], buf)
  copyMem(addr id, addr buf[0], sizeof(id))

  return await d.lookup(id)

proc resolve*(d: Protocol, id: NodeId): Future[Option[Node]]
    {.async, raises: [Exception, Defect].} =
  ## Resolve a `Node` based on provided `NodeId`.
  ##
  ## This will first look in the own DHT. If the node is known, it will try to
  ## contact if for newer information. If node is not known or it does not
  ## reply, a lookup is done to see if it can find a (newer) record of the node
  ## on the network.

  let node = d.getNode(id)
  if node.isSome():
    let request = await d.findNode(node.get(), 0)

    # TODO: Handle failures better. E.g. stop on different failures than timeout
    if request.isOk() and request[].len > 0:
      return some(request[][0])

  let discovered = await d.lookup(id)
  for n in discovered:
    if n.id == id:
      # TODO: Not getting any new seqNum here as in a lookup nodes in table with
      # new seqNum don't get replaced.
      if node.isSome() and node.get().record.seqNum >= n.record.seqNum:
        return node
      else:
        return some(n)

  return node

proc revalidateNode*(d: Protocol, n: Node)
    {.async, raises: [Exception, Defect].} = # TODO: Exception
  let pong = await d.ping(n)

  if pong.isOK():
    if pong.get().enrSeq > n.record.seqNum:
      # TODO: Request new ENR
      discard

proc revalidateLoop(d: Protocol) {.async, raises: [Exception, Defect].} =
  # TODO: General Exception raised.
  try:
    while true:
      await sleepAsync(d.rng[].rand(revalidateMax).milliseconds)
      let n = d.routingTable.nodeToRevalidate()
      if not n.isNil:
        traceAsyncErrors d.revalidateNode(n)
  except CancelledError:
    trace "revalidateLoop canceled"

proc lookupLoop(d: Protocol) {.async, raises: [Exception, Defect].} =
  # TODO: General Exception raised.
  try:
    # lookup self (neighbour nodes)
    let selfLookup = await d.lookup(d.localNode.id)
    trace "Discovered nodes in self lookup", nodes = $selfLookup
    while true:
      let randomLookup = await d.lookupRandom()
      trace "Discovered nodes in random lookup", nodes = $randomLookup
      trace "Total nodes in routing table", total = d.routingTable.len()
      await sleepAsync(lookupInterval)
  except CancelledError:
    trace "lookupLoop canceled"

proc newProtocol*(privKey: PrivateKey, db: Database,
                  externalIp: Option[ValidIpAddress], tcpPort, udpPort: Port,
                  localEnrFields: openarray[(string, seq[byte])] = [],
                  bootstrapRecords: openarray[Record] = [],
                  previousRecord = none[enr.Record](),
                  bindIp = IPv4_any(), rng = newRng()):
                  Protocol {.raises: [Defect].} =
  # TODO: Tried adding bindPort = udpPort as parameter but that gave
  # "Error: internal error: environment misses: udpPort" in nim-beacon-chain.
  # Anyhow, nim-beacon-chain would also require some changes to support port
  # remapping through NAT and this API is also subject to change once we
  # introduce support for ipv4 + ipv6 binding/listening.
  let extraFields = mapIt(localEnrFields, toFieldPair(it[0], it[1]))
  # TODO:
  # - Defect as is now or return a result for enr errors?
  # - In case incorrect key, allow for new enr based on new key (new node id)?
  var record: Record
  if previousRecord.isSome():
    record = previousRecord.get()
    record.update(privKey, externalIp, tcpPort, udpPort,
      extraFields).expect("Record within size limits and correct key")
  else:
    record = enr.Record.init(1, privKey, externalIp, tcpPort, udpPort,
     extraFields).expect("Record within size limits")
  let node = newNode(record).expect("Properly initialized record")

  # TODO Consider whether this should be a Defect
  doAssert rng != nil, "RNG initialization failed"

  result = Protocol(
    privateKey: privKey,
    db: db,
    localNode: node,
    bindAddress: Address(ip: ValidIpAddress.init(bindIp), port: udpPort),
    whoareyouMagic: whoareyouMagic(node.id),
    idHash: sha256.digest(node.id.toByteArrayBE).data,
    codec: Codec(localNode: node, privKey: privKey, db: db),
    bootstrapRecords: @bootstrapRecords,
    rng: rng)

  result.routingTable.init(node, 5, rng)

proc open*(d: Protocol) {.raises: [Exception, Defect].} =
  info "Starting discovery node", node = $d.localNode,
    uri = toURI(d.localNode.record), bindAddress = d.bindAddress
  # TODO allow binding to specific IP / IPv6 / etc
  let ta = initTAddress(d.bindAddress.ip, d.bindAddress.port)
  # TODO: raises `OSError` and `IOSelectorsException`, the latter which is
  # object of Exception. In Nim devel this got changed to CatchableError.
  d.transp = newDatagramTransport(processClient, udata = d, local = ta)

  for record in d.bootstrapRecords:
    debug "Adding bootstrap node", uri = toURI(record)
    discard d.addNode(record)

proc start*(d: Protocol) {.raises: [Exception, Defect].} =
  d.lookupLoop = lookupLoop(d)
  d.revalidateLoop = revalidateLoop(d)

proc close*(d: Protocol) {.raises: [Exception, Defect].} =
  doAssert(not d.transp.closed)

  debug "Closing discovery node", node = $d.localNode
  if not d.revalidateLoop.isNil:
    d.revalidateLoop.cancel()
  if not d.lookupLoop.isNil:
    d.lookupLoop.cancel()

  d.transp.close()

proc closeWait*(d: Protocol) {.async, raises: [Exception, Defect].} =
  doAssert(not d.transp.closed)

  debug "Closing discovery node", node = $d.localNode
  if not d.revalidateLoop.isNil:
    await d.revalidateLoop.cancelAndWait()
  if not d.lookupLoop.isNil:
    await d.lookupLoop.cancelAndWait()

  await d.transp.closeWait()
