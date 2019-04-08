#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import
  tables, hashes, times, algorithm, sets, sequtils, random,
  chronos, eth/keys, chronicles, stint, nimcrypto,
  enode

export sets # TODO: This should not be needed, but compilation fails otherwise

logScope:
  topics = "kademlia"

type
  KademliaProtocol* [Wire] = ref object
    wire: Wire
    thisNode: Node
    routing: RoutingTable
    pongFutures: Table[seq[byte], Future[bool]]
    pingFutures: Table[Node, Future[bool]]
    neighboursCallbacks: Table[Node, proc(n: seq[Node]) {.gcsafe.}]

  NodeId* = UInt256

  Node* = ref object
    node*: ENode
    id*: NodeId

  RoutingTable = object
    thisNode: Node
    buckets: seq[KBucket]

  KBucket = ref object
    istart, iend: UInt256
    nodes: seq[Node]
    replacementCache: seq[Node]
    lastUpdated: float # epochTime

const
  BUCKET_SIZE = 16
  BITS_PER_HOP = 8
  REQUEST_TIMEOUT = 900                 # timeout of message round trips
  FIND_CONCURRENCY = 3                  # parallel find node lookups
  ID_SIZE = 256

proc toNodeId*(pk: PublicKey): NodeId =
  readUintBE[256](keccak256.digest(pk.getRaw()).data)

proc newNode*(pk: PublicKey, address: Address): Node =
  result.new()
  result.node = initENode(pk, address)
  result.id = pk.toNodeId()

proc newNode*(uriString: string): Node =
  result.new()
  result.node = initENode(uriString)
  result.id = result.node.pubkey.toNodeId()

proc newNode*(enode: ENode): Node =
  result.new()
  result.node = enode
  result.id = result.node.pubkey.toNodeId()

proc distanceTo(n: Node, id: NodeId): UInt256 = n.id xor id

proc `$`*(n: Node): string =
  if n == nil:
    "Node[local]"
  else:
    "Node[" & $n.node.address.ip & ":" & $n.node.address.udpPort & "]"

proc hash*(n: Node): hashes.Hash = hash(n.node.pubkey.data)
proc `==`*(a, b: Node): bool = (a.isNil and b.isNil) or (not a.isNil and not b.isNil and a.node.pubkey == b.node.pubkey)

proc newKBucket(istart, iend: NodeId): KBucket =
  result.new()
  result.istart = istart
  result.iend = iend
  result.nodes = @[]
  result.replacementCache = @[]

proc midpoint(k: KBucket): NodeId =
  k.istart + (k.iend - k.istart) div 2.u256

proc distanceTo(k: KBucket, id: NodeId): UInt256 = k.midpoint xor id
proc nodesByDistanceTo(k: KBucket, id: NodeId): seq[Node] =
  sortedByIt(k.nodes, it.distanceTo(id))

proc len(k: KBucket): int {.inline.} = k.nodes.len
proc head(k: KBucket): Node {.inline.} = k.nodes[0]

proc add(k: KBucket, n: Node): Node =
  ## Try to add the given node to this bucket.

  ## If the node is already present, it is moved to the tail of the list, and we return None.

  ## If the node is not already present and the bucket has fewer than k entries, it is inserted
  ## at the tail of the list, and we return None.

  ## If the bucket is full, we add the node to the bucket's replacement cache and return the
  ## node at the head of the list (i.e. the least recently seen), which should be evicted if it
  ## fails to respond to a ping.
  k.lastUpdated = epochTime()
  let nodeIdx = k.nodes.find(n)
  if nodeIdx != -1:
      k.nodes.delete(nodeIdx)
      k.nodes.add(n)
  elif k.len < BUCKET_SIZE:
      k.nodes.add(n)
  else:
      k.replacementCache.add(n)
      return k.head
  return nil

proc removeNode(k: KBucket, n: Node) =
  let i = k.nodes.find(n)
  if i != -1: k.nodes.delete(i)

proc split(k: KBucket): tuple[lower, upper: KBucket] =
  ## Split at the median id
  let splitid = k.midpoint
  result.lower = newKBucket(k.istart, splitid)
  result.upper = newKBucket(splitid + 1.u256, k.iend)
  for node in k.nodes:
    let bucket = if node.id <= splitid: result.lower else: result.upper
    discard bucket.add(node)
  for node in k.replacementCache:
    let bucket = if node.id <= splitid: result.lower else: result.upper
    bucket.replacementCache.add(node)

proc inRange(k: KBucket, n: Node): bool {.inline.} =
  k.istart <= n.id and n.id <= k.iend

proc isFull(k: KBucket): bool = k.len == BUCKET_SIZE

proc contains(k: KBucket, n: Node): bool = n in k.nodes

proc binaryGetBucketForNode(buckets: openarray[KBucket],
                            n: Node): KBucket {.inline.} =
  ## Given a list of ordered buckets, returns the bucket for a given node.
  let bucketPos = lowerBound(buckets, n.id) do(a: KBucket, b: NodeId) -> int:
    cmp(a.iend, b)
  # Prevents edge cases where bisect_left returns an out of range index
  if bucketPos < buckets.len:
    let bucket = buckets[bucketPos]
    if bucket.istart <= n.id and n.id <= bucket.iend:
      result = bucket

  if result.isNil:
    raise newException(ValueError, "No bucket found for node with id " & $n.id)

proc computeSharedPrefixBits(nodes: openarray[Node]): int =
  ## Count the number of prefix bits shared by all nodes.
  if nodes.len < 2:
    return ID_SIZE

  var mask = zero(UInt256)
  let one = one(UInt256)

  for i in 1 .. ID_SIZE:
    mask = mask or (one shl (ID_SIZE - i))
    let reference = nodes[0].id and mask
    for j in 1 .. nodes.high:
      if (nodes[j].id and mask) != reference: return i - 1

  doAssert(false, "Unable to calculate number of shared prefix bits")

proc init(r: var RoutingTable, thisNode: Node) {.inline.} =
  r.thisNode = thisNode
  r.buckets = @[newKBucket(0.u256, high(Uint256))]

proc splitBucket(r: var RoutingTable, index: int) =
  let bucket = r.buckets[index]
  let (a, b) = bucket.split()
  r.buckets[index] = a
  r.buckets.insert(b, index + 1)

proc bucketForNode(r: RoutingTable, n: Node): KBucket =
  binaryGetBucketForNode(r.buckets, n)

proc removeNode(r: var RoutingTable, n: Node) =
  r.bucketForNode(n).removeNode(n)

proc addNode(r: var RoutingTable, n: Node): Node =
  doAssert(n != r.thisNode)
  let bucket = r.bucketForNode(n)
  let evictionCandidate = bucket.add(n)
  if not evictionCandidate.isNil:
    # Split if the bucket has the local node in its range or if the depth is not congruent
    # to 0 mod BITS_PER_HOP

    let depth = computeSharedPrefixBits(bucket.nodes)
    if bucket.inRange(r.thisNode) or (depth mod BITS_PER_HOP != 0 and depth != ID_SIZE):
      r.splitBucket(r.buckets.find(bucket))
      return r.addNode(n) # retry

    # Nothing added, ping evictionCandidate
    return evictionCandidate

proc contains(r: RoutingTable, n: Node): bool = n in r.bucketForNode(n)

proc bucketsByDistanceTo(r: RoutingTable, id: NodeId): seq[KBucket] =
  sortedByIt(r.buckets, it.distanceTo(id))

proc notFullBuckets(r: RoutingTable): seq[KBucket] =
  r.buckets.filterIt(not it.isFull)

proc neighbours(r: RoutingTable, id: NodeId, k: int = BUCKET_SIZE): seq[Node] =
  ## Return up to k neighbours of the given node.
  result = newSeqOfCap[Node](k * 2)
  for bucket in r.bucketsByDistanceTo(id):
    for n in bucket.nodesByDistanceTo(id):
      if n.id != id:
        result.add(n)
        if result.len == k * 2:
          break
  result = sortedByIt(result, it.distanceTo(id))
  if result.len > k:
    result.setLen(k)

proc len(r: RoutingTable): int =
  for b in r.buckets: result += b.len

proc newKademliaProtocol*[Wire](thisNode: Node,
                                wire: Wire): KademliaProtocol[Wire] =
  result.new()
  result.thisNode = thisNode
  result.wire = wire
  result.pongFutures = initTable[seq[byte], Future[bool]]()
  result.pingFutures = initTable[Node, Future[bool]]()
  result.neighboursCallbacks = initTable[Node, proc(n: seq[Node])]()
  result.routing.init(thisNode)

proc bond(k: KademliaProtocol, n: Node): Future[bool] {.async.}

proc updateRoutingTable(k: KademliaProtocol, n: Node) =
  ## Update the routing table entry for the given node.
  let evictionCandidate = k.routing.addNode(n)
  if not evictionCandidate.isNil:
      # This means we couldn't add the node because its bucket is full, so schedule a bond()
      # with the least recently seen node on that bucket. If the bonding fails the node will
      # be removed from the bucket and a new one will be picked from the bucket's
      # replacement cache.
      asyncCheck k.bond(evictionCandidate)

proc doSleep(p: proc()) {.async.} =
  await sleepAsync(REQUEST_TIMEOUT)
  p()

template onTimeout(b: untyped) =
  asyncCheck doSleep() do():
    b

proc pingId(n: Node, token: seq[byte]): seq[byte] {.inline.} =
  result = token & @(n.node.pubkey.data)

proc waitPong(k: KademliaProtocol, n: Node, pingid: seq[byte]): Future[bool] =
  doAssert(pingid notin k.pongFutures, "Already waiting for pong from " & $n)
  result = newFuture[bool]("waitPong")
  let fut = result
  k.pongFutures[pingid] = result
  onTimeout:
    if not fut.finished:
      k.pongFutures.del(pingid)
      fut.complete(false)

proc ping(k: KademliaProtocol, n: Node): seq[byte] =
  doAssert(n != k.thisNode)
  result = k.wire.sendPing(n)

proc waitPing(k: KademliaProtocol, n: Node): Future[bool] =
  result = newFuture[bool]("waitPing")
  doAssert(n notin k.pingFutures)
  k.pingFutures[n] = result
  let fut = result
  onTimeout:
    if not fut.finished:
      k.pingFutures.del(n)
      fut.complete(false)

proc waitNeighbours(k: KademliaProtocol, remote: Node): Future[seq[Node]] =
  doAssert(remote notin k.neighboursCallbacks)
  result = newFuture[seq[Node]]("waitNeighbours")
  let fut = result
  var neighbours = newSeqOfCap[Node](BUCKET_SIZE)
  k.neighboursCallbacks[remote] = proc(n: seq[Node]) =
    # This callback is expected to be called multiple times because nodes usually
    # split the neighbours replies into multiple packets, so we only complete the
    # future event.set() we've received enough neighbours.

    for i in n:
      if i != k.thisNode:
        neighbours.add(i)
        if neighbours.len == BUCKET_SIZE:
          k.neighboursCallbacks.del(remote)
          doAssert(not fut.finished)
          fut.complete(neighbours)

  onTimeout:
    if not fut.finished:
      k.neighboursCallbacks.del(remote)
      fut.complete(neighbours)

proc populateNotFullBuckets(k: KademliaProtocol) =
  ## Go through all buckets that are not full and try to fill them.
  ##
  ## For every node in the replacement cache of every non-full bucket, try to bond.
  ## When the bonding succeeds the node is automatically added to the bucket.
  for bucket in k.routing.notFullBuckets:
    for node in bucket.replacementCache:
      asyncCheck k.bond(node)

proc bond(k: KademliaProtocol, n: Node): Future[bool] {.async.} =
  ## Bond with the given node.
  ##
  ## Bonding consists of pinging the node, waiting for a pong and maybe a ping as well.
  ## It is necessary to do this at least once before we send findNode requests to a node.
  trace "Bonding to peer", n
  if n in k.routing:
    return true

  let pid = pingId(n, k.ping(n))
  if pid in k.pongFutures:
    debug "Bonding failed, already waiting for pong", n
    return false

  let gotPong = await k.waitPong(n, pid)
  if not gotPong:
    debug "Bonding failed, didn't receive pong from", n
    # Drop the failing node and schedule a populateNotFullBuckets() call to try and
    # fill its spot.
    k.routing.removeNode(n)
    k.populateNotFullBuckets()
    return false

  # Give the remote node a chance to ping us before we move on and start sending findNode
  # requests. It is ok for waitPing() to timeout and return false here as that just means
  # the remote remembers us.
  if n in k.pingFutures:
    debug "Bonding failed, already waiting for ping", n
    return false

  discard await k.waitPing(n)

  trace "Bonding completed successfully", n
  k.updateRoutingTable(n)
  return true

proc sortByDistance(nodes: var seq[Node], nodeId: NodeId, maxResults = 0) =
  nodes = nodes.sortedByIt(it.distanceTo(nodeId))
  if maxResults != 0 and nodes.len > maxResults:
    nodes.setLen(maxResults)

proc lookup*(k: KademliaProtocol, nodeId: NodeId): Future[seq[Node]] {.async.} =
  ## Lookup performs a network search for nodes close to the given target.

  ## It approaches the target by querying nodes that are closer to it on each iteration.  The
  ## given target does not need to be an actual node identifier.
  var nodesAsked = initSet[Node]()
  var nodesSeen = initSet[Node]()

  proc findNode(nodeId: NodeId, remote: Node): Future[seq[Node]] {.async.} =
    k.wire.sendFindNode(remote, nodeId)
    var candidates = await k.waitNeighbours(remote)
    if candidates.len == 0:
      trace "Got no candidates from peer, returning", peer = remote
      result = candidates
    else:
      # The following line:
      # 1. Add new candidates to nodesSeen so that we don't attempt to bond with failing ones
      # in the future
      # 2. Removes all previously seen nodes from candidates
      # 3. Deduplicates candidates
      candidates.keepItIf(not nodesSeen.containsOrIncl(it))
      trace "Got new candidates", count = candidates.len
      let bonded = await all(candidates.mapIt(k.bond(it)))
      for i in 0 ..< bonded.len:
        if not bonded[i]: candidates[i] = nil
      candidates.keepItIf(not it.isNil)
      trace "Bonded with candidates", count = candidates.len
      result = candidates

  proc excludeIfAsked(nodes: seq[Node]): seq[Node] =
    result = toSeq(items(nodes.toSet() - nodesAsked))
    sortByDistance(result, nodeId, FIND_CONCURRENCY)

  var closest = k.routing.neighbours(nodeId)
  trace "Starting lookup; initial neighbours: ", closest
  var nodesToAsk = excludeIfAsked(closest)
  while nodesToAsk.len != 0:
    trace "Node lookup; querying ", nodesToAsk
    nodesAsked.incl(nodesToAsk.toSet())
    let results = await all(nodesToAsk.mapIt(findNode(nodeId, it)))
    for candidates in results:
      closest.add(candidates)
    sortByDistance(closest, nodeId, BUCKET_SIZE)
    nodesToAsk = excludeIfAsked(closest)

  trace "Kademlia lookup finished", target = nodeId.toHex, closest
  result = closest

proc lookupRandom*(k: KademliaProtocol): Future[seq[Node]] =
  var id: NodeId
  discard randomBytes(addr id, id.sizeof)
  k.lookup(id)

proc resolve*(k: KademliaProtocol, id: NodeId): Future[Node] {.async.} =
  let closest = await k.lookup(id)
  for n in closest:
    if n.id == id: return n

proc bootstrap*(k: KademliaProtocol, bootstrapNodes: seq[Node], retries = 0) {.async.} =
  ## Bond with bootstrap nodes and do initial lookup. Retry `retries` times
  ## in case of failure, or indefinitely if `retries` is 0.
  var numTries = 0
  while true:
    let bonded = await all(bootstrapNodes.mapIt(k.bond(it)))
    if true notin bonded:
      info "Failed to bond with bootstrap nodes"
      inc numTries
      if retries == 0 or numTries < retries:
        info "Retrying"
      else:
        return
    else:
      break
  discard await k.lookupRandom()

proc recvPong*(k: KademliaProtocol, n: Node, token: seq[byte]) =
  trace "<<< pong from ", n
  let pingid = token & @(n.node.pubkey.data)
  var future: Future[bool]
  if k.pongFutures.take(pingid, future):
    future.complete(true)

proc recvPing*(k: KademliaProtocol, n: Node, msgHash: any) =
  trace "<<< ping from ", n
  k.updateRoutingTable(n)
  k.wire.sendPong(n, msgHash)

  var future: Future[bool]
  if k.pingFutures.take(n, future):
    future.complete(true)

proc recvNeighbours*(k: KademliaProtocol, remote: Node, neighbours: seq[Node]) =
  ## Process a neighbours response.
  ##
  ## Neighbours responses should only be received as a reply to a find_node, and that is only
  ## done as part of node lookup, so the actual processing is left to the callback from
  ## neighbours_callbacks, which is added (and removed after it's done or timed out) in
  ## wait_neighbours().
  trace "Received neighbours", remote, neighbours
  let cb = k.neighboursCallbacks.getOrDefault(remote)
  if not cb.isNil:
    cb(neighbours)
  else:
    trace "Unexpected neighbours, probably came too late", remote

proc recvFindNode*(k: KademliaProtocol, remote: Node, nodeId: NodeId) =
  if remote notin k.routing:
    # FIXME: This is not correct; a node we've bonded before may have become unavailable
    # and thus removed from self.routing, but once it's back online we should accept
    # find_nodes from them.
    trace "Ignoring find_node request from unknown node ", remote
    return
  k.updateRoutingTable(remote)
  var found = k.routing.neighbours(nodeId)
  found.sort() do(x, y: Node) -> int: cmp(x.id, y.id)
  k.wire.sendNeighbours(remote, found)

proc randomNodes*(k: KademliaProtocol, count: int): seq[Node] =
  var count = count
  let sz = k.routing.len
  if count > sz:
    debug  "Looking for peers", requested = count, present = sz
    count = sz

  result = newSeqOfCap[Node](count)
  var seen = initSet[Node]()

  # This is a rather inneficient way of randomizing nodes from all buckets, but even if we
  # iterate over all nodes in the routing table, the time it takes would still be
  # insignificant compared to the time it takes for the network roundtrips when connecting
  # to nodes.
  while len(seen) < count:
    let bucket = k.routing.buckets.rand()
    if bucket.nodes.len != 0:
      let node = bucket.nodes.rand()
      if node notin seen:
        result.add(node)
        seen.incl(node)

proc nodesDiscovered*(k: KademliaProtocol): int {.inline.} = k.routing.len

when isMainModule:
  proc randomNode(): Node =
    newNode("enode://aa36fdf33dd030378a0168efe6ed7d5cc587fafa3cdd375854fe735a2e11ea3650ba29644e2db48368c46e1f60e716300ba49396cd63778bf8a818c09bded46f@13.93.211.84:30303")

  var nodes = @[randomNode()]
  doAssert(computeSharedPrefixBits(nodes) == ID_SIZE)
  nodes.add(randomNode())
  nodes[0].id = 0b1.u256
  nodes[1].id = 0b0.u256
  doAssert(computeSharedPrefixBits(nodes) == ID_SIZE - 1)

  nodes[0].id = 0b010.u256
  nodes[1].id = 0b110.u256
  doAssert(computeSharedPrefixBits(nodes) == ID_SIZE - 3)
