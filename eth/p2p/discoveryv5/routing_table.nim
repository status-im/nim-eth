import
  std/[algorithm, times, sequtils, bitops, random, sets, options],
  stint, chronicles,
  node

{.push raises: [Defect].}

type
  RoutingTable* = object
    thisNode: Node
    buckets: seq[KBucket]

  KBucket = ref object
    istart, iend: NodeId ## Range of NodeIds this KBucket covers. This is not a
    ## simple logarithmic distance as buckets can be split over a prefix that
    ## does not cover the `thisNode` id.
    nodes: seq[Node] ## Node entries of the KBucket. Sorted according to last
    ## time seen. First entry (head) is considered the most recently seen node
    ## and the last entry (tail) is considered the least recently seen node.
    ## Here "seen" means a successful request-response. This can also not have
    ## occured yet.
    replacementCache: seq[Node] ## Nodes that could not be added to the `nodes`
    ## seq as it is full and without stale nodes.
    lastUpdated: float ## epochTime of last update to the KBucket
    # TODO: Should this update be about changes made only in `nodes`?

const
  BUCKET_SIZE* = 16
  REPLACEMENT_CACHE_SIZE* = 8
  BITS_PER_HOP = 8
  ID_SIZE = 256

proc distanceTo(n: Node, id: NodeId): UInt256 =
  ## Calculate the distance to a NodeId.
  n.id xor id

proc logDist*(a, b: NodeId): uint32 =
  ## Calculate the logarithmic distance between two `NodeId`s.
  ##
  ## According the specification, this is the log base 2 of the distance. But it
  ## is rather the log base 2 of the distance + 1, as else the 0 value can not
  ## be used (e.g. by FindNode call to return peer its own ENR)
  ## For NodeId of 256 bits, range is 0-256.
  let a = a.toBytes
  let b = b.toBytes
  var lz = 0
  for i in countdown(a.len - 1, 0):
    let x = a[i] xor b[i]
    if x == 0:
      lz += 8
    else:
      lz += bitops.countLeadingZeroBits(x)
      break
  return uint32(a.len * 8 - lz)

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
proc tail(k: KBucket): Node {.inline.} = k.nodes[high(k.nodes)]

proc add(k: KBucket, n: Node): Node =
  ## Try to add the given node to this bucket.
  ##
  ## If the node is already present, nothing is done, as the node should only
  ## be moved in case of a new succesful request-reponse.
  ##
  ## If the node is not already present and the bucket has fewer than k entries,
  ## it is inserted as the last entry of the bucket (least recently seen node),
  ## and nil is returned.
  ##
  ## If the bucket is full, the node is added to the bucket's replacement cache
  ## and the node at the last entry of the bucket (least recently seen), which
  ## should be evicted if it fails to respond to a ping, is returned.
  ##
  ## If the replacement cache is also full, the node at the last entry of the
  ## bucket is returned. The new node is nowhere stored and thus lost.
  ##
  ## Reasoning here is that adding nodes will happen for a big part from
  ## lookups, which do not necessarily return nodes that are (still) reachable.
  ## So, more trust is put in the own ordering and newly additions are added
  ## as least recently seen (in fact they are never seen yet from this node its
  ## perspective).
  ## However, in discovery v5 it can be that a node is added after a incoming
  ## request, and considering a handshake that needs to be done, it is likely
  ## that this node is reachable. An additional `addSeen` proc could be created
  ## for this,
  k.lastUpdated = epochTime() # TODO: only when an actual update is done?
  let nodeIdx = k.nodes.find(n)
  if nodeIdx != -1:
    return nil
  elif k.len < BUCKET_SIZE:
    k.nodes.add(n)
    return nil
  elif k.replacementCache.len < REPLACEMENT_CACHE_SIZE:
    k.replacementCache.add(n)
    return k.tail
  else:
    return k.tail

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

proc contains(k: KBucket, n: Node): bool = n in k.nodes

proc binaryGetBucketForNode(buckets: openarray[KBucket],
                            id: NodeId): KBucket {.inline.} =
  ## Given a list of ordered buckets, returns the bucket for a given node.
  let bucketPos = lowerBound(buckets, id) do(a: KBucket, b: NodeId) -> int:
    cmp(a.iend, b)
  # Prevents edge cases where bisect_left returns an out of range index
  if bucketPos < buckets.len:
    let bucket = buckets[bucketPos]
    if bucket.istart <= id and id <= bucket.iend:
      result = bucket

  # TODO: Is this really an error that should occur? Feels a lot like a work-
  # around to another problem. Set to Defect for now.
  if result.isNil:
    raise (ref Defect)(msg: "No bucket found for node with id " & $id)

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

  for n in nodes:
    echo n.id.toHex()

  doAssert(false, "Unable to calculate number of shared prefix bits")

proc init*(r: var RoutingTable, thisNode: Node) {.inline.} =
  r.thisNode = thisNode
  r.buckets = @[newKBucket(0.u256, high(Uint256))]
  randomize() # for later `randomNodes` selection

proc splitBucket(r: var RoutingTable, index: int) =
  let bucket = r.buckets[index]
  let (a, b) = bucket.split()
  r.buckets[index] = a
  r.buckets.insert(b, index + 1)

proc bucketForNode(r: RoutingTable, id: NodeId): KBucket =
  binaryGetBucketForNode(r.buckets, id)

proc removeNode*(r: var RoutingTable, n: Node) =
  r.bucketForNode(n.id).removeNode(n)

proc addNode*(r: var RoutingTable, n: Node): Node =
  if n == r.thisNode:
    # warn "Trying to add ourselves to the routing table", node = n
    return
  let bucket = r.bucketForNode(n.id)
  let evictionCandidate = bucket.add(n)
  if not evictionCandidate.isNil:
    # Split if the bucket has the local node in its range or if the depth is not congruent
    # to 0 mod BITS_PER_HOP

    let depth = computeSharedPrefixBits(bucket.nodes)
    # TODO: Shouldn't the adding to replacement cache be done only if the bucket
    # doesn't get split?
    if bucket.inRange(r.thisNode) or (depth mod BITS_PER_HOP != 0 and depth != ID_SIZE):
      r.splitBucket(r.buckets.find(bucket))
      return r.addNode(n) # retry

    # Nothing added, ping evictionCandidate
    return evictionCandidate

proc getNode*(r: RoutingTable, id: NodeId): Option[Node] =
  let b = r.bucketForNode(id)
  for n in b.nodes:
    if n.id == id:
      return some(n)

proc contains*(r: RoutingTable, n: Node): bool = n in r.bucketForNode(n.id)

proc bucketsByDistanceTo(r: RoutingTable, id: NodeId): seq[KBucket] =
  sortedByIt(r.buckets, it.distanceTo(id))

proc neighbours*(r: RoutingTable, id: NodeId, k: int = BUCKET_SIZE): seq[Node] =
  ## Return up to k neighbours of the given node.
  result = newSeqOfCap[Node](k * 2)
  block addNodes:
    for bucket in r.bucketsByDistanceTo(id):
      for n in bucket.nodesByDistanceTo(id):
        result.add(n)
        if result.len == k * 2:
          break addNodes

  # TODO: is this sort still needed? Can we get nodes closer from the "next"
  # bucket?
  result = sortedByIt(result, it.distanceTo(id))
  if result.len > k:
    result.setLen(k)

proc idAtDistance*(id: NodeId, dist: uint32): NodeId =
  ## Calculate the "lowest" `NodeId` for given logarithmic distance.
  ## A logarithmic distance obviously covers a whole range of distances and thus
  ## potential `NodeId`s.
  # xor the NodeId with 2^(d - 1) or one could say, calculate back the leading
  # zeroes and xor those` with the id.
  id xor (1.stuint(256) shl (dist.int - 1))

proc neighboursAtDistance*(r: RoutingTable, distance: uint32,
    k: int = BUCKET_SIZE): seq[Node] =
  result = r.neighbours(idAtDistance(r.thisNode.id, distance), k)
  # This is a bit silly, first getting closest nodes then to only keep the ones
  # that are exactly the requested distance.
  keepIf(result, proc(n: Node): bool = logDist(n.id, r.thisNode.id) == distance)

proc len*(r: RoutingTable): int =
  for b in r.buckets: result += b.len

proc moveRight[T](arr: var openarray[T], a, b: int) {.inline.} =
  ## In `arr` move elements in range [a, b] right by 1.
  var t: T
  shallowCopy(t, arr[b + 1])
  for i in countdown(b, a):
    shallowCopy(arr[i + 1], arr[i])
  shallowCopy(arr[a], t)

proc setJustSeen*(r: RoutingTable, n: Node) =
  ## Move `n` to the head (most recently seen) of its bucket.
  let b = r.bucketForNode(n.id)
  let idx = b.nodes.find(n)
  # TODO: This assert might be troublesome if we start using it for every
  # message response & then ping a node that is not in our table (e.g. in tests)
  doAssert(idx >= 0)
  if idx != 0:
    b.nodes.moveRight(0, idx - 1)
  b.lastUpdated = epochTime()

proc nodeToRevalidate*(r: RoutingTable): Node =
  var buckets = r.buckets
  shuffle(buckets)
  # TODO: Should we prioritize less-recently-updated buckets instead?
  for b in buckets:
    if b.len > 0:
      return b.nodes[^1]

proc randomNodes*(r: RoutingTable, maxAmount: int,
    pred: proc(x: Node): bool {.gcsafe, noSideEffect.} = nil): seq[Node] =
  var maxAmount = maxAmount
  let sz = r.len
  if maxAmount > sz:
    debug  "Less peers in routing table than maximum requested",
      requested = maxAmount, present = sz
    maxAmount = sz

  result = newSeqOfCap[Node](maxAmount)
  var seen = initHashSet[Node]()

  # This is a rather inefficient way of randomizing nodes from all buckets, but even if we
  # iterate over all nodes in the routing table, the time it takes would still be
  # insignificant compared to the time it takes for the network roundtrips when connecting
  # to nodes.
  # However, "time it takes" might not be relevant, as there might be no point
  # in providing more `randomNodes` as the routing table might not have anything
  # new to provide. And there is no way for the calling code to know this. So
  # while it will take less total time compared to e.g. an (async)
  # randomLookup, the time might be wasted as all nodes are possibly seen
  # already.
  while len(seen) < maxAmount:
    # TODO: Is it important to get a better random source for these sample calls?
    let bucket = sample(r.buckets)
    if bucket.nodes.len != 0:
      let node = sample(bucket.nodes)
      if node notin seen:
        seen.incl(node)
        if pred.isNil() or node.pred:
          result.add(node)
