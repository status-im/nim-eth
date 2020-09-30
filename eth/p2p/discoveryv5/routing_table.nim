import
  std/[algorithm, times, sequtils, bitops, sets, options],
  stint, chronicles, metrics, bearssl,
  node, random2

export options

{.push raises: [Defect].}

declarePublicGauge routing_table_nodes,
  "Discovery routing table nodes", labels = ["state"]

type
  RoutingTable* = object
    thisNode: Node
    buckets: seq[KBucket]
    bitsPerHop: int ## This value indicates how many bits (at minimum) you get
    ## closer to finding your target per query. Practically, it tells you also
    ## how often your "not in range" branch will split off. Setting this to 1
    ## is the basic, non accelerated version, which will never split off the
    ## not in range branch and which will result in log base2 n hops per lookup.
    ## Setting it higher will increase the amount of splitting on a not in range
    ## branch (thus holding more nodes with a better keyspace coverage) and this
    ## will result in an improvement of log base(2^b) n hops per lookup.
    rng: ref BrHmacDrbgContext

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
    ## seq as it is full and without stale nodes. This is practically a small
    ## LRU cache.
    lastUpdated: float ## epochTime of last update to `nodes` in the KBucket.

const
  BUCKET_SIZE* = 16 ## Maximum amount of nodes per bucket
  REPLACEMENT_CACHE_SIZE* = 8 ## Maximum amount of nodes per replacement cache
  ## of a bucket
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
  ## If the bucket is full, the node at the last entry of the bucket (least
  ## recently seen), which should be evicted if it fails to respond to a ping,
  ## is returned.
  ##
  ## Reasoning here is that adding nodes will happen for a big part from
  ## lookups, which do not necessarily return nodes that are (still) reachable.
  ## So, more trust is put in the own ordering and newly additions are added
  ## as least recently seen (in fact they are never seen yet from this node its
  ## perspective).
  ## However, in discovery v5 it can be that a node is added after a incoming
  ## request, and considering a handshake that needs to be done, it is likely
  ## that this node is reachable. An additional `addSeen` proc could be created
  ## for this.
  k.lastUpdated = epochTime()
  let nodeIdx = k.nodes.find(n)
  if nodeIdx != -1:
    if k.nodes[nodeIdx].record.seqNum < n.record.seqNum:
      # In case of a newer record, it gets replaced.
      k.nodes[nodeIdx].record = n.record
    return nil
  elif k.len < BUCKET_SIZE:
    k.nodes.add(n)
    routing_table_nodes.inc()
    return nil
  else:
    return k.tail

proc addReplacement(k: KBucket, n: Node) =
  ## Add the node to the tail of the replacement cache of the KBucket.
  ##
  ## If the replacement cache is full, the oldest (first entry) node will be
  ## removed. If the node is already in the replacement cache, it will be moved
  ## to the tail.
  let nodeIdx = k.replacementCache.find(n)
  if nodeIdx != -1:
    if k.replacementCache[nodeIdx].record.seqNum <= n.record.seqNum:
      # In case the record sequence number is higher or the same, the node gets
      # moved to the tail.
      k.replacementCache.delete(nodeIdx)
      k.replacementCache.add(n)
  else:
    doAssert(k.replacementCache.len <= REPLACEMENT_CACHE_SIZE)
    if k.replacementCache.len == REPLACEMENT_CACHE_SIZE:
      k.replacementCache.delete(0)
    k.replacementCache.add(n)

proc removeNode(k: KBucket, n: Node) =
  let i = k.nodes.find(n)
  if i != -1:
    k.nodes.delete(i)
    routing_table_nodes.dec()

proc split(k: KBucket): tuple[lower, upper: KBucket] =
  ## Split the kbucket `k` at the median id.
  let splitid = k.midpoint
  result.lower = newKBucket(k.istart, splitid)
  result.upper = newKBucket(splitid + 1.u256, k.iend)
  for node in k.nodes:
    let bucket = if node.id <= splitid: result.lower else: result.upper
    bucket.nodes.add(node)
  for node in k.replacementCache:
    let bucket = if node.id <= splitid: result.lower else: result.upper
    bucket.replacementCache.add(node)

proc inRange(k: KBucket, n: Node): bool {.inline.} =
  k.istart <= n.id and n.id <= k.iend

proc contains(k: KBucket, n: Node): bool = n in k.nodes

proc binaryGetBucketForNode*(buckets: openarray[KBucket],
                            id: NodeId): KBucket =
  ## Given a list of ordered buckets, returns the bucket for a given `NodeId`.
  ## Returns nil if no bucket in range for given `id` is found.
  let bucketPos = lowerBound(buckets, id) do(a: KBucket, b: NodeId) -> int:
    cmp(a.iend, b)

  # Prevent cases where `lowerBound` returns an out of range index e.g. at empty
  # openarray, or when the id is out range for all buckets in the openarray.
  if bucketPos < buckets.len:
    let bucket = buckets[bucketPos]
    if bucket.istart <= id and id <= bucket.iend:
      result = bucket

proc computeSharedPrefixBits(nodes: openarray[NodeId]): int =
  ## Count the number of prefix bits shared by all nodes.
  if nodes.len < 2:
    return ID_SIZE

  var mask = zero(UInt256)
  let one = one(UInt256)

  for i in 1 .. ID_SIZE:
    mask = mask or (one shl (ID_SIZE - i))
    let reference = nodes[0] and mask
    for j in 1 .. nodes.high:
      if (nodes[j] and mask) != reference: return i - 1

  for n in nodes:
    echo n.toHex()

  # Reaching this would mean that all node ids are equal.
  doAssert(false, "Unable to calculate number of shared prefix bits")

proc init*(r: var RoutingTable, thisNode: Node, bitsPerHop = 5,
    rng: ref BrHmacDrbgContext) {.inline.} =
  ## Initialize the routing table for provided `Node` and bitsPerHop value.
  ## `bitsPerHop` is default set to 5 as recommended by original Kademlia paper.
  r.thisNode = thisNode
  r.buckets = @[newKBucket(0.u256, high(Uint256))]
  r.bitsPerHop = bitsPerHop
  r.rng = rng

proc splitBucket(r: var RoutingTable, index: int) =
  let bucket = r.buckets[index]
  let (a, b) = bucket.split()
  r.buckets[index] = a
  r.buckets.insert(b, index + 1)

proc bucketForNode(r: RoutingTable, id: NodeId): KBucket =
  result = binaryGetBucketForNode(r.buckets, id)
  doAssert(not result.isNil(),
    "Routing table should always cover the full id space")

proc removeNode*(r: var RoutingTable, n: Node) =
  ## Remove the node `n` from the routing table.
  r.bucketForNode(n.id).removeNode(n)

proc addNode*(r: var RoutingTable, n: Node): Node =
  ## Try to add the node to the routing table.
  ##
  ## First, an attempt will be done to add the node to the bucket in its range.
  ## If this fails, the bucket will be split if it is eligable for splitting.
  ## If so, a new attempt will be done to add the node. If not, the node will be
  ## added to the replacement cache.
  if n == r.thisNode:
    # warn "Trying to add ourselves to the routing table", node = n
    return
  let bucket = r.bucketForNode(n.id)
  let evictionCandidate = bucket.add(n)
  if not evictionCandidate.isNil:
    # Split if the bucket has the local node in its range or if the depth is not
    # congruent to 0 mod `bitsPerHop`
    #
    # Calculate the prefix shared by all nodes in the bucket's range, not the
    # ones actually in the bucket.
    let depth = computeSharedPrefixBits(@[bucket.istart, bucket.iend])
    if bucket.inRange(r.thisNode) or
        (depth mod r.bitsPerHop != 0 and depth != ID_SIZE):
      r.splitBucket(r.buckets.find(bucket))
      return r.addNode(n) # retry adding
    else:
      # When bucket doesn't get split the node is added to the replacement cache
      bucket.addReplacement(n)

      # Nothing added, return evictionCandidate
      return evictionCandidate

proc replaceNode*(r: var RoutingTable, n: Node) =
  ## Replace node `n` with last entry in the replacement cache. If there are
  ## no entries in the replacement cache, node `n` will simply be removed.
  # TODO: Kademlia paper recommends here to not remove nodes if there are no
  # replacements. However, that would require a bit more complexity in the
  # revalidation as you don't want to try pinging that node all the time.
  let b = r.bucketForNode(n.id)
  let idx = b.nodes.find(n)
  if idx != -1:
    routing_table_nodes.dec()
    if b.nodes[idx].seen:
      routing_table_nodes.dec(labelValues = ["seen"])
    b.nodes.delete(idx)

    if b.replacementCache.len > 0:
      b.nodes.add(b.replacementCache[high(b.replacementCache)])
      routing_table_nodes.inc()
      b.replacementCache.delete(high(b.replacementCache))

proc getNode*(r: RoutingTable, id: NodeId): Option[Node] =
  ## Get the `Node` with `id` as `NodeId` from the routing table.
  ## If no node with provided node id can be found,`none` is returned .
  let b = r.bucketForNode(id)
  for n in b.nodes:
    if n.id == id:
      return some(n)

proc contains*(r: RoutingTable, n: Node): bool = n in r.bucketForNode(n.id)
  # Check if the routing table contains node `n`.

proc bucketsByDistanceTo(r: RoutingTable, id: NodeId): seq[KBucket] =
  sortedByIt(r.buckets, it.distanceTo(id))

proc neighbours*(r: RoutingTable, id: NodeId, k: int = BUCKET_SIZE,
    seenOnly = false): seq[Node] =
  ## Return up to k neighbours of the given node id.
  ## When seenOnly is set to true, only nodes that have been contacted
  ## previously successfully will be selected.
  result = newSeqOfCap[Node](k * 2)
  block addNodes:
    for bucket in r.bucketsByDistanceTo(id):
      for n in bucket.nodesByDistanceTo(id):
        # Only provide actively seen nodes when `seenOnly` set.
        if not seenOnly or n.seen:
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
    k: int = BUCKET_SIZE, seenOnly = false): seq[Node] =
  ## Return up to k neighbours at given logarithmic distance.
  result = r.neighbours(idAtDistance(r.thisNode.id, distance), k, seenOnly)
  # This is a bit silly, first getting closest nodes then to only keep the ones
  # that are exactly the requested distance.
  keepIf(result, proc(n: Node): bool = logDist(n.id, r.thisNode.id) == distance)

proc neighboursAtDistances*(r: RoutingTable, distances: seq[uint32],
    k: int = BUCKET_SIZE, seenOnly = false): seq[Node] =
  ## Return up to k neighbours at given logarithmic distances.
  # TODO: This will currently return nodes with neighbouring distances on the
  # first one prioritize. It might end up not including all the node distances
  # requested. Need to rework the logic here and not use the neighbours call.
  if distances.len > 0:
    result = r.neighbours(idAtDistance(r.thisNode.id, distances[0]), k,
      seenOnly)
    # This is a bit silly, first getting closest nodes then to only keep the ones
    # that are exactly the requested distances.
    keepIf(result, proc(n: Node): bool =
      distances.contains(logDist(n.id, r.thisNode.id)))

proc len*(r: RoutingTable): int =
  for b in r.buckets: result += b.len

proc moveRight[T](arr: var openarray[T], a, b: int) =
  ## In `arr` move elements in range [a, b] right by 1.
  var t: T
  shallowCopy(t, arr[b + 1])
  for i in countdown(b, a):
    shallowCopy(arr[i + 1], arr[i])
  shallowCopy(arr[a], t)

proc setJustSeen*(r: RoutingTable, n: Node) =
  ## Move `n` to the head (most recently seen) of its bucket.
  ## If `n` is not in the routing table, do nothing.
  let b = r.bucketForNode(n.id)
  let idx = b.nodes.find(n)
  if idx >= 0:
    if idx != 0:
      b.nodes.moveRight(0, idx - 1)
    b.lastUpdated = epochTime()

    if not n.seen:
      b.nodes[0].seen = true
      routing_table_nodes.inc(labelValues = ["seen"])

proc nodeToRevalidate*(r: RoutingTable): Node =
  ## Return a node to revalidate. The least recently seen node from a random
  ## bucket is selected.
  var buckets = r.buckets
  r.rng[].shuffle(buckets)
  # TODO: Should we prioritize less-recently-updated buckets instead? Could use
  # `lastUpdated` for this, but it would probably make more sense to only update
  # that value on revalidation then and rename it to `lastValidated`.
  for b in buckets:
    if b.len > 0:
      return b.nodes[^1]

proc randomNodes*(r: RoutingTable, maxAmount: int,
    pred: proc(x: Node): bool {.gcsafe, noSideEffect.} = nil): seq[Node] =
  ## Get a `maxAmount` of random nodes from the routing table with the `pred`
  ## predicate function applied as filter on the nodes selected.
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
    let bucket = r.rng[].sample(r.buckets)
    if bucket.nodes.len != 0:
      let node = r.rng[].sample(bucket.nodes)
      if node notin seen:
        seen.incl(node)
        if pred.isNil() or node.pred:
          result.add(node)
