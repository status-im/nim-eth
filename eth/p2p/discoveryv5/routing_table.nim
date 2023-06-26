# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[algorithm, times, sequtils, bitops, sets],
  bearssl/rand,
  stint, chronicles, metrics, chronos, stew/shims/net as stewNet,
  ../../net/utils, stew/results,
  "."/[node, random2, enr]

export results

declarePublicGauge routing_table_nodes,
  "Discovery routing table nodes", labels = ["state"]

type
  DistanceProc* =
    proc(a, b: NodeId): NodeId {.raises: [], gcsafe, noSideEffect.}
  LogDistanceProc* =
    proc(a, b: NodeId): uint16 {.raises: [], gcsafe, noSideEffect.}
  IdAtDistanceProc* =
    proc (id: NodeId, dist: uint16): NodeId {.raises: [], gcsafe, noSideEffect.}

  DistanceCalculator* = object
    calculateDistance*: DistanceProc
    calculateLogDistance*: LogDistanceProc
    calculateIdAtDistance*: IdAtDistanceProc

  RoutingTable* = object
    localNode*: Node
    buckets*: seq[KBucket]
    bitsPerHop: int ## This value indicates how many bits (at minimum) you get
    ## closer to finding your target per query. Practically, it tells you also
    ## how often your "not in range" branch will split off. Setting this to 1
    ## is the basic, non accelerated version, which will never split off the
    ## not in range branch and which will result in log base2 n hops per lookup.
    ## Setting it higher will increase the amount of splitting on a not in range
    ## branch (thus holding more nodes with a better keyspace coverage) and this
    ## will result in an improvement of log base(2^b) n hops per lookup.
    ipLimits: IpLimits ## IP limits for total routing table: all buckets and
    ## replacement caches.
    distanceCalculator: DistanceCalculator
    rng: ref HmacDrbgContext

  KBucket = ref object
    istart, iend: NodeId ## Range of NodeIds this KBucket covers. This is not a
    ## simple logarithmic distance as buckets can be split over a prefix that
    ## does not cover the `localNode` id.
    nodes*: seq[Node] ## Node entries of the KBucket. Sorted according to last
    ## time seen. First entry (head) is considered the most recently seen node
    ## and the last entry (tail) is considered the least recently seen node.
    ## Here "seen" means a successful request-response. This can also not have
    ## occurred yet.
    replacementCache: seq[Node] ## Nodes that could not be added to the `nodes`
    ## seq as it is full and without stale nodes. This is practically a small
    ## LRU cache.
    ipLimits: IpLimits ## IP limits for bucket: node entries and replacement
    ## cache entries combined.

  ## The routing table IP limits are applied on both the total table, and on the
  ## individual buckets. In each case, the active node entries, but also the
  ## entries waiting in the replacement cache are accounted for. This way, the
  ## replacement cache can't get filled with nodes that then can't be added due
  ## to the limits that apply.
  ##
  ## As entries are not verified (=contacted) immediately before or on entry, it
  ## is possible that a malicious node could fill (poison) the routing table or
  ## a specific bucket with ENRs with IPs it does not control. The effect of
  ## this would be that a node that actually owns the IP could have a difficult
  ## time getting its ENR distributed in the DHT and as a consequence would
  ## not be reached from the outside as much (or at all). However, that node can
  ## still search and find nodes to connect to. So it would practically be a
  ## similar situation as a node that is not reachable behind the NAT because
  ## port mapping is not set up properly.
  ## There is the possibility to set the IP limit on verified (=contacted) nodes
  ## only, but that would allow for lookups to be done on a higher set of nodes
  ## owned by the same identity. This is a worse alternative.
  ## Next, doing lookups only on verified nodes would slow down discovery start
  ## up.
  TableIpLimits* = object
    tableIpLimit*: uint
    bucketIpLimit*: uint

  NodeStatus* = enum
    Added
    LocalNode
    Existing
    IpLimitReached
    ReplacementAdded
    ReplacementExisting
    NoAddress

# xor distance functions
func distance*(a, b: NodeId): UInt256 =
  ## Calculate the distance to a NodeId.
  a xor b

func logDistance*(a, b: NodeId): uint16 =
  ## Calculate the logarithmic distance between two `NodeId`s.
  ##
  ## According the specification, this is the log base 2 of the distance. But it
  ## is rather the log base 2 of the distance + 1, as else the 0 value can not
  ## be used (e.g. by FindNode call to return peer its own ENR)
  ## For NodeId of 256 bits, range is 0-256.
  let a = a.toBytesBE
  let b = b.toBytesBE
  var lz = 0
  for i in 0..<a.len:
    let x = a[i] xor b[i]
    if x == 0:
      lz += 8
    else:
      lz += bitops.countLeadingZeroBits(x)
      break
  return uint16(a.len * 8 - lz)

func idAtDistance*(id: NodeId, dist: uint16): NodeId =
  ## Calculate the "lowest" `NodeId` for given logarithmic distance.
  ## A logarithmic distance obviously covers a whole range of distances and thus
  ## potential `NodeId`s.
  # xor the NodeId with 2^(d - 1) or one could say, calculate back the leading
  # zeroes and xor those` with the id.
  id xor (1.stuint(256) shl (dist.int - 1))

const
  BUCKET_SIZE* = 16 ## Maximum amount of nodes per bucket
  REPLACEMENT_CACHE_SIZE* = 8 ## Maximum amount of nodes per replacement cache
  ## of a bucket
  ID_SIZE = 256
  DefaultBitsPerHop* = 5
  DefaultBucketIpLimit* = 2'u
  DefaultTableIpLimit* = 10'u
  DefaultTableIpLimits* = TableIpLimits(tableIpLimit: DefaultTableIpLimit,
    bucketIpLimit: DefaultBucketIpLimit)
  XorDistanceCalculator* = DistanceCalculator(calculateDistance: distance,
    calculateLogDistance: logDistance, calculateIdAtDistance: idAtDistance)

func distance*(r: RoutingTable, a, b: NodeId): UInt256 =
  r.distanceCalculator.calculateDistance(a, b)

func logDistance*(r: RoutingTable, a, b: NodeId): uint16 =
  r.distanceCalculator.calculateLogDistance(a, b)

func idAtDistance*(r: RoutingTable, id: NodeId, dist: uint16): NodeId =
  r.distanceCalculator.calculateIdAtDistance(id, dist)

proc new(T: type KBucket, istart, iend: NodeId, bucketIpLimit: uint): T =
  KBucket(
    istart: istart,
    iend: iend,
    nodes: @[],
    replacementCache: @[],
    ipLimits: IpLimits(limit: bucketIpLimit))

proc midpoint(k: KBucket): NodeId =
  k.istart + (k.iend - k.istart) div 2.u256

proc len(k: KBucket): int = k.nodes.len

proc tail(k: KBucket): Node = k.nodes[high(k.nodes)]

proc ipLimitInc(r: var RoutingTable, b: KBucket, n: Node): bool =
  ## Check if the ip limits of the routing table and the bucket are reached for
  ## the specified `Node` its ip.
  ## When one of the ip limits is reached return false, else increment them and
  ## return true.
  let ip = n.address.get().ip # Node from table should always have an address
  # Check ip limit for bucket
  if not b.ipLimits.inc(ip):
    return false
  # Check ip limit for routing table
  if not r.ipLimits.inc(ip):
    b.ipLimits.dec(ip)
    return false

  return true

proc ipLimitDec(r: var RoutingTable, b: KBucket, n: Node) =
  ## Decrement the ip limits of the routing table and the bucket for the
  ## specified `Node` its ip.
  let ip = n.address.get().ip # Node from table should always have an address

  b.ipLimits.dec(ip)
  r.ipLimits.dec(ip)

proc add(k: KBucket, n: Node) =
  k.nodes.add(n)
  routing_table_nodes.inc()

proc remove(k: KBucket, n: Node): bool =
  let i = k.nodes.find(n)
  if i != -1:
    routing_table_nodes.dec()
    if k.nodes[i].seen:
      routing_table_nodes.dec(labelValues = ["seen"])
    k.nodes.delete(i)
    true
  else:
    false

proc split(k: KBucket): tuple[lower, upper: KBucket] =
  ## Split the kbucket `k` at the median id.
  let splitid = k.midpoint
  result.lower = KBucket.new(k.istart, splitid, k.ipLimits.limit)
  result.upper = KBucket.new(splitid + 1.u256, k.iend, k.ipLimits.limit)
  for node in k.nodes:
    let bucket = if node.id <= splitid: result.lower else: result.upper
    bucket.nodes.add(node)
    # Ip limits got reset because of the KBucket.new, so there is the need to
    # increment again for each added node. It should however never fail as the
    # previous bucket had the same limits.
    doAssert(bucket.ipLimits.inc(node.address.get().ip),
      "IpLimit increment should work as all buckets have the same limits")

  for node in k.replacementCache:
    let bucket = if node.id <= splitid: result.lower else: result.upper
    bucket.replacementCache.add(node)
    doAssert(bucket.ipLimits.inc(node.address.get().ip),
      "IpLimit increment should work as all buckets have the same limits")

proc inRange(k: KBucket, n: Node): bool =
  k.istart <= n.id and n.id <= k.iend

proc contains(k: KBucket, n: Node): bool = n in k.nodes

proc binaryGetBucketForNode*(buckets: openArray[KBucket],
                            id: NodeId): KBucket =
  ## Given a list of ordered buckets, returns the bucket for a given `NodeId`.
  ## Returns nil if no bucket in range for given `id` is found.
  let bucketPos = lowerBound(buckets, id) do(a: KBucket, b: NodeId) -> int:
    cmp(a.iend, b)

  # Prevent cases where `lowerBound` returns an out of range index e.g. at empty
  # openArray, or when the id is out range for all buckets in the openArray.
  if bucketPos < buckets.len:
    let bucket = buckets[bucketPos]
    if bucket.istart <= id and id <= bucket.iend:
      result = bucket

proc computeSharedPrefixBits(nodes: openArray[NodeId]): int =
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

proc init*(T: type RoutingTable, localNode: Node, bitsPerHop = DefaultBitsPerHop,
    ipLimits = DefaultTableIpLimits, rng: ref HmacDrbgContext,
    distanceCalculator = XorDistanceCalculator): T =
  ## Initialize the routing table for provided `Node` and bitsPerHop value.
  ## `bitsPerHop` is default set to 5 as recommended by original Kademlia paper.
  RoutingTable(
    localNode: localNode,
    buckets: @[KBucket.new(0.u256, high(UInt256), ipLimits.bucketIpLimit)],
    bitsPerHop: bitsPerHop,
    ipLimits: IpLimits(limit: ipLimits.tableIpLimit),
    distanceCalculator: distanceCalculator,
    rng: rng)

proc splitBucket(r: var RoutingTable, index: int) =
  let bucket = r.buckets[index]
  let (a, b) = bucket.split()
  r.buckets[index] = a
  r.buckets.insert(b, index + 1)

proc bucketForNode(r: RoutingTable, id: NodeId): KBucket =
  result = binaryGetBucketForNode(r.buckets, id)
  doAssert(not result.isNil(),
    "Routing table should always cover the full id space")

proc addReplacement(r: var RoutingTable, k: KBucket, n: Node): NodeStatus =
  ## Add the node to the tail of the replacement cache of the KBucket.
  ##
  ## If the replacement cache is full, the oldest (first entry) node will be
  ## removed. If the node is already in the replacement cache, it will be moved
  ## to the tail.
  ## When the IP of the node has reached the IP limits for the bucket or the
  ## total routing table, the node will not be added to the replacement cache.
  let nodeIdx = k.replacementCache.find(n)
  if nodeIdx != -1:
    if k.replacementCache[nodeIdx].record.seqNum <= n.record.seqNum:
      # In case the record sequence number is higher or the same, the new node
      # gets moved to the tail.
      if k.replacementCache[nodeIdx].address.get().ip != n.address.get().ip:
        if not ipLimitInc(r, k, n):
          return IpLimitReached
        ipLimitDec(r, k, k.replacementCache[nodeIdx])
      k.replacementCache.delete(nodeIdx)
      k.replacementCache.add(n)
    return ReplacementExisting
  elif not ipLimitInc(r, k, n):
    return IpLimitReached
  else:
    doAssert(k.replacementCache.len <= REPLACEMENT_CACHE_SIZE)

    if k.replacementCache.len == REPLACEMENT_CACHE_SIZE:
      # Remove ip from limits for the to be deleted node.
      ipLimitDec(r, k, k.replacementCache[0])
      k.replacementCache.delete(0)

    k.replacementCache.add(n)
    return ReplacementAdded

proc addNode*(r: var RoutingTable, n: Node): NodeStatus =
  ## Try to add the node to the routing table.
  ##
  ## First, an attempt will be done to add the node to the bucket in its range.
  ## If this fails, the bucket will be split if it is eligible for splitting.
  ## If so, a new attempt will be done to add the node. If not, the node will be
  ## added to the replacement cache.
  ##
  ## In case the node was already in the table, it will be updated if it has a
  ## newer record.
  ## When the IP of the node has reached the IP limits for the bucket or the
  ## total routing table, the node will not be added to the bucket, nor its
  ## replacement cache.

  # Don't allow nodes without an address field in the ENR to be added.
  # This could also be reworked by having another Node type that always has an
  # address.
  if n.address.isNone():
    return NoAddress

  if n == r.localNode:
    return LocalNode

  let bucket = r.bucketForNode(n.id)

  ## Check if the node is already present. If so, check if the record requires
  ## updating.
  let nodeIdx = bucket.nodes.find(n)
  if nodeIdx != -1:
    if bucket.nodes[nodeIdx].record.seqNum < n.record.seqNum:
      # In case of a newer record, it gets replaced.
      if bucket.nodes[nodeIdx].address.get().ip != n.address.get().ip:
        if not ipLimitInc(r, bucket, n):
          return IpLimitReached
        ipLimitDec(r, bucket, bucket.nodes[nodeIdx])
      # Copy over the seen status, we trust here that after the ENR update the
      # node will still be reachable, but it might not be the case.
      n.seen = bucket.nodes[nodeIdx].seen
      bucket.nodes[nodeIdx] = n

    return Existing

  # If the bucket has fewer than `BUCKET_SIZE` entries, it is inserted as the
  # last entry of the bucket (least recently seen node). If the bucket is
  # full, it might get split and adding is retried, else it is added as a
  # replacement.
  # Reasoning here is that adding nodes will happen for a big part from
  # lookups, which do not necessarily return nodes that are (still) reachable.
  # So, more trust is put in the own ordering by actually contacting peers and
  # newly additions are added as least recently seen (in fact they have not been
  # seen yet from our node its perspective).
  # However, in discovery v5 a node can also be added after a incoming request
  # if a handshake is done and an ENR is provided, and considering that this
  # handshake needs to be done, it is more likely that this node is reachable.
  # However, it is not certain and depending on different NAT mechanisms and
  # timers it might still fail. For this reason we currently do not add a way to
  # immediately add nodes to the most recently seen spot.
  if bucket.len < BUCKET_SIZE:
    if not ipLimitInc(r, bucket, n):
      return IpLimitReached

    bucket.add(n)
  else:
    # Bucket must be full, but lets see if it should be split the bucket.

    # Calculate the prefix shared by all nodes in the bucket's range, not the
    # ones actually in the bucket.
    let depth = computeSharedPrefixBits(@[bucket.istart, bucket.iend])
    # Split if the bucket has the local node in its range or if the depth is not
    # congruent to 0 mod `bitsPerHop`
    if bucket.inRange(r.localNode) or
        (depth mod r.bitsPerHop != 0 and depth != ID_SIZE):
      r.splitBucket(r.buckets.find(bucket))
      return r.addNode(n) # retry adding
    else:
      # When bucket doesn't get split the node is added to the replacement cache
      return r.addReplacement(bucket, n)

proc removeNode*(r: var RoutingTable, n: Node) =
  ## Remove the node `n` from the routing table.
  let b = r.bucketForNode(n.id)
  if b.remove(n):
    ipLimitDec(r, b, n)

proc replaceNode*(r: var RoutingTable, n: Node) =
  ## Replace node `n` with last entry in the replacement cache. If there are
  ## no entries in the replacement cache, node `n` will simply be removed.
  # TODO: Kademlia paper recommends here to not remove nodes if there are no
  # replacements. However, that would require a bit more complexity in the
  # revalidation as you don't want to try pinging that node all the time.
  let b = r.bucketForNode(n.id)
  if b.remove(n):
    ipLimitDec(r, b, n)

    if b.replacementCache.len > 0:
      # Nodes in the replacement cache are already included in the ip limits.
      b.add(b.replacementCache[high(b.replacementCache)])
      b.replacementCache.delete(high(b.replacementCache))

proc getNode*(r: RoutingTable, id: NodeId): Opt[Node] =
  ## Get the `Node` with `id` as `NodeId` from the routing table.
  ## If no node with provided node id can be found,`none` is returned .
  let b = r.bucketForNode(id)
  for n in b.nodes:
    if n.id == id:
      return Opt.some(n)

proc contains*(r: RoutingTable, n: Node): bool = n in r.bucketForNode(n.id)
  # Check if the routing table contains node `n`.

proc bucketsByDistanceTo(r: RoutingTable, id: NodeId): seq[KBucket] =
  sortedByIt(r.buckets,  r.distance(it.midpoint, id))

proc nodesByDistanceTo(r: RoutingTable, k: KBucket, id: NodeId): seq[Node] =
  sortedByIt(k.nodes, r.distance(it.id, id))

proc neighbours*(r: RoutingTable, id: NodeId, k: int = BUCKET_SIZE,
    seenOnly = false): seq[Node] =
  ## Return up to k neighbours of the given node id.
  ## When seenOnly is set to true, only nodes that have been contacted
  ## previously successfully will be selected.
  result = newSeqOfCap[Node](k * 2)
  block addNodes:
    for bucket in r.bucketsByDistanceTo(id):
      for n in r.nodesByDistanceTo(bucket, id):
        # Only provide actively seen nodes when `seenOnly` set.
        if not seenOnly or n.seen:
          result.add(n)
          if result.len == k * 2:
            break addNodes

  # TODO: is this sort still needed? Can we get nodes closer from the "next"
  # bucket?
  result = sortedByIt(result, r.distance(it.id, id))
  if result.len > k:
    result.setLen(k)

proc neighboursAtDistance*(r: RoutingTable, distance: uint16,
    k: int = BUCKET_SIZE, seenOnly = false): seq[Node] =
  ## Return up to k neighbours at given logarithmic distance.
  result = r.neighbours(r.idAtDistance(r.localNode.id, distance), k, seenOnly)
  # This is a bit silly, first getting closest nodes then to only keep the ones
  # that are exactly the requested distance.
  keepIf(result, proc(n: Node): bool = r.logDistance(n.id, r.localNode.id) == distance)

proc neighboursAtDistances*(r: RoutingTable, distances: seq[uint16],
    k: int = BUCKET_SIZE, seenOnly = false): seq[Node] =
  ## Return up to k neighbours at given logarithmic distances.
  # TODO: This will currently return nodes with neighbouring distances on the
  # first one prioritize. It might end up not including all the node distances
  # requested. Need to rework the logic here and not use the neighbours call.
  if distances.len > 0:
    result = r.neighbours(r.idAtDistance(r.localNode.id, distances[0]), k,
      seenOnly)
    # This is a bit silly, first getting closest nodes then to only keep the ones
    # that are exactly the requested distances.
    keepIf(result, proc(n: Node): bool =
      distances.contains(r.logDistance(n.id, r.localNode.id)))

proc len*(r: RoutingTable): int =
  for b in r.buckets: result += b.len

proc moveRight[T](arr: var openArray[T], a, b: int) =
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

    if not n.seen:
      b.nodes[0].seen = true
      routing_table_nodes.inc(labelValues = ["seen"])

proc nodeToRevalidate*(r: RoutingTable): Node =
  ## Return a node to revalidate. The least recently seen node from a random
  ## bucket is selected.
  var buckets = r.buckets
  r.rng[].shuffle(buckets)
  # TODO: Should we prioritize less-recently-updated buckets instead? Could
  # store a `now` Moment at setJustSeen or at revalidate per bucket.
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
