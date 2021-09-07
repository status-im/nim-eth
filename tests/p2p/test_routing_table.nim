{.used.}

import
  std/unittest,
  bearssl,
  ../../eth/keys, ../../eth/p2p/discoveryv5/[routing_table, node, enr],
  ./discv5_test_helper

func customDistance*(a, b: NodeId): Uint256 =
  if a >= b:
    a - b
  else:
    b - a

func customLogDistance*(a, b: NodeId): uint16 =
  let distance = customDistance(a, b)
  let modulo = distance mod (u256(uint8.high))
  cast[uint16](modulo)

func customIdAdDist*(id: NodeId, dist: uint16): NodeId =
  id + u256(dist)

suite "Routing Table Tests":
  let rng = newRng()

  # Used for testing. Could also at runtime check whether the address is the
  # loopback address as these are only allowed to be added when coming from
  # another loopback nodes, however that check is done in the protocol code and
  # thus independent of routing_table.
  let ipLimits = TableIpLimits(tableIpLimit: 200,
    bucketIpLimit: BUCKET_SIZE + REPLACEMENT_CACHE_SIZE + 1)

  let customDistanceCalculator = DistanceCalculator(
    calculateDistance: customDistance, 
    calculateLogDistance: customLogDistance, 
    calculateIdAtDistance: customIdAdDist)

  test "Add local node":
    let node = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    check table.addNode(node) == LocalNode

  test "Bucket splitting in range branch b=1":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    for j in 0..5'u32:
      for i in 0..<BUCKET_SIZE:
        check table.addNode(node.nodeAtDistance(rng[], 256-j)) == Added
      check table.addNode(node.nodeAtDistance(rng[], 256-j)) == ReplacementAdded

  test "Bucket splitting off range branch b=1":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    # Add 16 nodes, distance 256
    for i in 0..<BUCKET_SIZE:
      check table.addNode(node.nodeAtDistance(rng[], 256)) == Added

    # This should split the bucket in the distance 256 branch, and the distance
    # <=255 branch. But not add the node, as distance 256 bucket is already full
    # and b=1 will not allow it to spit any further
    check table.addNode(node.nodeAtDistance(rng[], 256)) == ReplacementAdded

    # This add should be allowed as it is on the branch where the own node's id
    # id belongs to.
    check table.addNode(node.nodeAtDistance(rng[], 255)) == Added

  test "Bucket splitting off range branch b=2":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 2, allow not in range branch to split once (2 buckets).
    var table = RoutingTable.init(node, 2, ipLimits, rng = rng)

    # Add 16 nodes, distance 256 from `node`, but all with 2 bits shared prefix
    # among themselves.
    let firstNode = node.nodeAtDistance(rng[], 256)
    check table.addNode(firstNode) == Added
    for n in 1..<BUCKET_SIZE:
      check table.addNode(firstNode.nodeAtDistance(rng[], 254)) == Added

    # Add 16 more nodes with only 1 bit shared prefix with previous 16. This
    # should cause the initial bucket to split and and fill the second bucket
    # with the 16 new entries.
    for n in 0..<BUCKET_SIZE:
      check table.addNode(firstNode.nodeAtDistance(rng[], 255)) == Added

    # Adding another should fail as both buckets will be full and not be
    # allowed to split another time.
    check table.addNode(node.nodeAtDistance(rng[], 256)) == ReplacementAdded
    # And also when targetting one of the two specific buckets.
    check table.addNode(firstNode.nodeAtDistance(rng[], 255)) == ReplacementAdded
    check table.addNode(firstNode.nodeAtDistance(rng[], 254)) == ReplacementAdded
    # This add should be allowed as it is on the branch where the own node's id
    # id belongs to.
    check table.addNode(node.nodeAtDistance(rng[], 255)) == Added

  test "Replacement cache":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    # create a full bucket
    let bucketNodes = node.nodesAtDistance(rng[], 256, BUCKET_SIZE)
    for n in bucketNodes:
      check table.addNode(n) == Added

    # create a full replacement cache
    let replacementNodes = node.nodesAtDistance(rng[], 256, REPLACEMENT_CACHE_SIZE)
    for n in replacementNodes:
      check table.addNode(n) == ReplacementAdded

    # Add one more node to replacement (would drop first one)
    let lastNode = node.nodeAtDistance(rng[], 256)
    check table.addNode(lastNode) == ReplacementAdded

    # This should replace the last node in the bucket, with the last one of
    # the replacement cache.
    table.replaceNode(table.nodeToRevalidate())
    block:
      # Should return the last node of the replacement cache successfully.
      let result = table.getNode(lastNode.id)
      check:
        result.isSome()
        result.get() == lastNode
    block:
      # This node should be removed
      check (table.getNode(bucketNodes[bucketNodes.high].id)).isNone()

  test "Empty bucket":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    check table.nodeToRevalidate().isNil()

    # try to replace not existing node
    table.replaceNode(generateNode(PrivateKey.random(rng[])))
    check table.len == 0

    let addedNode = generateNode(PrivateKey.random(rng[]))
    check table.addNode(addedNode) == Added
    check table.len == 1

    # try to replace not existing node
    table.replaceNode(generateNode(PrivateKey.random(rng[])))
    check table.len == 1

    table.replaceNode(addedNode)
    check table.len == 0

  test "Empty replacement cache":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    # create a full bucket TODO: no need to store bucketNodes
    let bucketNodes = node.nodesAtDistance(rng[], 256, BUCKET_SIZE)
    for n in bucketNodes:
      check table.addNode(n) == Added

    table.replaceNode(table.nodeToRevalidate())
    # This node should still be removed
    check (table.getNode(bucketNodes[bucketNodes.high].id)).isNone()

  test "Double add":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    let doubleNode = node.nodeAtDistance(rng[], 256)
    # Try to add the node twice
    check table.addNode(doubleNode) == Added
    check table.addNode(doubleNode) == Existing

    for n in 0..<BUCKET_SIZE-1:
      check table.addNode(node.nodeAtDistance(rng[], 256)) == Added

    check table.addNode(node.nodeAtDistance(rng[], 256)) == ReplacementAdded
    # Check when adding again once the bucket is full
    check table.addNode(doubleNode) == Existing

    # Test if its order is preserved, there is one node in replacement cache
    # which is why we run `BUCKET_SIZE` times.
    for n in 0..<BUCKET_SIZE:
      table.replaceNode(table.nodeToRevalidate())

    let result = table.getNode(doubleNode.id)
    check:
      result.isSome()
      result.get() == doubleNode
      table.len == 1

  test "Double replacement add":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    # create a full bucket
    let bucketNodes = node.nodesAtDistance(rng[], 256, BUCKET_SIZE)
    for n in bucketNodes:
      check table.addNode(n) == Added

    # create a full replacement cache
    let replacementNodes = node.nodesAtDistance(rng[], 256, REPLACEMENT_CACHE_SIZE)
    for n in replacementNodes:
      check table.addNode(n) == ReplacementAdded

    check table.addNode(replacementNodes[0]) == ReplacementExisting

    table.replaceNode(table.nodeToRevalidate())
    block:
      # Should return the last node of the replacement cache successfully.
      let result = table.getNode(replacementNodes[0].id)
      check:
        result.isSome()
        result.get() == replacementNodes[0]
    block:
      # This node should be removed
      check (table.getNode(bucketNodes[bucketNodes.high].id)).isNone()

  test "Just seen":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    # create a full bucket
    let bucketNodes = node.nodesAtDistance(rng[], 256, BUCKET_SIZE)
    for n in bucketNodes:
      check table.addNode(n) == Added

    # swap seen order
    for n in bucketNodes:
      table.setJustSeen(n)

    for n in bucketNodes:
      table.replaceNode(table.nodeToRevalidate())
      check (table.getNode(n.id)).isNone()

  test "Just seen replacement":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, ipLimits, rng = rng)

    # create a full bucket
    let bucketNodes = node.nodesAtDistance(rng[], 256, BUCKET_SIZE)
    for n in bucketNodes:
      check table.addNode(n) == Added

    # create a full replacement cache
    let replacementNodes = node.nodesAtDistance(rng[], 256, REPLACEMENT_CACHE_SIZE)
    for n in replacementNodes:
      check table.addNode(n) == ReplacementAdded

    for i in countdown(replacementNodes.high, 0):
      table.replaceNode(table.nodeToRevalidate())
      table.setJustSeen(replacementNodes[i])

    for n in replacementNodes:
      let result = table.getNode(n.id)
      check:
        result.isSome()
        result.get() == n

    for i in 0..<int(BUCKET_SIZE/2):
      let result = table.getNode(bucketNodes[i].id)
      check:
        result.isSome()
        result.get() == bucketNodes[i]

  test "Ip limits on bucket":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, DefaultTableIpLimits, rng = rng)

    block: # First bucket
      let sameIpNodes = node.nodesAtDistance(rng[], 256,
        int(DefaultTableIpLimits.bucketIpLimit))
      for n in sameIpNodes:
        check table.addNode(n) == Added

      # Try to add a node, which should fail due to ip bucket limit
      let anotherSameIpNode = node.nodeAtDistance(rng[], 256)
      check table.addNode(anotherSameIpNode) == IpLimitReached

      # Remove one and try add again
      table.replaceNode(table.nodeToRevalidate())
      check table.addNode(anotherSameIpNode) == Added

      # Further fill the bucket with nodes with different ip.
      let diffIpNodes = node.nodesAtDistanceUniqueIp(rng[], 256,
        int(BUCKET_SIZE - DefaultTableIpLimits.bucketIpLimit),
        ValidIpAddress.init("192.168.0.1"))
      for n in diffIpNodes:
        check table.addNode(n) == Added

    block: # Second bucket
      # Try to add another node with the same IP, but different distance.
      # This should split the bucket and add it.
      let anotherSameIpNode = node.nodeAtDistance(rng[], 255)
      check table.addNode(anotherSameIpNode) == Added

      # Add more nodes with different ip and distance 255 to get in the new bucket
      let diffIpNodes = node.nodesAtDistanceUniqueIp(rng[], 255,
        int(BUCKET_SIZE - DefaultTableIpLimits.bucketIpLimit - 1),
        ValidIpAddress.init("192.168.1.1"))
      for n in diffIpNodes:
        check table.addNode(n) == Added

      let sameIpNodes = node.nodesAtDistance(rng[], 255,
        int(DefaultTableIpLimits.bucketIpLimit - 1))
      for n in sameIpNodes:
        check table.addNode(n) == Added

      # Adding in another one should fail again
      let anotherSameIpNode2 = node.nodeAtDistance(rng[], 255)
      check table.addNode(anotherSameIpNode2) == IpLimitReached

  test "Ip limits on routing table":
    let node = generateNode(PrivateKey.random(rng[]))
    # bitsPerHop = 1 -> Split only the branch in range of own id
    var table = RoutingTable.init(node, 1, DefaultTableIpLimits, rng = rng)

    let amount = uint32(DefaultTableIpLimits.tableIpLimit div
      DefaultTableIpLimits.bucketIpLimit)
    # Fill `amount` of buckets, each with 14 nodes with different ips and 2
    # with equal ones.
    for j in 0..<amount:
      let nodes = node.nodesAtDistanceUniqueIp(rng[], 256 - j,
        int(BUCKET_SIZE - DefaultTableIpLimits.bucketIpLimit),
        ValidIpAddress.init("192.168.0.1"))
      for n in nodes:
        check table.addNode(n) == Added

      let sameIpNodes = node.nodesAtDistance(rng[], 256 - j,
        int(DefaultTableIpLimits.bucketIpLimit))
      for n in sameIpNodes:
        check table.addNode(n) == Added

    # Add a node with a different IP, should work and split a bucket once more.
    let anotherDiffIpNode = node.nodeAtDistance(rng[], 256 - amount,
      ValidIpAddress.init("192.168.1.1"))
    check table.addNode(anotherDiffIpNode) == Added

    let amountLeft = int(DefaultTableIpLimits.tableIpLimit mod
      DefaultTableIpLimits.bucketIpLimit)

    let sameIpNodes = node.nodesAtDistance(rng[], 256 - amount, amountLeft)
    for n in sameIpNodes:
      check table.addNode(n) == Added

    # Add a node with same ip to this fresh bucket, should fail because of total
    # ip limit of routing table is reached.
    let anotherSameIpNode = node.nodeAtDistance(rng[], 256 - amount)
    check table.addNode(anotherSameIpNode) == IpLimitReached

  test "Ip limits on replacement cache":
    let node = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(node, 1, DefaultTableIpLimits, rng = rng)

    let diffIpNodes = node.nodesAtDistanceUniqueIp(rng[], 256,
      int(BUCKET_SIZE - DefaultTableIpLimits.bucketIpLimit + 1),
      ValidIpAddress.init("192.168.0.1"))
    for n in diffIpNodes:
      check table.addNode(n) == Added

    let sameIpNodes = node.nodesAtDistance(rng[], 256,
      int(DefaultTableIpLimits.bucketIpLimit - 1))
    for n in sameIpNodes:
      check table.addNode(n) == Added

    let anotherSameIpNode1 = node.nodeAtDistance(rng[], 256)
    check table.addNode(anotherSameIpNode1) == ReplacementAdded

    let anotherSameIpNode2 = node.nodeAtDistance(rng[], 256)
    check table.addNode(anotherSameIpNode2) == IpLimitReached

    block: # Replace node to see if the first one becomes available
      table.replaceNode(table.nodeToRevalidate())
      let res = table.getNode(anotherSameIpNode1.id)
      check:
        res.isSome()
        res.get() == anotherSameIpNode1

        table.getNode(anotherSameIpNode2.id).isNone()

    block: # Replace again to see if the first one never becomes available
      table.replaceNode(table.nodeToRevalidate())
      check:
        table.getNode(anotherSameIpNode1.id).isNone()
        table.getNode(anotherSameIpNode2.id).isNone()

  test "Ip limits on replacement cache: deletion":
    let node = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(node, 1, DefaultTableIpLimits, rng = rng)

    block: # Fill bucket
      let sameIpNodes = node.nodesAtDistance(rng[], 256,
        int(DefaultTableIpLimits.bucketIpLimit - 1))
      for n in sameIpNodes:
        check table.addNode(n) == Added

      let diffIpNodes = node.nodesAtDistanceUniqueIp(rng[], 256,
        int(BUCKET_SIZE - DefaultTableIpLimits.bucketIpLimit + 1),
        ValidIpAddress.init("192.168.0.1"))
      for n in diffIpNodes:
        check table.addNode(n) == Added

    block: # Fill bucket replacement cache
      let sameIpNode = node.nodeAtDistance(rng[], 256)
      check table.addNode(sameIpNode) == ReplacementAdded

      let diffIpNodes = node.nodesAtDistanceUniqueIp(rng[], 256,
        int(REPLACEMENT_CACHE_SIZE - 1),
        ValidIpAddress.init("192.168.1.1"))
      for n in diffIpNodes:
        check table.addNode(n) == ReplacementAdded

    # Try to add node to replacement, but limit is reached
    let sameIpNode = node.nodeAtDistance(rng[], 256)
    check table.addNode(sameIpNode) == IpLimitReached

    # Add one with different ip, to remove the first
    let diffIpNode = node.nodeAtDistance(rng[], 256,
      ValidIpAddress.init("192.168.2.1"))
    check table.addNode(diffIpNode) == ReplacementAdded

    # Now the add should work
    check table.addNode(sameIpNode) == ReplacementAdded

  test "Ip limits on replacement cache: double add":
    let node = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(node, 1, DefaultTableIpLimits, rng = rng)

    # Fill bucket
    let diffIpNodes = node.nodesAtDistanceUniqueIp(rng[], 256, BUCKET_SIZE,
      ValidIpAddress.init("192.168.0.1"))
    for n in diffIpNodes:
      check table.addNode(n) == Added

    # Test if double add does not account for the ip limits.
    for i in 0..<DefaultTableIpLimits.bucketIpLimit:
      let sameIpNode = node.nodeAtDistance(rng[], 256)
      check table.addNode(sameIpNode) == ReplacementAdded
      # Add it again
      check table.addNode(sameIpNode) == ReplacementExisting

    let sameIpNode = node.nodeAtDistance(rng[], 256)
    check table.addNode(sameIpNode) == IpLimitReached

  test "Ip limits on bucket: double add with new ip":
    let node = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(node, 1, DefaultTableIpLimits, rng = rng)

    let pk = PrivateKey.random(rng[])
    let sameIpNode1 = generateNode(pk)
    check table.addNode(sameIpNode1) == Added

    let updatedNode1 = generateNode(pk)
    # Need to do an update to get seqNum increased
    let updated = updatedNode1.update(pk,
      some(ValidIpAddress.init("192.168.0.1")),
      some(Port(9000)), some(Port(9000)))
    check updated.isOk()
    check table.addNode(updatedNode1) == Existing

    let sameIpNodes = node.nodesAtDistance(rng[], 256,
      int(DefaultTableIpLimits.bucketIpLimit))
    for n in sameIpNodes:
      check table.addNode(n) == Added

    check table.len == int(DefaultTableIpLimits.bucketIpLimit) + 1

  test "Ip limits on replacement cache: double add with new ip":
    let node = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(node, 1, DefaultTableIpLimits, rng = rng)

    # Fill bucket
    let diffIpNodes = node.nodesAtDistanceUniqueIp(rng[], 256, BUCKET_SIZE,
      ValidIpAddress.init("192.168.0.1"))
    for n in diffIpNodes:
      check table.addNode(n) == Added

    let (sameIpNode1, pk) = node.nodeAndPrivKeyAtDistance(rng[], 256)
    check table.addNode(sameIpNode1) == ReplacementAdded

    # For replacements we don't need to get seqNum increased as the node will
    # still get pushed in front of the queue.
    let updatedNode1 = generateNode(pk, ip = ValidIpAddress.init("192.168.1.1"))
    check table.addNode(updatedNode1) == ReplacementExisting

    let sameIpNodes = node.nodesAtDistance(rng[], 256,
      int(DefaultTableIpLimits.bucketIpLimit))
    for n in sameIpNodes:
      check table.addNode(n) == ReplacementAdded

  test "Ip limits on bucket: even more adds with new ip":
    # This tests against an issue where the ip of the nodes would not get updated
    let node = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(node, 1, DefaultTableIpLimits, rng = rng)

    let pk = PrivateKey.random(rng[])
    let sameIpNode1 = generateNode(pk)
    check table.addNode(sameIpNode1) == Added

    let updatedNode1 = generateNode(pk)

    for i in 0..<DefaultTableIpLimits.bucketIpLimit + 1:
      # Need to do an update to get seqNum increased
      let updated = updatedNode1.update(pk,
        some(ValidIpAddress.init("192.168.0.1")),
        some(Port(9000+i)), some(Port(9000+i)))
      check updated.isOk()
      check table.addNode(updatedNode1) == Existing

    let sameIpNodes = node.nodesAtDistance(rng[], 256,
      int(DefaultTableIpLimits.bucketIpLimit))
    for n in sameIpNodes:
      check table.addNode(n) == Added

    check table.len == int(DefaultTableIpLimits.bucketIpLimit) + 1

  test "Custom distance calculator: distance":
    let numNodes = 10
    let local = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(local, 1, ipLimits, rng = rng,
      distanceCalculator = customDistanceCalculator)

    let nodes = generateNRandomNodes(rng, numNodes)

    for n in nodes:
      check table.addNode(n) == Added

    let neighbours = table.neighbours(local.id)
    check len(neighbours) == numNodes

    #  check that neighbours are sorted by provdied custom distance funciton
    for i in 0..numNodes-2:
      let prevDist = customDistance(local.id, neighbours[i].id)
      let nextDist = customDistance(local.id, neighbours[i + 1].id)
      check prevDist <= nextDist

  test "Custom distance calculator: at log distance":
    let numNodes = 10
    let local = generateNode(PrivateKey.random(rng[]))
    var table = RoutingTable.init(local, 1, ipLimits, rng = rng,
      distanceCalculator = customDistanceCalculator)

    let nodes = generateNRandomNodes(rng, numNodes)

    for n in nodes:
      check table.addNode(n) == Added

    let neighbours = table.neighbours(local.id)
    check len(neighbours) == numNodes

    for n in neighbours:
      let cLogDist = customLogDistance(local.id, n.id)
      let neighboursAtLogDist = table.neighboursAtDistance(cLogDist)
      # there may be more than one node at provided distance
      check len(neighboursAtLogDist) >= 1
      check neighboursAtLogDist.contains(n)
