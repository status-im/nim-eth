import
  unittest,
  eth/p2p/discoveryv5/[routing_table, node],
  ./discv5_test_helper

suite "Routing Table Tests":
  test "Bucket splitting in range branch b=1":
    let node = generateNode()
    var table: RoutingTable

    # bitsPerHop = 1 -> Split only the branch in range of own id
    table.init(node, 1)

    for j in 0..5'u32:
      for i in 0..<BUCKET_SIZE:
        check table.addNode(node.nodeAtDistance(256-j)) == nil
      check table.addNode(node.nodeAtDistance(256-j)) != nil

  test "Bucket splitting off range branch b=1":
    let node = generateNode()
    var table: RoutingTable

    # bitsPerHop = 1 -> Split only the branch in range of own id
    table.init(node, 1)

    # Add 16 nodes, distance 256
    for i in 0..<BUCKET_SIZE:
      check table.addNode(node.nodeAtDistance(256)) == nil

    # This should split the bucket in the distance 256 branch, and the distance
    # <=255 branch. But not add the node, as distance 256 bucket is already full
    # and b=1 will not allow it to spit any further
    check table.addNode(node.nodeAtDistance(256)) != nil

    # This add should be allowed as it is on the branch where the own node's id
    # id belongs to.
    check table.addNode(node.nodeAtDistance(255)) == nil

  test "Bucket splitting off range branch b=2":
    let node = generateNode()
    var table: RoutingTable

    # bitsPerHop = 2, allow not in range branch to split once (2 buckets).
    table.init(node, 2)

    # Add 16 nodes, distance 256 from `node`, but all with 2 bits shared prefix
    # among themselves.
    let firstNode = node.nodeAtDistance(256)
    check table.addNode(firstNode) == nil
    for n in 1..<BUCKET_SIZE:
      check table.addNode(firstNode.nodeAtDistance(254)) == nil

    # Add 16 more nodes with only 1 bit shared prefix with previous 16. This
    # should cause the initial bucket to split and and fill the second bucket
    # with the 16 new entries.
    for n in 0..<BUCKET_SIZE:
      check table.addNode(firstNode.nodeAtDistance(255)) == nil

    # Adding another should fail as both buckets will be full and not be
    # allowed to split another time.
    check table.addNode(node.nodeAtDistance(256)) != nil
    # And also when targetting one of the two specific buckets.
    check table.addNode(firstNode.nodeAtDistance(255)) != nil
    check table.addNode(firstNode.nodeAtDistance(254)) != nil
    # This add should be allowed as it is on the branch where the own node's id
    # id belongs to.
    check table.addNode(node.nodeAtDistance(255)) == nil

  test "Replacement cache":
    let node = generateNode()
    var table: RoutingTable

    # bitsPerHop = 1 -> Split only the branch in range of own id
    table.init(node, 1)

    # create a full bucket
    let bucketNodes = node.nodesAtDistance(256, BUCKET_SIZE)
    for n in bucketNodes:
      check table.addNode(n) == nil

    # create a full replacement cache
    let replacementNodes = node.nodesAtDistance(256, REPLACEMENT_CACHE_SIZE)
    for n in replacementNodes:
      check table.addNode(n) != nil

    # Add one more node to replacement (would drop first one)
    let lastNode = node.nodeAtDistance(256)
    check table.addNode(lastNode) != nil

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

  test "Empty replacement cache":
    let node = generateNode()
    var table: RoutingTable

    # bitsPerHop = 1 -> Split only the branch in range of own id
    table.init(node, 1)

    # create a full bucket TODO: no need to store bucketNodes
    let bucketNodes = node.nodesAtDistance(256, BUCKET_SIZE)
    for n in bucketNodes:
      check table.addNode(n) == nil

    table.replaceNode(table.nodeToRevalidate())
    # This node should still be removed
    check (table.getNode(bucketNodes[bucketNodes.high].id)).isNone()

  test "Double replacement":
    let node = generateNode()
    var table: RoutingTable

    # bitsPerHop = 1 -> Split only the branch in range of own id
    table.init(node, 1)

    # create a full bucket
    let bucketNodes = node.nodesAtDistance(256, BUCKET_SIZE)
    for n in bucketNodes:
      check table.addNode(n) == nil

    # create a full replacement cache
    let replacementNodes = node.nodesAtDistance(256, REPLACEMENT_CACHE_SIZE)
    for n in replacementNodes:
      check table.addNode(n) != nil

    check table.addNode(replacementNodes[0]) != nil

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
