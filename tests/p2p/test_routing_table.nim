import
  unittest, stew/shims/net, stint,
  eth/keys, eth/p2p/discoveryv5/[routing_table, node],
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

    # bitsPerHop = 2, allow not in range branch to split once.
    table.init(node, 2)

    # Add 16 nodes, distance 256
    for i in 0..<BUCKET_SIZE:
      check table.addNode(node.nodeAtDistance(256)) == nil

    # Add another 32 nodes, to make the not in range branch split and be be sure
    # both buckets are full.
    # TODO: Could improve by adding specific nodes for one of the buckets.
    for i in 0..<BUCKET_SIZE*2:
      discard table.addNode(node.nodeAtDistance(256))

    # Adding another should fail as both buckets should be full and not be
    # allowed to split another time
    check table.addNode(node.nodeAtDistance(256)) != nil
    # This add should be allowed as it is on the branch where the own node's id
    # id belongs to.
    check table.addNode(node.nodeAtDistance(255)) == nil
