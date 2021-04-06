{.used.}

import
  std/unittest,
  stew/shims/net,
  ../../eth/keys, ../../eth/p2p/discoveryv5/[node, ip_vote]

suite "IP vote":
  let rng = newRng()

  test "Majority vote":
    var
      votes = IpVote.init(2)
    let
      addr1 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(2))
      addr3 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(3))

    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr3);
    votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority() == some(addr2)

  test "Votes below threshold":
    const threshold = 10

    var
      votes = IpVote.init(threshold)
    let
      addr1 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(2))
      addr3 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(3))

    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);

    for i in 0..<(threshold - 1):
      votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority().isNone()

  test "Votes at threshold":
    const threshold = 10

    var
      votes = IpVote.init(threshold)
    let
      addr1 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(2))
      addr3 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(3))

    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);

    for i in 0..<(threshold):
      votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority() == some(addr3)

  test "Double votes with same address":
    const threshold = 2

    var
      votes = IpVote.init(threshold)
    let
      addr1 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(2))

    let nodeIdA = NodeId.random(rng[])
    votes.insert(nodeIdA, addr1);
    votes.insert(nodeIdA, addr1);
    votes.insert(nodeIdA, addr1);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr2);

    check votes.majority() == some(addr2)

  test "Double votes with different address":
    const threshold = 2

    var
      votes = IpVote.init(threshold)
    let
      addr1 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(2))
      addr3 = Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(3))

    let nodeIdA = NodeId.random(rng[])
    votes.insert(nodeIdA, addr1);
    votes.insert(nodeIdA, addr2);
    votes.insert(nodeIdA, addr3);
    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority() == some(addr3)
