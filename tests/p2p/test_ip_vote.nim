# nim-eth
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/net,
  unittest2,
  ../../eth/keys, ../../eth/p2p/discoveryv5/[node, ip_vote]

suite "IP vote":
  let rng = newRng()

  test "Majority vote":
    var
      votes = IpVote.init(2)
    let
      addr1 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(2))
      addr3 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(3))

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
      addr1 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(2))
      addr3 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(3))

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
      addr1 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(2))
      addr3 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(3))

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
      addr1 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(2))

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
      addr1 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(2))
      addr3 = Address(ip: parseIpAddress("127.0.0.1"), port: Port(3))

    let nodeIdA = NodeId.random(rng[])
    votes.insert(nodeIdA, addr1);
    votes.insert(nodeIdA, addr2);
    votes.insert(nodeIdA, addr3);
    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority() == some(addr3)
