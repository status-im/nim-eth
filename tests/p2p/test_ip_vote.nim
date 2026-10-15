# nim-eth
# Copyright (c) 2021-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/net,
  unittest2,
  ../../eth/common/keys, ../../eth/p2p/discoveryv5/[node, ip_vote]

suite "Discovery v5.1 IP vote":
  let rng = newRng()

  test "Majority vote":
    var
      votes = IpVote.init(2)
    let
      ip = parseIpAddress("127.0.0.1")
      addr1 = Address(ip: ip, port: Port(1))
      addr2 = Address(ip: ip, port: Port(2))
      addr3 = Address(ip: ip, port: Port(3))

    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr3);
    votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority() == (Opt.some(ip), Opt.some(Port(2)))

  test "Votes below threshold":
    const threshold = 10

    var
      votes = IpVote.init(threshold)
    let
      addr1 = Address(ip: parseIpAddress("1.2.3.4"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("5.6.7.8"), port: Port(2))
      addr3 = Address(ip: parseIpAddress("9.10.11.12"), port: Port(3))

    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);

    for i in 0..<(threshold - 1):
      votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority() == (Opt.none(IpAddress), Opt.none(Port))

  test "Votes at threshold":
    const threshold = 10

    var
      votes = IpVote.init(threshold)
    let
      addr1 = Address(ip: parseIpAddress("1.2.3.4"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("5.6.7.8"), port: Port(2))
      addr3 = Address(ip: parseIpAddress("9.10.11.12"), port: Port(3))

    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);

    for i in 0..<(threshold):
      votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority() == (Opt.some(addr3.ip), Opt.some(addr3.port))

  test "Double votes with same address":
    const threshold = 2

    var
      votes = IpVote.init(threshold)
    let
      addr1 = Address(ip: parseIpAddress("1.2.3.4"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("5.6.7.8"), port: Port(2))

    let nodeIdA = NodeId.random(rng[])
    votes.insert(nodeIdA, addr1);
    votes.insert(nodeIdA, addr1);
    votes.insert(nodeIdA, addr1);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr2);

    check votes.majority() == (Opt.some(addr2.ip), Opt.some(addr2.port))

  test "Double votes with different address":
    const threshold = 2

    var
      votes = IpVote.init(threshold)
    let
      addr1 = Address(ip: parseIpAddress("1.2.3.4"), port: Port(1))
      addr2 = Address(ip: parseIpAddress("5.6.7.8"), port: Port(2))
      addr3 = Address(ip: parseIpAddress("9.10.11.12"), port: Port(3))

    let nodeIdA = NodeId.random(rng[])
    votes.insert(nodeIdA, addr1);
    votes.insert(nodeIdA, addr2);
    votes.insert(nodeIdA, addr3);
    votes.insert(NodeId.random(rng[]), addr1);
    votes.insert(NodeId.random(rng[]), addr2);
    votes.insert(NodeId.random(rng[]), addr3);

    check votes.majority() == (Opt.some(addr3.ip), Opt.some(addr3.port))

  test "IP majority without port majority":
    const threshold = 10

    var
      votes = IpVote.init(threshold)
    let ip = parseIpAddress("1.2.3.4")

    # Symmetric NAT: every peer reports a different port for the same IP.
    for i in 0 ..< threshold:
      votes.insert(NodeId.random(rng[]), Address(ip: ip, port: Port(1000 + i)))

    check votes.majority() == (Opt.some(ip), Opt.none(Port))

  test "IP majority below threshold":
    const threshold = 10

    var
      votes = IpVote.init(threshold)
    let
      ip1 = parseIpAddress("1.2.3.4")
      ip2 = parseIpAddress("5.6.7.8")

    for i in 0 ..< (threshold - 1):
      votes.insert(NodeId.random(rng[]), Address(ip: ip1, port: Port(1000 + i)))
    votes.insert(NodeId.random(rng[]), Address(ip: ip2, port: Port(9000)))

    check votes.majority() == (Opt.none(IpAddress), Opt.none(Port))

  test "IP majority with different IPs":
    const threshold = 2

    var
      votes = IpVote.init(threshold)
    let
      ip1 = parseIpAddress("1.2.3.4")
      ip2 = parseIpAddress("5.6.7.8")

    votes.insert(NodeId.random(rng[]), Address(ip: ip1, port: Port(1000)))
    votes.insert(NodeId.random(rng[]), Address(ip: ip1, port: Port(1001)))
    votes.insert(NodeId.random(rng[]), Address(ip: ip2, port: Port(1002)))

    check votes.majority() == (Opt.some(ip1), Opt.none(Port))

  test "IP:port majority wins from IP majority":
    const threshold = 2

    var
      votes = IpVote.init(threshold)
    let
      ip1 = parseIpAddress("1.2.3.4")
      ip2 = parseIpAddress("5.6.7.8")

    # Most votes are on ip1, but its ports all differ.
    for i in 0 ..< 3:
      votes.insert(NodeId.random(rng[]), Address(ip: ip1, port: Port(1000 + i)))
    # Less votes, but an agreement on the full address.
    for i in 0 ..< threshold:
      votes.insert(NodeId.random(rng[]), Address(ip: ip2, port: Port(9000)))

    check votes.majority() == (Opt.some(ip2), Opt.some(Port(9000)))

  test "Double votes with same node id and IP":
    const threshold = 2

    var
      votes = IpVote.init(threshold)
    let ip = parseIpAddress("1.2.3.4")

    let nodeIdA = NodeId.random(rng[])
    votes.insert(nodeIdA, Address(ip: ip, port: Port(1000)))
    votes.insert(nodeIdA, Address(ip: ip, port: Port(1001)))

    # Only one node voted, so no majority on the IP either.
    check votes.majority() == (Opt.none(IpAddress), Opt.none(Port))
