# nim-eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/net,
  unittest2,
  ../../eth/common/keys,
  ../../eth/enr/enr,
  ../../eth/p2p/discoveryv5/node

const
  tcpPort = Port(9000)
  udpPort = Port(9000)
  newUdpPort = Port(9001)

suite "Discovery v5.1 DiscoveryNode":
  let rng = newRng()

  test "Update with IP and UDP port":
    let
      privKey = PrivateKey.random(rng[])
      record = enr.Record.init(1, privKey, Opt.none(IpAddress),
        Opt.some(tcpPort), Opt.some(udpPort)).expect("Valid record")
      node = LocalDiscoveryNode.fromRecord(record)
      extIp = parseIpAddress("1.2.3.4")

    check:
      node.address.isNone()
      node.update(
        privKey, ip = Opt.some(extIp), udpPort = Opt.some(newUdpPort)).isOk()
      node.address == Opt.some(Address(ip: extIp, port: newUdpPort))

  test "Update with IP only takes the UDP port from the record":
    let
      privKey = PrivateKey.random(rng[])
      record = enr.Record.init(1, privKey, Opt.none(IpAddress),
        Opt.some(tcpPort), Opt.some(udpPort)).expect("Valid record")
      node = LocalDiscoveryNode.fromRecord(record)
      extIp = parseIpAddress("1.2.3.4")

    check:
      # No IP in the record, so there is no address, even though there is a port
      node.address.isNone()
      node.update(privKey, ip = Opt.some(extIp)).isOk()
      # The UDP port in the record is left untouched and is now usable
      node.address == Opt.some(Address(ip: extIp, port: udpPort))

  test "Update with IP only and no UDP port in the record":
    let
      privKey = PrivateKey.random(rng[])
      record = enr.Record.init(1, privKey, Opt.none(IpAddress),
        Opt.some(tcpPort), Opt.none(Port)).expect("Valid record")
      node = LocalDiscoveryNode.fromRecord(record)
      extIp = parseIpAddress("1.2.3.4")

    check:
      node.update(privKey, ip = Opt.some(extIp)).isOk()
      node.address.isNone()

  test "Update of custom fields only keeps the address":
    let
      privKey = PrivateKey.random(rng[])
      ip = parseIpAddress("1.2.3.4")
      record = enr.Record.init(1, privKey, Opt.some(ip),
        Opt.some(tcpPort), Opt.some(udpPort)).expect("Valid record")
      node = LocalDiscoveryNode.fromRecord(record)

    check:
      node.address == Opt.some(Address(ip: ip, port: udpPort))
      node.update(privKey, ip = Opt.none(IpAddress),
        extraFields = [toFieldPair("test", @[byte 0, 1, 2])]).isOk()
      node.address == Opt.some(Address(ip: ip, port: udpPort))
