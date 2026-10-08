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
  chronos,
  ../eth/net/nat

suite "NAT external address":
  let ports = @[(port: Port(9009), protocol: PortProtocol.UDP)]

  test "extip with an IPv4 address is advertised":
    let
      natConfig = NatConfig.parseCmdArg("extip:1.2.3.4")
      res = setupAddress(natConfig, parseIpAddress("0.0.0.0"), ports, "test")

    check:
      natConfig.hasExtIp
      res.ip == Opt.some(parseIpAddress("1.2.3.4"))
      res.ports == @[Opt.some(ports[0])]

  test "extip with an IPv6 address is parsed but not advertised":
    let
      natConfig = NatConfig.parseCmdArg("extip:2001:db8::1")
      res = setupAddress(natConfig, parseIpAddress("0.0.0.0"), ports, "test")

    check:
      natConfig.hasExtIp
      res.ip.isNone()
      res.ports == @[Opt.some(ports[0])]

  test "extip with an invalid address is rejected":
    expect ValueError:
      discard NatConfig.parseCmdArg("extip:not-an-ip")
