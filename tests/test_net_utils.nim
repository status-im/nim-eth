# nim-eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ../eth/net/utils

suite "Net utils":
  test "Globally assigned addresses":
    check:
      not isLocallyAssigned(parseIpAddress("1.2.3.4"))
      not isLocallyAssigned(parseIpAddress("2606:4700:4700::1111"))

  test "Private IPv4 addresses are locally assigned":
    check:
      isLocallyAssigned(parseIpAddress("10.0.0.1"))
      isLocallyAssigned(parseIpAddress("172.16.0.1"))
      isLocallyAssigned(parseIpAddress("192.168.0.1"))

  test "Unique local IPv6 addresses are locally assigned":
    check:
      isLocallyAssigned(parseIpAddress("fc00::1"))
      isLocallyAssigned(parseIpAddress("fd12:3456:789a::1"))
      isLocallyAssigned(parseIpAddress("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
      isLocallyAssigned(parseIpAddress("fec0::1"))

  test "Loopback and link local addresses are locally assigned":
    check:
      isLocallyAssigned(parseIpAddress("127.0.0.1"))
      isLocallyAssigned(parseIpAddress("::1"))
      isLocallyAssigned(parseIpAddress("169.254.0.1"))
      isLocallyAssigned(parseIpAddress("fe80::1"))

  test "Locally assigned addresses are not global unicast":
    # An address that passes as globally routable but not as public would enter
    # the routing table without being counted against its ip limits.
    check:
      isGlobalUnicast(parseIpAddress("1.2.3.4"))
      isGlobalUnicast(parseIpAddress("2606:4700:4700::1111"))
      not isGlobalUnicast(parseIpAddress("192.168.0.1"))
      not isGlobalUnicast(parseIpAddress("fd12:3456:789a::1"))
      not isGlobalUnicast(parseIpAddress("fec0::1"))
