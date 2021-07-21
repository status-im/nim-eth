# nim-eth
# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, hashes],
  stew/results, stew/shims/net as stewNet, chronos, chronicles
from ../p2p/discoveryv5/node import Address

type
  IpLimits* = object
    limit*: uint
    ips: Table[ValidIpAddress, uint]

func hash(ip: ValidIpAddress): Hash = hash($ip)

func inc*(ipLimits: var IpLimits, ip: ValidIpAddress): bool =
  let val = ipLimits.ips.getOrDefault(ip, 0)
  if val < ipLimits.limit:
    ipLimits.ips[ip] = val + 1
    true
  else:
    false

func dec*(ipLimits: var IpLimits, ip: ValidIpAddress) =
  let val = ipLimits.ips.getOrDefault(ip, 0)
  if val == 1:
    ipLimits.ips.del(ip)
  elif val > 1:
    ipLimits.ips[ip] = val - 1

func isPublic*(address: TransportAddress): bool =
  # TODO: Some are still missing, for special reserved addresses see:
  # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  # https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
  if address.isLoopback() or address.isSiteLocal() or
      address.isMulticast() or address.isLinkLocal():
    false
  else:
    true

func isPublic*(address: IpAddress): bool =
  let a = initTAddress(address, Port(0))
  a.isPublic

proc getRouteIpv4*(): Result[ValidIpAddress, cstring] =
  # Avoiding Exception with initTAddress and can't make it work with static.
  # Note: `publicAddress` is only used an "example" IP to find the best route,
  # no data is send over the network to this IP!
  let
    publicAddress = TransportAddress(family: AddressFamily.IPv4,
      address_v4: [1'u8, 1, 1, 1], port: Port(0))
    route = getBestRoute(publicAddress)

  if route.source.isUnspecified():
    err("No best ipv4 route found")
  else:
    let ip = try: route.source.address()
             except ValueError as e:
               # This should not occur really.
               error "Address convertion error", exception = e.name, msg = e.msg
               return err("Invalid IP address")
    ok(ValidIpAddress.init(ip))

proc isWrappedIPv4*(ta: TransportAddress): bool =
  # First 80 bits are all 0;
  # next 16 bits are FFFF;
  # last 32 bits are the IPv4 address.
  if ta.family != AddressFamily.IPv6:
    return false
  for i in 0..9:
   if ta.address_v6[i] != 0x0:
     return false
  if ta.address_v6[10] != 0xff or ta.address_v6[11] != 0xff:
    return false
  return true

proc unwrapIPv4InIPv6*(ta: TransportAddress): TransportAddress = 
  assert ta.isWrappedIPv4
  var address_v4: array[4, uint8]
  address_v4[0] = ta.address_v6[12]
  address_v4[1] = ta.address_v6[13]
  address_v4[2] = ta.address_v6[14]
  address_v4[3] = ta.address_v6[15]
  return TransportAddress(
    family: AddressFamily.IPv4,
    address_v4: address_v4,
    port: ta.port
  )

proc wrapIPv4InIPv6*(ta: TransportAddress): TransportAddress =
  assert ta.family == AddressFamily.IPv4
  var address_v6: array[16, uint8]
  address_v6[10] = 0xff
  address_v6[11] = 0xff
  address_v6[12] = ta.address_v4[0]
  address_v6[13] = ta.address_v4[1]
  address_v6[14] = ta.address_v4[2]
  address_v6[15] = ta.address_v4[3]
  return TransportAddress(
    family: AddressFamily.IPv6,
    address_v6: address_v6,
    port: ta.port
  )
  
proc wrapIPv4InIPv6*(a: Address): Address =
  let ta = initTAddress(a.ip, a.port)
  let wrapped = wrapIPv4InIPv6(ta)
  return Address(
    ip: ipv6(cast[array[16, uint8]](wrapped.address_v6)), port: wrapped.port
  )