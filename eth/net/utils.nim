# nim-eth
# Copyright (c) 2020-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[tables, hashes, net],
  results, chronos, chronicles

export net.IpAddress

const
  IpLimitSubnetV4* = 24
    ## The IPv4 prefix length that the ip limits are counted on. Prefixes
    ## longer than a /24 are commonly filtered out of the global routing
    ## tables, which makes a /24 the smallest block that can be obtained and
    ## announced on its own.
  IpLimitSubnetV6* = 64
    ## The IPv6 prefix length that the ip limits are counted on. A /64 is what
    ## a single network gets assigned, down to a home gateway, and the
    ## addresses in it are free to pick for its host. It is thus the equivalent
    ## of the single address that such a gateway has on IPv4.

type
  IpLimits* = object
    limit*: uint ## Maximum amount of addresses allowed per subnet
    ips: Table[IpAddress, uint]

func hash*(ip: IpAddress): Hash =
  case ip.family
  of IpAddressFamily.IPv6: hash(ip.address_v6)
  of IpAddressFamily.IPv4: hash(ip.address_v4)

func subnet*(ip: IpAddress): IpAddress =
  ## The subnet of the `ip` that the limits are counted on. Counting
  ## exact addresses instead would make the limits meaningless for anyone
  ## holding a prefix, which for IPv6 is every regular end user.
  var masked = ip
  case ip.family
  of IpAddressFamily.IPv4:
    for i in IpLimitSubnetV4 div 8 ..< masked.address_v4.len:
      masked.address_v4[i] = 0
  of IpAddressFamily.IPv6:
    for i in IpLimitSubnetV6 div 8 ..< masked.address_v6.len:
      masked.address_v6[i] = 0

  masked

func inc*(ipLimits: var IpLimits, ip: IpAddress): bool =
  let
    subnet = ip.subnet()
    val = ipLimits.ips.getOrDefault(subnet, 0)
  if val < ipLimits.limit:
    ipLimits.ips[subnet] = val + 1
    true
  else:
    false

func dec*(ipLimits: var IpLimits, ip: IpAddress) =
  let
    subnet = ip.subnet()
    val = ipLimits.ips.getOrDefault(subnet, 0)
  if val == 1:
    ipLimits.ips.del(subnet)
  elif val > 1:
    ipLimits.ips[subnet] = val - 1

func isGlobalUnicast*(address: TransportAddress): bool =
  if address.isGlobal() and address.isUnicast():
    true
  else:
    false

func isGlobalUnicast*(address: IpAddress): bool =
  let a = initTAddress(address, Port(0))
  a.isGlobalUnicast()

func isPublic*(address: IpAddress): bool =
  ## Returns true for globally routable (public) addresses
  let a = initTAddress(address, Port(0))
  not (a.isLoopback() or a.isSiteLocal() or a.isLinkLocal())

proc getRouteIpv4*(): Result[IpAddress, cstring] =
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
               error "Address conversion error", exception = e.name, msg = e.msg
               return err("Invalid IP address")
    ok(ip)

func ipv4*(address: array[4, byte]): IpAddress =
  IpAddress(family: IPv4, address_v4: address)

func ipv6*(address: array[16, byte]): IpAddress =
  IpAddress(family: IPv6, address_v6: address)
