# nim-eth
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[tables, hashes, net],
  results, chronos, chronicles

export net.IpAddress

type
  IpLimits* = object
    limit*: uint
    ips: Table[IpAddress, uint]

func hash*(ip: IpAddress): Hash =
  case ip.family
  of IpAddressFamily.IPv6: hash(ip.address_v6)
  of IpAddressFamily.IPv4: hash(ip.address_v4)

func inc*(ipLimits: var IpLimits, ip: IpAddress): bool =
  let val = ipLimits.ips.getOrDefault(ip, 0)
  if val < ipLimits.limit:
    ipLimits.ips[ip] = val + 1
    true
  else:
    false

func dec*(ipLimits: var IpLimits, ip: IpAddress) =
  let val = ipLimits.ips.getOrDefault(ip, 0)
  if val == 1:
    ipLimits.ips.del(ip)
  elif val > 1:
    ipLimits.ips[ip] = val - 1

func isGlobalUnicast*(address: TransportAddress): bool =
  if address.isGlobal() and address.isUnicast():
    true
  else:
    false

func isGlobalUnicast*(address: IpAddress): bool =
  let a = initTAddress(address, Port(0))
  a.isGlobalUnicast()

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

proc getRouteIpv6*(): Result[IpAddress, cstring] =
  # Avoiding Exception with initTAddress and can't make it work with static.
  # Note: `publicAddress` is only used an "example" IP to find the best route,
  # no data is send over the network to this IP!
  let
    publicAddress = TransportAddress(family: AddressFamily.IPv6,
      address_v6: [1'u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], port: Port(0))
    route = getBestRoute(publicAddress)

  if route.source.isUnspecified():
    err("No best ipv6 route found")
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
