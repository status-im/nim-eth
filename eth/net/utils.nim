import
  std/[tables, hashes],
  stew/results, stew/shims/net as stewNet, chronos, chronicles

{.push raises: [Defect].}

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
