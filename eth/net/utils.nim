import
  std/[tables, hashes],
  stew/shims/net as stewNet, chronos

{.push raises: [Defect].}

type
  IpLimits* = object
    limit*: uint
    ips: Table[ValidIpAddress, uint]

proc hash(ip: ValidIpAddress): Hash = hash($ip)

proc inc*(ipLimits: var IpLimits, ip: ValidIpAddress): bool =
  let val = ipLimits.ips.getOrDefault(ip, 0)
  if val < ipLimits.limit:
    ipLimits.ips[ip] = val + 1
    true
  else:
    false

proc dec*(ipLimits: var IpLimits, ip: ValidIpAddress) =
  let val = ipLimits.ips.getOrDefault(ip, 0)
  if val == 1:
    ipLimits.ips.del(ip)
  elif val > 1:
    ipLimits.ips[ip] = val - 1

proc isPublic*(address: TransportAddress): bool {.raises: [Defect].} =
  # TODO: Some are still missing, for special reserved addresses see:
  # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  # https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
  if address.isLoopback() or address.isSiteLocal() or
      address.isMulticast() or address.isLinkLocal():
    false
  else:
    true
