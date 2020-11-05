import
  std/[tables, hashes],
  stew/shims/net as stewNet

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
