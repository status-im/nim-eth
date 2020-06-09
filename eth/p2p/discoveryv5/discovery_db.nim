import
  stint, stew/endians2, stew/shims/net,
  eth/trie/db, types, node

{.push raises: [Defect].}

type
  DiscoveryDB* = ref object of Database
    backend: TrieDatabaseRef

  DbKeyKind = enum
    kNodeToKeys = 100

proc init*(T: type DiscoveryDB, backend: TrieDatabaseRef): DiscoveryDB =
  T(backend: backend)

const keySize = 1 + # unique triedb prefix (kNodeToKeys)
                sizeof(NodeId) +
                16 + # max size of ip address (ipv6)
                2 # Sizeof port

proc makeKey(id: NodeId, address: Address): array[keySize, byte] =
  result[0] = byte(kNodeToKeys)
  var pos = 1
  result[pos ..< pos+sizeof(id)] = toBytes(id)
  pos.inc(sizeof(id))
  case address.ip.family
  of IpAddressFamily.IpV4:
    result[pos ..< pos+sizeof(address.ip.address_v4)] = address.ip.address_v4
  of IpAddressFamily.IpV6:
    result[pos..< pos+sizeof(address.ip.address_v6)] = address.ip.address_v6
  pos.inc(sizeof(address.ip.address_v6))
  result[pos ..< pos+sizeof(address.port)] = toBytes(address.port.uint16)

method storeKeys*(db: DiscoveryDB, id: NodeId, address: Address, r, w: AesKey):
    bool =
  try:
    var value: array[sizeof(r) + sizeof(w), byte]
    value[0 .. 15] = r
    value[16 .. ^1] = w
    db.backend.put(makeKey(id, address), value)
    return true
  except CatchableError:
    return false

method loadKeys*(db: DiscoveryDB, id: NodeId, address: Address,
    r, w: var AesKey): bool =
  try:
    let res = db.backend.get(makeKey(id, address))
    if res.len != sizeof(r) + sizeof(w):
      return false
    copyMem(addr r[0], unsafeAddr res[0], sizeof(r))
    copyMem(addr w[0], unsafeAddr res[sizeof(r)], sizeof(w))
    return true
  except CatchableError:
    return false

method deleteKeys*(db: DiscoveryDB, id: NodeId, address: Address): bool =
  try:
    db.backend.del(makeKey(id, address))
    return true
  except CatchableError:
    return false
