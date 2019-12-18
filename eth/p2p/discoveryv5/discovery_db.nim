import std/net
import types, ../enode
import eth/trie/db

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
  copyMem(addr result[1], unsafeAddr id, sizeof(id))
  case address.ip.family
  of IpAddressFamily.IpV4:
    copyMem(addr result[sizeof(id) + 1], unsafeAddr address.ip.address_v4, sizeof(address.ip.address_v4))
  of IpAddressFamily.IpV6:
    copyMem(addr result[sizeof(id) + 1], unsafeAddr address.ip.address_v6, sizeof(address.ip.address_v6))
  copyMem(addr result[sizeof(id) + 1 + sizeof(address.ip.address_v6)], unsafeAddr address.udpPort, sizeof(address.udpPort))

method storeKeys*(db: DiscoveryDB, id: NodeId, address: Address, r, w: array[16, byte]) =
  var value: array[sizeof(r) + sizeof(w), byte]
  value[0 .. 15] = r
  value[16 .. ^1] = w
  db.backend.put(makeKey(id, address), value)

method loadKeys*(db: DiscoveryDB, id: NodeId, address: Address, r, w: var array[16, byte]): bool =
  let res = db.backend.get(makeKey(id, address))
  if res.len == sizeof(r) + sizeof(w):
    copyMem(addr r[0], unsafeAddr res[0], sizeof(r))
    copyMem(addr w[0], unsafeAddr res[sizeof(r)], sizeof(w))
    result = true
