import types
import eth/trie/db

type
  DiscoveryDB* = ref object of Database
    backend: TrieDatabaseRef

  DbKeyKind = enum
    kNodeToKeys = 100

proc init*(T: type DiscoveryDB, backend: TrieDatabaseRef): DiscoveryDB =
  T(backend: backend)

proc makeKey(id: NodeId, address: int): array[1 + sizeof(id) + sizeof(address), byte] =
  result[0] = byte(kNodeToKeys)
  copyMem(addr result[1], unsafeAddr id, sizeof(id))
  copyMem(addr result[sizeof(id) + 1], unsafeAddr address, sizeof(address))

method storeKeys*(db: DiscoveryDB, id: NodeId, address: int, r, w: array[16, byte]) =
  var value: array[sizeof(r) + sizeof(w), byte]
  value[0 .. 15] = r
  value[16 .. ^1] = w
  db.backend.put(makeKey(id, address), value)

method loadKeys*(db: DiscoveryDB, id: NodeId, address: int, r, w: var array[16, byte]): bool =
  let res = db.backend.get(makeKey(id, address))
  if res.len == sizeof(r) + sizeof(w):
    copyMem(addr r[0], unsafeAddr res[0], sizeof(r))
    copyMem(addr w[0], unsafeAddr res[sizeof(r)], sizeof(w))
    result = true
