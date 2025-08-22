import ".."/common/[addresses, hashes, base]
import ../rlp
import ssz_serialization
import json_serialization

# import std/[typetraits, hashes], nimcrypto/keccak, stew/assign2

# # SSZ for addresses
# proc toSszType*(x: Address): var array[20, byte] {.inline.} =

# proc fromSszBytes*(T: type Address, bytes: var openArray[byte]): Address {.inline.} =
#   doAssert bytes.len == 20
#   Address.copyFrom(bytes)

# # SSZ for hash32
# proc toSszType*(x: Hash32): var array[32, byte] {.inline.} =

# proc fromSszBytes*(T: type Hash32, bytes: var openArray[byte]): Hash32 {.inline.} =
#   doAssert bytes.len == 32
#   Hash32.copyFrom(bytes)

# template toSszType*(T: type Address): untyped = array[20, byte]
# template toSszType*(T: type Hash32): untyped = array[32, byte]

proc rlpToSsz*[T](bytes: openArray[byte]): seq[byte] =
  var r = rlpFromBytes(bytes)
  let v = r.read(T)
  SSZ.encode(v)

proc jsonToSsz*[T](data: string): seq[byte] =
  let v = Json.decode(data, T)
  SSZ.encode(v)
