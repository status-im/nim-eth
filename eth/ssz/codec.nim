import ".."/common/[addresses, hashes, base]
import ../rlp
import ssz_serialization
import json_serialization

# SSZ for Address
template toSszType*(T: type Address): untyped = 
  array[20, byte]

template toSszType*(x: Address): untyped = 
  x.data

proc toSszType*(x: var Address): var array[20, byte] {.inline.} =
  x.data

proc fromSszBytes*(T: type Address, bytes: openArray[byte]): Address {.inline.} =
  doAssert bytes.len == 20
  Address.copyFrom(bytes)

# SSZ for Hash32
template toSszType*(T: type Hash32): untyped = 
  array[32, byte]

template toSszType*(x: Hash32): untyped = 
  x.data

proc toSszType*(x: var Hash32): var array[32, byte] {.inline.} =
  x.data

proc fromSszBytes*(T: type Hash32, bytes: openArray[byte]): Hash32 {.inline.} =
  doAssert bytes.len == 32
  Hash32.copyFrom(bytes)

proc rlpToSsz*[T](bytes: openArray[byte]): seq[byte] =
  var r = rlpFromBytes(bytes)
  let v = r.read(T)
  SSZ.encode(v)

proc jsonToSsz*[T](data: string): seq[byte] =
  let v = Json.decode(data, T)
  SSZ.encode(v)