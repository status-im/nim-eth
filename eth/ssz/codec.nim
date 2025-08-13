import ".."/common/[addresses,hashes]

# SSZ for addresses
proc toSszType*(x: Address): array[20, byte] {.inline.} =
  x.data

proc fromSszBytes*(T: type Address, bytes: openArray[byte]): Address {.inline.} =
  doAssert bytes.len == 20
  Address.copyFrom(bytes)

# SSZ for hash32
proc toSszType*(x: Hash32): array[32, byte] {.inline.} =
  x.data

proc fromSszBytes*(T: type Hash32, bytes: openArray[byte]): Hash32 {.inline.} =
  doAssert bytes.len == 32
  Hash32.copyFrom(bytes)