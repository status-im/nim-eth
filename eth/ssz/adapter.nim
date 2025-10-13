{.push raises: [].}

import
  ../common/[addresses, hashes, base],
  std/[typetraits],
  ssz_serialization,
  ssz_serialization/codec,
  ssz_serialization/merkleization

# This follows how
# https://github.com/status-im/nimbus-eth2/blob/9839f140628ae0e2e8aa7eb055da5c4bb08171d0/beacon_chain/spec/ssz_codec.nim#L29
# does it for addresses in eth 2
export ssz_serialization, codec, base, typetraits

# SSZ for Address
template toSszType*(T: Address): auto =
  distinctBase(T)

func fromSszBytes*(T: type Address, bytes: openArray[byte]): T {.raises: [SszError].} =
  readSszValue(bytes, distinctBase(result))

# SSZ for Hash32
template toSszType*(T: Hash32): auto =
  distinctBase(T)

func fromSszBytes*(T: type Hash32, bytes: openArray[byte]): T {.raises: [SszError].} =
  readSszValue(bytes, distinctBase(result))

# SSZ for Bytes32
template toSszType*(T: Bytes32): auto =
  distinctBase(T)

func fromSszBytes*(T: type Bytes32, bytes: openArray[byte]): T {.raises: [SszError].} =
  readSszValue(bytes, distinctBase(result))
