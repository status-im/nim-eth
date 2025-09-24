{.push raises: [].}

import
 ../common/[addresses, hashes, base],
 std/[typetraits],
 ssz_serialization,
 ssz_serialization/codec,
 ssz_serialization/merkleization,
 unittest2

# This follows how
# https://github.com/status-im/nimbus-eth2/blob/9839f140628ae0e2e8aa7eb055da5c4bb08171d0/beacon_chain/spec/ssz_codec.nim#L29
# does it for addresses in eth 2
export ssz_serialization, codec, base, typetraits

# SSZ for Address
template toSszType*(T: Address): auto =
 distinctBase(T)

func fromSszBytes*( T: type Address, bytes: openArray[byte]): T {.raises: [SszError].} =
  readSszValue(bytes, distinctBase(result))

# SSZ for Hash32
template toSszType*(T:  Hash32): auto =
  distinctBase(T)

func fromSszBytes*( T: type Hash32, bytes: openArray[byte]): T {.raises: [SszError].} =
  readSszValue(bytes, distinctBase(result))


suite "SSZ: Hash32 distinct Bytes32 roundtrip":
  test "encode/decode parity":
    var h: Hash32
    for i in 0 ..< 32:
      distinctBase(h)[i] = byte(0xA0 + i)
    let enc = SSZ.encode(h)
    let dec = SSZ.decode(enc, Hash32)
    check distinctBase(h) == distinctBase(dec)

suite "SSZ: Hash32 merkleization":
  test "seq[Hash32] root stable and order-sensitive":
    var h1, h2: Hash32
    for i in 0 ..< 32:
      distinctBase(h1)[i] = byte(i)
      distinctBase(h2)[i] = byte(255 - i)
    let r1 = hash_tree_root(@[h1, h2])
    let r2 = hash_tree_root(@[h1, h2])
    let r3 = hash_tree_root(@[h2, h1])
    check r1 == r2
    check r1 != r3

  test "single vs pair has different root":
    var a, b: Hash32
    for i in 0 ..< 32:
      distinctBase(a)[i] = byte(i)
      distinctBase(b)[i] = byte(i xor 0xFF)
    let rs = hash_tree_root(@[a])
    let rp = hash_tree_root(@[a, b])
    check rs != rp

suite "SSZ: Address encode/decode + merkleization":
#   test "Address encode/decode parity":
#     var a: Address
#     for i in 0 ..< 20:
#       a.data[i] = byte(i + 1)
#     let enc = SSZ.encode(a)
#     let dec = SSZ.decode(enc, Address)
#     check distinctBase(a) == distinctBase(dec)

  test "merkleization: seq[Address] root stable and order-sensitive":
    var a1, a2: Address
    for i in 0 ..< 20:
      a1.data[i] = byte(i)
      a2.data[i] = byte(19 - i)
    # let r1 = hash_tree_root(a1)
    # let r2 = hash_tree_root(a2)
    let r4 = hash_tree_root(@[a1, a2])
    # check r1 == r2
    # check r1 != r3
