import unittest2
import ../../eth/ssz/codec
import ../../eth/common/[addresses, hashes, base, eth_types_json_serialization]
import ../../eth/rlp
import ssz_serialization

suite "SSZ codec transforms":
  test "rlpToSsz and back for uint64":
    let value: uint64 = 0x1234'u64
    let rlpBytes = encode(value)
    let sszBytes = rlpToSsz[uint64](rlpBytes)
    let decoded = SSZ.decode(uint64, sszBytes)
    check decoded == value

  test "jsonToSsz and back for uint64":
    let value: uint64 = 0x5678'u64
    let jsonData = $(value)
    let sszBytes = jsonToSsz[uint64](jsonData)
    let decoded = SSZ.decode(uint64, sszBytes)
    check decoded == value

  test "rlpToSsz and back for Address":
    let addr = fromHex(Address, "0x0011223344556677889900112233445566778899")
    let rlpBytes = encode(addr)
    let sszBytes = rlpToSsz[Address](rlpBytes)
    let restored = SSZ.decode(Address, sszBytes)
    check restored == addr

  test "jsonToSsz and back for Address":
    let addr = fromHex(Address, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    let jsonData = "\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
    let sszBytes = jsonToSsz[Address](jsonData)
    let restored = SSZ.decode(Address, sszBytes)
    check restored == addr
