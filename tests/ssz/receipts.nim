import
  unittest2,
  macros,
  ssz_serialization,
  stew/byteutils,std/sequtils  

import
  ../../eth/common/[addresses, base, hashes]
import
  ../../eth/ssz/[receipts,codec]

# Stand in as what the tests will be 
# Need more work done 
template roundTrip*(v: untyped) =
  let bytes  = SSZ.encode(v)
  # Decode failing
  let v2     = SSZ.decode(bytes, v.type)
  let bytes2 = SSZ.encode(v2)
  check bytes == bytes2

macro testRT*(name: static[string], expr: untyped): untyped =
  result = quote do:
    test `name`:
      let v = `expr`
      roundTrip(v)
      check sszSize(v) == SSZ.encode(v).len

suite "SSZ Receipts (EIP-6466)":

  testRT("Log: 0 topics, empty data",
    block:
      let addr11 = Address.copyFrom(newSeqWith(20, byte 0x11))
      Log(
        address: addr11,
        topics: List[Hash32, MAX_TOPICS_PER_LOG](@[]),
        data: @[]
      )
  )

  testRT("Log: 4 topics, some data",
    block:
      let addr22 = Address.copyFrom(newSeqWith(20, byte 0x22))
      var a0, a1, a2, a3: array[32, byte]
      for i in 0 ..< 32:
        a0[i] = 0xA0'u8; a1[i] = 0xA1'u8; a2[i] = 0xA2'u8; a3[i] = 0xA3'u8
      Log(
        address: addr22,
        topics: List[Hash32, MAX_TOPICS_PER_LOG](@[a0.to(Hash32), a1.to(Hash32), a2.to(Hash32), a3.to(Hash32)]),
        data: @[byte 0xDE, 0xAD, 0xBE, 0xEF]
      )
  )

  test "Log decode sanity":
    let addr33 = Address.copyFrom(newSeqWith(20, byte 0x33))
    var t1, t2: array[32, byte]
    for i in 0 ..< 32: t1[i] = 1; t2[i] = 2
    let l = Log(
      address: addr33,
      topics: List[Hash32, MAX_TOPICS_PER_LOG](@[t1.to(Hash32), t2.to(Hash32)]),
      data: @[byte 1,2,3,4]
    )
    let d = SSZ.decode(SSZ.encode(l), Log)
    check:
      d.address == l.address
      d.topics.len == 2
      d.topics[0] == t1.to(Hash32)
      d.topics[1] == t2.to(Hash32)
      d.data == l.data

  # -------- Receipts --------

  testRT("BasicReceipt: single log",
    block:
      let fromAA = Address.copyFrom(newSeqWith(20, byte 0xAA))
      let a10    = Address.copyFrom(newSeqWith(20, byte 0x10))
      var tt: array[32, byte]
      for i in 0 ..< 32: tt[i] = 0xEE
      makeBasicReceipt(
        fromAddr = fromAA,
        gasUsed  = 21'u64,
        logs     = @[
          Log(address: a10,
                topics: List[Hash32, MAX_TOPICS_PER_LOG](@[tt.to(Hash32)]),
                data: @[byte 1,2,3])
        ],
        status   = true
      )
  )

  test "BasicReceipt: reserved contract_address is zero":
    let fromAA = Address.copyFrom(newSeqWith(20, byte 0xAA))
    let rc = makeBasicReceipt(fromAA, 1, @[], true)
    let dec = SSZ.decode(SSZ.encode(rc), Receipt)
    check:
      dec.kind == rkBasic
      dec.basic.contract_address == addresses.zeroAddress

  testRT("CreateReceipt: no logs",
    block:
      let fromBB  = Address.copyFrom(newSeqWith(20, byte 0xBB))
      let addrCC  = Address.copyFrom(newSeqWith(20, byte 0xCC))
      makeCreateReceipt(
        fromAddr     = fromBB,
        gasUsed      = 42'u64,
        contractAddr = addrCC,
        logs         = @[],
        status       = false
      )
  )

  testRT("SetCodeReceipt: authorities with zero + non-zero",
    block:
      let fromDD = Address.copyFrom(newSeqWith(20, byte 0xDD))
      let a55    = Address.copyFrom(newSeqWith(20, byte 0x55))
      let l44    = Address.copyFrom(newSeqWith(20, byte 0x44))
      makeSetCodeReceipt(
        fromAddr    = fromDD,
        gasUsed     = 100'u64,
        authorities = @[addresses.zeroAddress, a55],
        logs        = @[
          Log(address: l44,
                topics: List[Hash32, MAX_TOPICS_PER_LOG](@[]),
                data: @[byte 0x01])
        ],
        status      = true
      )
  )

  test "SetCodeReceipt decode sanity":
    let fromDD = Address.copyFrom(newSeqWith(20, byte 0xDD))
    let a55    = Address.copyFrom(newSeqWith(20, byte 0x55))
    let rc = makeSetCodeReceipt(fromDD, 100, @[addresses.zeroAddress, a55], @[], true)
    let d  = SSZ.decode(SSZ.encode(rc), Receipt)
    check:
      d.kind == rkSetCode
      d.setcode.`from` == fromDD
      d.setcode.gas_used == 100'u64
      d.setcode.contract_address == addresses.zeroAddress
      d.setcode.authorities.len == 2
      d.setcode.authorities[0] == addresses.zeroAddress
      d.setcode.authorities[1] == a55
      d.setcode.status == true


#   test "receiptsRoot stable across roundtrip; changes on mutation":
#     let from01 = Address.copyFrom(newSeqWith(20, byte 0x01))
#     let from02 = Address.copyFrom(newSeqWith(20, byte 0x02))
#     let cAB    = Address.copyFrom(newSeqWith(20, byte 0xAB))

#     let r0 = makeBasicReceipt(from01, 1, @[], true)
#     let r1 = makeCreateReceipt(from02, 2, cAB, @[], false)
#     var receipts = @[r0, r1]

#     let root1 = receiptsRoot(receipts)

#     var receipts2: seq[Receipt]
#     for x in receipts:
#       receipts2.add SSZ.decode(SSZ.encode(x), Receipt)
#     let root2 = receiptsRoot(receipts2)
#     check root1 == root2

#     receipts2[0].basic.gas_used = 999
#     let root3 = receiptsRoot(receipts2)
#     check root3 != root1

  test "Log: large progressive data (128 KiB)":
    let a77 = Address.copyFrom(newSeqWith(20, byte 0x77))
    var t1, t2: array[32, byte]
    for i in 0 ..< 32: t1[i] = 1; t2[i] = 2
    var big = newSeq[byte](128 * 1024)
    for i in 0 ..< big.len: big[i] = byte(i and 0xFF)

    let l = Log(
      address: a77,
      topics: List[Hash32, MAX_TOPICS_PER_LOG](@[t1.to(Hash32), t2.to(Hash32)]),
      data: big
    )
    roundTrip(l)
    check sszSize(l) == SSZ.encode(l).len


#   test "Receipt union selector pinning (0:Basic, 1:Create, 2:SetCode)":
#     check:
#       ord(rkBasic) == 0
#       ord(rkCreate) == 1
#       ord(rkSetCode) == 2