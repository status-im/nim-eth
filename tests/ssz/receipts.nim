import
  unittest2,
  ssz_serialization,
  macros,
  std/sequtils,
  ../../eth/common/[addresses, base, hashes],
  ../../eth/ssz/[receipts,codec]

template roundTrip*(v: var untyped) =
  var bytes = SSZ.encode(v)
  var v2 = SSZ.decode(bytes, v.type)
  var bytes2 = SSZ.encode(v2)
  check bytes == bytes2
template topicFill(b: byte): untyped =
  (block:
    var buf: array[32, byte]
    for i in 0 ..< 32:
      buf[i] = b
    Hash32.copyFrom(buf)
  )
# Idea- pass only l values to this

macro testRT*(name: static[string], expr: typed): untyped =
  ## Roundtrip SSZ + size check.
  let valueSym   = genSym(nskLet, "rtValue")
  let bytesSym   = genSym(nskLet, "rtEncoded")
  let value2Sym  = genSym(nskVar, "rtDecoded")
  let bytes2Sym  = genSym(nskLet, "rtReencoded")

  result = quote do:
    test `name`:
      let `valueSym` = `expr`
      when compiles(encodeReceipt(`valueSym`)):
        let `bytesSym`  = encodeReceipt(`valueSym`)
        var `value2Sym` = decodeReceipt[type(`valueSym`)](`bytesSym`)
        let `bytes2Sym` = encodeReceipt(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(asTagged(`valueSym`)) == `bytesSym`.len
      else:
        let `bytesSym`  = SSZ.encode(`valueSym`)
        var `value2Sym` = SSZ.decode(`bytesSym`, type(`valueSym`))
        let `bytes2Sym` = SSZ.encode(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(`valueSym`) == `bytesSym`.len

macro testRT*(name: static[string], expr: typed, body: untyped): untyped =
  ## Same as above, with an extra assertions block.
  let valueSym   = genSym(nskLet, "rtValue")
  let bytesSym   = genSym(nskLet, "rtEncoded")
  let value2Sym  = genSym(nskVar, "rtDecoded")
  let bytes2Sym  = genSym(nskLet, "rtReencoded")
  let userAlias  = ident("v")

  result = quote do:
    test `name`:
      let `valueSym` = `expr`
      when compiles(encodeReceipt(`valueSym`)):
        let `bytesSym`  = encodeReceipt(`valueSym`)
        var `value2Sym` = decodeReceipt[type(`valueSym`)](`bytesSym`)
        let `bytes2Sym` = encodeReceipt(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(asTagged(`valueSym`)) == `bytesSym`.len
      else:
        let `bytesSym`  = SSZ.encode(`valueSym`)
        var `value2Sym` = SSZ.decode(`bytesSym`, type(`valueSym`))
        let `bytes2Sym` = SSZ.encode(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(`valueSym`) == `bytesSym`.len
      block:
        let `userAlias` = `valueSym`
        `body`

suite "Log Construction (SSZ)":
  testRT "Log: empty topics",
    Log(
      address: addresses.zeroAddress,
      topics: List[Hash32, MAX_TOPICS_PER_LOG](@[]),
      data: @[]
    )
  
  testRT "Log: max topics",
    (block:
      let addrAA = Address.copyFrom(newSeqWith(20, byte 0xAA))
      Log(
        address: addrAA,
        topics: List[Hash32, MAX_TOPICS_PER_LOG](@[
          topicFill(0x10), topicFill(0x11), topicFill(0x12), topicFill(0x13)
        ]),
        data: @[byte 0xDE, 0xAD, 0xBE, 0xEF]
      )
    ):
    check v.topics.len == 4
  
  testRT "BasicReceipt roundtrip",
    BasicReceipt(
      `from`: addresses.zeroAddress,
      gas_used: 100'u64,
      contract_address: addresses.zeroAddress,
      logs: @[],
      status: true
    )

  
  
  # suite "Receipts Construction (SSZ)":
  #   test "Basic receipt":
  #     var log0 = Log(
  #       address: default(Address),
  #       topics: default(List[Hash32, MAX_TOPICS_PER_LOG]),
  #       data: @[]
  #     )
  
  #     var rec = Receipt(
  #       kind: rkBasic,
  #       basic: BasicReceipt(
  #         `from`: default(Address),
  #         gas_used: 100'u64,
  #         contract_address: default(Address),
  #         logs: @[log0],
  #         status: true
  #       )
  #     )

  # test "Create receipt":
  #   var log1 = Log(
  #     address: default(Address),
  #     topics:default(List[Hash32, MAX_TOPICS_PER_LOG]),
  #     data: @[byte 0x01, 0x02, 0x03],
  #   )
  #   var createdAddr = address"0x00000000000000000000000000000000000000aa"

  #   var rec = Receipt(
  #     kind: rkCreate,
  #     create: CreateReceipt(
  #       `from`: address"0x00000000000000000000000000000000000000bb",
  #       gas_used: 21000'u64,
  #       contract_address: createdAddr,
  #       logs: @[log1],
  #       status: false,
  #     ),
  #   )
  #   # roundTrip(rec)

  # test "SetCode receipt":
  #   var log2 = Log(
  #     address: address"0x00000000000000000000000000000000000000cc",
  #     topics: default(List[Hash32, MAX_TOPICS_PER_LOG]),
  #   )

  #   var rec = Receipt(
  #     kind: rkSetCode,
  #     setcode: SetCodeReceipt(
  #       `from`: address"0x00000000000000000000000000000000000000dd",
  #       gas_used: 42000'u64,
  #       contract_address: address"0x00000000000000000000000000000000000000ee",
  #       logs: @[log2],
  #       status: true,
  #       authorities:
  #         @[
  #           address"0x00000000000000000000000000000000000000f1",
  #           address"0x00000000000000000000000000000000000000f2",
  #         ],
  #     ),
  #   )


# suite "SSZ Receipts (EIP-6466)":
#   var addr22 = Address.copyFrom(newSeqWith(20, byte 0x22))

#   test "Log: 0 topics, empty data":
#     var l =
#       Log(address: addr22, topics: List[Hash32, MAX_TOPICS_PER_LOG](@[]), data: @[])
#     # testRT("Log: 0 topics, empty data", l)

#   # test "Log: 4 topics, some data":
#   #   let addr22 = Address.copyFrom(newSeqWith(20, byte 0x22))
#   #   var a0, a1, a2, a3: array[32, byte]
#   #   for i in 0 ..< 32:
#   #     a0[i] = 0xA0'u8; a1[i] = 0xA1'u8; a2[i] = 0xA2'u8; a3[i] = 0xA3'u8
#   #   var l = Log(
#   #     address: addr22,
#   #     topics: List[Hash32, MAX_TOPICS_PER_LOG](@[a0.to(Hash32), a1.to(Hash32), a2.to(Hash32), a3.to(Hash32)]),
#   #     data: @[byte 0xDE, 0xAD, 0xBE, 0xEF]
#   #   )
#   #   testRT("Log: 4 topics, some data", l)

#   test "Log decode sanity":
#     let addr33 = Address.copyFrom(newSeqWith(20, byte 0x33))
#     var t1, t2: array[32, byte]
#     for i in 0 ..< 32: t1[i] = 1; t2[i] = 2
#     let l = Log(
#       address: addr33,
#       topics: List[Hash32, MAX_TOPICS_PER_LOG](@[t1.to(Hash32), t2.to(Hash32)]),
#       data: @[byte 1,2,3,4]
#     )
#     var d = SSZ.decode(SSZ.encode(l), Log)
#     check:
#       d.address == l.address
#       d.topics.len == 2
#       d.topics[0] == t1.to(Hash32)
#       d.topics[1] == t2.to(Hash32)
#       d.data == l.data

#   # ---------- Receipts ----------
#   test "BasicReceipt: single log":
#     let fromAA = Address.copyFrom(newSeqWith(20, byte 0xAA))
#     let a10    = Address.copyFrom(newSeqWith(20, byte 0x10))
#     var tt: array[32, byte]
#     for i in 0 ..< 32: tt[i] = 0xEE
#     var rc = makeBasicReceipt(
#       fromAddr = fromAA,
#       gasUsed  = 21'u64,
#       logs     = @[
#         Log(
#           address: a10,
#           topics: List[Hash32, MAX_TOPICS_PER_LOG](@[tt.to(Hash32)]),
#           data: @[byte 1,2,3]
#         )
#       ],
#       status   = true
#     )
#     testRT("BasicReceipt: single log", rc)

#   test "BasicReceipt: reserved contract_address is zero":
#     let fromAA = Address.copyFrom(newSeqWith(20, byte 0xAA))
#     let rc = makeBasicReceipt(fromAA, 1, @[], true)
#     let dec = SSZ.decode(SSZ.encode(rc), Receipt)
#     check:
#       dec.kind == rkBasic
#       dec.basic.contract_address == addresses.zeroAddress

#   test "CreateReceipt: no logs":
#     let fromBB  = Address.copyFrom(newSeqWith(20, byte 0xBB))
#     let addrCC  = Address.copyFrom(newSeqWith(20, byte 0xCC))
#     var rc = makeCreateReceipt(
#       fromAddr     = fromBB,
#       gasUsed      = 42'u64,
#       contractAddr = addrCC,
#       logs         = @[],
#       status       = false
#     )
#     testRT("CreateReceipt: no logs", rc)

#   test "SetCodeReceipt: authorities with zero + non-zero":
#     let fromDD = Address.copyFrom(newSeqWith(20, byte 0xDD))
#     let a55    = Address.copyFrom(newSeqWith(20, byte 0x55))
#     let l44    = Address.copyFrom(newSeqWith(20, byte 0x44))
#     var rc = makeSetCodeReceipt(
#       fromAddr    = fromDD,
#       gasUsed     = 100'u64,
#       authorities = @[addresses.zeroAddress, a55],
#       logs        = @[
#         Log(
#           address: l44,
#           topics: List[Hash32, MAX_TOPICS_PER_LOG](@[]),
#           data: @[byte 0x01]
#         )
#       ],
#       status      = true
#     )
#     testRT("SetCodeReceipt: authorities with zero + non-zero", rc)

#   test "SetCodeReceipt decode sanity":
#     let fromDD = Address.copyFrom(newSeqWith(20, byte 0xDD))
#     let a55    = Address.copyFrom(newSeqWith(20, byte 0x55))
#     let rc = makeSetCodeReceipt(fromDD, 100, @[addresses.zeroAddress, a55], @[], true)
#     let d  = SSZ.decode(SSZ.encode(rc), Receipt)
#     check:
#       d.kind == rkSetCode
#       d.setcode.`from` == fromDD
#       d.setcode.gas_used == 100'u64
#       d.setcode.contract_address == addresses.zeroAddress
#       d.setcode.authorities.len == 2
#       d.setcode.authorities[0] == addresses.zeroAddress
#       d.setcode.authorities[1] == a55
#       d.setcode.status == true

#   # test "receiptsRoot stable across roundtrip; changes on mutation":
#   #   let from01 = Address.copyFrom(newSeqWith(20, byte 0x01))
#   #   let from02 = Address.copyFrom(newSeqWith(20, byte 0x02))
#   #   let cAB    = Address.copyFrom(newSeqWith(20, byte 0xAB))
#   #   let r0 = makeBasicReceipt(from01, 1, @[], true)
#   #   let r1 = makeCreateReceipt(from02, 2, cAB, @[], false)
#   #   var receipts = @[r0, r1]
#   #   let root1 = receiptsRoot(receipts)
#   #   var receipts2: seq[Receipt]
#   #   for x in receipts:
#   #     receipts2.add SSZ.decode(SSZ.encode(x), Receipt)
#   #   let root2 = receiptsRoot(receipts2)
#   #   check root1 == root2
#   #   receipts2[0].basic.gas_used = 999
#   #   let root3 = receiptsRoot(receipts2)
#   #   check root3 != root1

#   test "Log: large progressive data (128 KiB)":
#     let a77 = Address.copyFrom(newSeqWith(20, byte 0x77))
#     var t1, t2: array[32, byte]
#     for i in 0 ..< 32: t1[i] = 1; t2[i] = 2
#     var big = newSeq[byte](128 * 1024)
#     for i in 0 ..< big.len: big[i] = byte(i and 0xFF)

#     var l = Log(
#       address: a77,
#       topics: List[Hash32, MAX_TOPICS_PER_LOG](@[t1.to(Hash32), t2.to(Hash32)]),
#       data: big
#     )
#     testRT("Log: large progressive data (128 KiB)", l)

#   # test "Receipt union selector pinning (0:Basic, 1:Create, 2:SetCode)":
#   #   check:
#   #     ord(rkBasic) == 0
#   #     ord(rkCreate) == 1
#   #     ord(rkSetCode) == 2
