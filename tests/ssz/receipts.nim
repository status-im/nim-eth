import
  unittest2,
  ssz_serialization/merkleization,
  ssz_serialization,
  macros,
  std/sequtils,
  ../../eth/common/[addresses, base, hashes],
  ../../eth/ssz/[receipts_ssz, adapter]

proc topicFill*(b: SomeInteger): Bytes32 =
  var a: array[32, byte]
  let v = byte(b)
  for i in 0 ..< 32:
    a[i] = v
  Bytes32.copyFrom(a)

template roundTrip*(v: var untyped) =
  var bytes = SSZ.encode(v)
  var v2 = SSZ.decode(bytes, v.type)
  var bytes2 = SSZ.encode(v2)
  check bytes == bytes2

template topicList(args: varargs[Bytes32]): untyped =
  List[Bytes32, MAX_TOPICS_PER_LOG].init(@args)

macro testRT*(name: static[string], expr: typed): untyped =
  ## Roundtrip SSZ + size check.
  let valueSym = genSym(nskLet, "rtValue")
  let bytesSym = genSym(nskLet, "rtEncoded")
  let value2Sym = genSym(nskVar, "rtDecoded")
  let bytes2Sym = genSym(nskLet, "rtReencoded")

  result = quote:
    test `name`:
      let `valueSym` = `expr`
      when compiles(encodeReceipt(`valueSym`)):
        let `bytesSym` = encodeReceipt(`valueSym`)
        var `value2Sym` = decodeReceipt[type(`valueSym`)](`bytesSym`)
        let `bytes2Sym` = encodeReceipt(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(asTagged(`valueSym`)) == `bytesSym`.len
      else:
        let `bytesSym` = SSZ.encode(`valueSym`)
        var `value2Sym` = SSZ.decode(`bytesSym`, type(`valueSym`))
        let `bytes2Sym` = SSZ.encode(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(`valueSym`) == `bytesSym`.len

macro testRT*(name: static[string], expr: typed, body: untyped): untyped =
  ## Same as above, with an extra assertions block.
  let valueSym = genSym(nskLet, "rtValue")
  let bytesSym = genSym(nskLet, "rtEncoded")
  let value2Sym = genSym(nskVar, "rtDecoded")
  let bytes2Sym = genSym(nskLet, "rtReencoded")
  let userAlias = ident("v")

  result = quote:
    test `name`:
      let `valueSym` = `expr`
      when compiles(encodeReceipt(`valueSym`)):
        let `bytesSym` = encodeReceipt(`valueSym`)
        var `value2Sym` = decodeReceipt[type(`valueSym`)](`bytesSym`)
        let `bytes2Sym` = encodeReceipt(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(asTagged(`valueSym`)) == `bytesSym`.len
      else:
        let `bytesSym` = SSZ.encode(`valueSym`)
        var `value2Sym` = SSZ.decode(`bytesSym`, type(`valueSym`))
        let `bytes2Sym` = SSZ.encode(`value2Sym`)
        check `bytesSym` == `bytes2Sym`
        check sszSize(`valueSym`) == `bytesSym`.len
      block:
        let `userAlias` = `valueSym`
        `body`

suite "Log Construction (SSZ)":
  testRT "Log: empty topics",
    Log(address: addresses.zeroAddress, topics: topicList(), data: @[])

  testRT "Log: max topics",
    (
      block:
        let addrAA = Address.copyFrom(newSeqWith(20, byte 0xAA))
        Log(
          address: addrAA,
          topics: topicList(
            topicFill(0x10), topicFill(0x11), topicFill(0x12), topicFill(0x13)
          ),
          data: @[byte 0xDE, 0xAD, 0xBE, 0xEF],
        )
    )

  testRT "Log: 4 topics, some data",
    (
      block:
        let addr22 = Address.copyFrom(newSeqWith(20, byte 0x22))
        var a0, a1, a2, a3: array[32, byte]
        for i in 0 ..< 32:
          a0[i] = 0xA0'u8
          a1[i] = 0xA1'u8
          a2[i] = 0xA2'u8
          a3[i] = 0xA3'u8
        Log(
          address: addr22,
          topics: topicList(
            Bytes32.copyFrom(a0),
            Bytes32.copyFrom(a1),
            Bytes32.copyFrom(a2),
            Bytes32.copyFrom(a3),
          ),
          data: @[byte 0xDE, 0xAD, 0xBE, 0xEF],
        )
    )

  testRT "Log decode sanity",
    (
      block:
        let addr33 = Address.copyFrom(newSeqWith(20, byte 0x33))
        var t1, t2: array[32, byte]
        for i in 0 ..< 32:
          t1[i] = 1
          t2[i] = 2
        Log(
          address: addr33,
          topics: topicList(Bytes32.copyFrom(t1), Bytes32.copyFrom(t2)),
          data: @[byte 1, 2, 3, 4],
        )
    ):
    let d = SSZ.decode(SSZ.encode(v), Log)
    check d.address == v.address
    check d.topics[0] == v.topics[0]
    check d.topics[1] == v.topics[1]
    check d.data == v.data

  testRT "Log: large progressive data (128 KiB)",
    (
      block:
        let a77 = Address.copyFrom(newSeqWith(20, byte 0x77))
        var t1, t2: array[32, byte]
        for i in 0 ..< 32:
          t1[i] = 1
          t2[i] = 2
        var big = newSeq[byte](128 * 1024)
        for i in 0 ..< big.len:
          big[i] = byte(i and 0xFF)
        Log(
          address: a77,
          topics: topicList(Bytes32.copyFrom(t1), Bytes32.copyFrom(t2)),
          data: big,
        )
    ):
    check v.data.len == 128 * 1024

suite "Receipts Construction (SSZ)":
  testRT "Basic Receipt empty",
    BasicReceipt(
      `from`: addresses.zeroAddress,
      gas_used: 100'u64,
      logs: @[],
      status: true,
    )

  testRT "Basic receipt data",
    (
      block:
        let log0 = Log(address: default(Address), topics: topicList(), data: @[])
        BasicReceipt(
          `from`: default(Address),
          gas_used: 100'u64,
          logs: @[log0],
          status: true,
        )
    ):
    check v.gas_used == 100'u64
    check v.status == true
    check v.logs.len == 1

  testRT "CreateReceipt: no logs",
    (
      block:
        let fromBB = Address.copyFrom(newSeqWith(20, byte 0xBB))
        let addrCC = Address.copyFrom(newSeqWith(20, byte 0xCC))
        CreateReceipt(
          `from`: fromBB,
          gas_used: 42'u64,
          contract_address: addrCC,
          logs: @[],
          status: false,
        )
    ):
    check v.logs.len == 0

  testRT "Create receipt: logs 1",
    (
      block:
        let log1 = Log(
          address: default(Address), topics: topicList(), data: @[byte 0x01, 0x02, 0x03]
        )
        let createdAddr = address"0x00000000000000000000000000000000000000aa"
        CreateReceipt(
          `from`: address"0x00000000000000000000000000000000000000bb",
          gas_used: 21000'u64,
          contract_address: createdAddr,
          logs: @[log1],
          status: false,
        )
    ):
    check v.gas_used == 21000'u64
    check v.status == false
    check v.logs.len == 1

  testRT "SetCode receipt",
    (
      block:
        let log2 = Log(
          address: address"0x00000000000000000000000000000000000000cc",
          topics: topicList(
            Bytes32.default, Bytes32.default, Bytes32.default, Bytes32.default
          ),
          data: @[],
        )
        SetCodeReceipt(
          `from`: address"0x00000000000000000000000000000000000000dd",
          gas_used: 42000'u64,
          logs: @[log2],
          status: true,
          authorities:
            @[
              address"0x00000000000000000000000000000000000000f1",
              address"0x00000000000000000000000000000000000000f2",
            ],
        )
    ):
    check v.gas_used == 42000'u64
    check v.status == true
    check v.authorities.len == 2
    check v.logs.len == 1

suite "Block receipts root (SSZ)":
  test "receipts root for 3 receipts: non-zero and stable":
    let r0 = toReceipt(
      BasicReceipt(
        `from`: addresses.zeroAddress,
        gas_used: 21_000'u64,
        logs: @[],
        status: true,
      )
    )
    let r1 = toReceipt(
      CreateReceipt(
        `from`: address"0x0000000000000000000000000000000000000001",
        gas_used: 42_000'u64,
        contract_address: address"0x00000000000000000000000000000000000000aa",
        logs: @[],
        status: false,
      )
    )
    let r2 = toReceipt(
      SetCodeReceipt(
        `from`: address"0x00000000000000000000000000000000000000bb",
        gas_used: 63_000'u64,
        logs: @[],
        status: true,
        authorities: @[address"0x00000000000000000000000000000000000000f1"],
      )
    )
    var receipts: seq[Receipt] = @[r0, r1, r2]
    let root1 = hash_tree_root(receipts)

test "receipts root changes when a receipt changes":
  var receipts =
    @[
      BasicReceipt(
        `from`: default(Address),
        gas_used: 1'u64,
        logs: @[],
        status: true,
      ),
      BasicReceipt(
        `from`: default(Address),
        gas_used: 2'u64,
        logs: @[],
        status: true,
      ),
    ]
  let rootA = hash_tree_root(receipts)
  receipts[0].gas_used = 3'u64
  let rootB = hash_tree_root(receipts)
  check rootA != rootB

test "receipts root is order-sensitive":
  let a = BasicReceipt(
    `from`: default(Address),
    gas_used: 1'u64,
    logs: @[],
    status: true,
  )
  let b = BasicReceipt(
    `from`: default(Address),
    gas_used: 2'u64,
    logs: @[],
    status: true,
  )
  let list1 = @[a, b]
  let list2 = @[b, a]
  let r1 = hash_tree_root(list1)
  let r2 = hash_tree_root(list2)
  check r1 != r2

suite "SSZ root":
  test "hash_tree_root for Log":
    let log = Log(
      address: addresses.zeroAddress,
      topics:
        topicList(Bytes32.default, Bytes32.default, Bytes32.default, Bytes32.default),
      data: @[],
    )
    let root = hash_tree_root(log)

  test "hash_tree_root for list of Log":
    let log = Log(
      address: addresses.zeroAddress,
      topics:
        topicList(Bytes32.default, Bytes32.default, Bytes32.default, Bytes32.default),
      data: @[],
    )
    let logs = @[log]
    let root = hash_tree_root(logs)

  test "hash_tree_root for BasicReceipt":
    let r = BasicReceipt(
      `from`: addresses.zeroAddress,
      gas_used: 100'u64,
      logs: @[],
      status: true,
    )
    let root = hash_tree_root(r)

  test "hash_tree_root for CreateReceipt":
    let r = CreateReceipt(
      `from`: address"0x0000000000000000000000000000000000000001",
      gas_used: 42_000'u64,
      contract_address: address"0x00000000000000000000000000000000000000aa",
      logs: @[],
      status: false,
    )
    let root = hash_tree_root(r)

  test "hash_tree_root for SetCodeReceipt":
    let r = SetCodeReceipt(
      `from`: address"0x00000000000000000000000000000000000000bb",
      gas_used: 63_000'u64,
      logs: @[],
      status: true,
      authorities: @[address"0x00000000000000000000000000000000000000f1"],
    )
    let root = hash_tree_root(r)
