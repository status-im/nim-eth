{.used.}

import
  std/[os, json],
  unittest2,
  stew/byteutils,
  ../../eth/[common, rlp]

type
  EthHeader = object
    header: BlockHeader

func `==`(a, b: ChainId): bool =
  a.uint64 == b.uint64

proc loadFile(x: int) =
  let fileName = "tests" / "rlp" / "eip2718" / "acl_block_" & $x & ".json"
  test fileName:
    let n = json.parseFile(fileName)
    let data = n["rlp"].getStr()
    var bytes1 = hexToSeqByte(data)
    var blk1   = rlp.decode(bytes1, EthBlock)

    let bytes2 = rlp.encode(blk1)
    var blk2   = rlp.decode(bytes2, EthBlock)
    check blk1 == blk2
    check bytes1 == bytes2

    var r      = rlpFromBytes(bytes1)
    let header = r.read(EthHeader).header
    let body   = r.readRecordType(BlockBody, false)

    let blk3 = EthBlock(header: header, txs: body.transactions, uncles: body.uncles)
    let bytes3 = rlp.encode(blk3)
    check blk1 == blk3
    check bytes1 == bytes3

proc suite1() =
  suite "rlp encoding":
    test "receipt roundtrip":
      let a = Receipt(
        receiptType: LegacyReceipt,
        isHash: false,
        status: false,
        cumulativeGasUsed: 51000
      )

      let hash = rlpHash(a)
      let b = Receipt(
        receiptType: LegacyReceipt,
        isHash: true,
        hash: hash,
        cumulativeGasUsed: 21000
      )

      let abytes = rlp.encode(a)
      let bbytes = rlp.encode(b)
      let aa = rlp.decode(abytes, Receipt)
      let bb = rlp.decode(bbytes, Receipt)
      check aa == a
      check bb == b

    test "EIP 2930 receipt":
      let a = Receipt(
        receiptType: Eip2930Receipt,
        status: true
      )

      let b = Receipt(
        receiptType: Eip2930Receipt,
        status: false,
        cumulativeGasUsed: 21000
      )

      let abytes = rlp.encode(a)
      let bbytes = rlp.encode(b)
      let aa = rlp.decode(abytes, Receipt)
      let bb = rlp.decode(bbytes, Receipt)
      check aa == a
      check bb == b

    test "EIP 4895 roundtrip":
      let a = Withdrawal(
        index: 1,
        validatorIndex: 2,
        address: EthAddress [
          0.byte, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
          11, 12, 13, 14, 15, 16, 17, 18, 19],
        amount: 4.u256 * 1_000_000_000.u256)

      let abytes = rlp.encode(a)
      let aa = rlp.decode(abytes, Withdrawal)
      check aa == a

proc suite2() =
  suite "eip 2718 transaction":
    for i in 0..<10:
      loadFile(i)

    test "rlp roundtrip EIP1559":
      var h: BlockHeader
      let xy = rlp.encode(h)
      let hh = rlp.decode(xy, BlockHeader)
      check h == hh

suite1()
suite2()
