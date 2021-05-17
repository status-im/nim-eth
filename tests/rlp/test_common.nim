{.used.}

import
  std/[unittest, os, json],
  stew/byteutils,
  ../../eth/[common, rlp]

type
  EthHeader = object
    header: BlockHeader

proc `==`(a, b: HashOrStatus): bool =
  result = a.isHash == b.isHash
  if not result: return
  if a.isHash:
    result = result and a.hash == b.hash
  else:
    result = result and a.status == b.status

func `==`(a, b: ChainId): bool =
  a.uint64 == b.uint64

func `==`(a, b: Transaction): bool =
  if a.txType != b.txType:
    return false
  if a.txType == LegacyTxType:
    return a.legacyTx == b.legacyTx
  else:
    return a.accessListTx == b.accessListTx

func `==`(a, b: Receipt): bool =
  if a.receiptType != b.receiptType:
    return false
  if a.receiptType == LegacyReceiptType:
    return a.legacyReceipt == b.legacyReceipt
  else:
    return a.accessListReceipt == b.accessListReceipt

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
        receiptType: LegacyReceiptType,
        legacyReceipt: LegacyReceipt(
          stateRootOrStatus: hashOrStatus(true),
          cumulativeGasUsed: 51000
        )
      )

      let hash = rlpHash(a)
      let b = Receipt(
        receiptType: LegacyReceiptType,
        legacyReceipt: LegacyReceipt(
          stateRootOrStatus: hashOrStatus(hash),
          cumulativeGasUsed: 21000
        )
      )

      let abytes = rlp.encode(a)
      let bbytes = rlp.encode(b)
      let aa = rlp.decode(abytes, Receipt)
      let bb = rlp.decode(bbytes, Receipt)
      check aa == a
      check bb == b

    test "access list receipt":
      let a = Receipt(
        receiptType: AccessListReceiptType,
        accessListReceipt: AccessListReceipt(
          status: true
        )
      )

      let b = Receipt(
        receiptType: AccessListReceiptType,
        accessListReceipt: AccessListReceipt(
          status: false,
          cumulativeGasUsed: 21000
        )
      )

      let abytes = rlp.encode(a)
      let bbytes = rlp.encode(b)
      let aa = rlp.decode(abytes, Receipt)
      let bb = rlp.decode(bbytes, Receipt)
      check aa == a
      check bb == b

proc suite2() =
  suite "eip 2718 transaction":
    for i in 0..<10:
      loadFile(i)

suite1()
suite2()