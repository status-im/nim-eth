# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[os, json],
  unittest2,
  stew/byteutils,
  ../../eth/[common, rlp]

type
  EthHeader = object
    header: BlockHeader

proc loadFile(x: int) =
  let fileName = "tests" / "common" / "eip2718" / "acl_block_" & $x & ".json"
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

    let blk3 = EthBlock(header: header, transactions: body.transactions, uncles: body.uncles)
    let bytes3 = rlp.encode(blk3)
    check blk1 == blk3
    check bytes1 == bytes3

suite "RLP encoding":
  test "Receipt roundtrip":
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

  test "EIP-2930 receipt":
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

  test "EIP-4895 roundtrip":
    let a = Withdrawal(
      index: 1,
      validatorIndex: 2,
      address: Address [
        0.byte, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19],
      amount: 4)

    let abytes = rlp.encode(a)
    let aa = rlp.decode(abytes, Withdrawal)
    check aa == a

suite "EIP-2718 transaction / receipt":
  for i in 0..<10:
    loadFile(i)

  test "BlockHeader: rlp roundtrip EIP-1559 / EIP-4895 / EIP-4844":
    proc doTest(h: BlockHeader) =
      let xy = rlp.encode(h)
      let hh = rlp.decode(xy, BlockHeader)
      check h == hh

    var h: BlockHeader
    doTest h

    # EIP-1559
    h.baseFeePerGas = Opt.some 1234.u256
    doTest h

    # EIP-4895
    h.withdrawalsRoot = Opt.some Hash32.fromHex(
      "0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c588")
    doTest h

    # EIP-4844
    h.blobGasUsed = Opt.some 1234'u64
    h.excessBlobGas = Opt.some 1234'u64
    doTest h

  test "Receipts EIP-2718 + EIP-2976 encoding":
    const
      # Test payload from
      # https://github.com/ethereum/go-ethereum/blob/253447a4f5e5f7f65c0605d490360bb58fb5f8e0/core/types/receipt_test.go#L370
      payload = "f9043eb9010c01f90108018262d4b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0b9010c01f901080182cd14b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0b9010d01f901090183013754b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0b9010d01f90109018301a194b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0"
      receiptsBytes = hexToSeqByte(payload)
    let receipts = rlp.decode(receiptsBytes, seq[Receipt])

    check receipts.len() == 4
    for receipt in receipts:
      check receipt.receiptType == TxEip2930

    let encoded = rlp.encode(receipts)

    check receiptsBytes == encoded

  test "Receipts EIP-2718 encoding - invalid - empty":
    let receiptBytes: seq[byte] = @[]
    expect MalformedRlpError:
      let _ = rlp.decode(receiptBytes, Receipt)

  test "Receipts EIP-2718 encoding - invalid - unsupported tx type":
    let receiptBytes: seq[byte] = @[0x05]
    expect UnsupportedRlpError:
      let _ = rlp.decode(receiptBytes, Receipt)

  test "Receipts EIP-2718 encoding - invalid - legacy tx type":
    let receiptBytes: seq[byte] = @[0x00]
    expect MalformedRlpError:
      let _ = rlp.decode(receiptBytes, Receipt)

  test "Receipts EIP-2718 encoding - invalid - out of bounds tx type":
    let receiptBytes: seq[byte] = @[0x81, 0x80]
    expect MalformedRlpError:
      let _ = rlp.decode(receiptBytes, Receipt)

  test "Receipts EIP-2718 encoding - invalid - empty receipt payload":
    let receiptBytes: seq[byte] = @[0x02]
    expect RlpTypeMismatch:
      let _ = rlp.decode(receiptBytes, Receipt)

  test "Receipt legacy":
    const
      # Test payload from
      # https://github.com/ethereum/go-ethereum/blob/253447a4f5e5f7f65c0605d490360bb58fb5f8e0/core/types/receipt_test.go#L417
      payload = "f901c58001b9010000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000010000080000000000000000000004000000000000000000000000000040000000000000000000000000000800000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000f8bef85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100fff85d940000000000000000000000000000000000000111f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff"
      receiptsBytes = hexToSeqByte(payload)

    let receipt = rlp.decode(receiptsBytes, Receipt)
    check receipt.receiptType == LegacyReceipt
    let encoded = rlp.encode(receipt)
    check receiptsBytes == encoded

  test "Receipt EIP-2930":
    const
      # Test payload from
      # https://github.com/ethereum/go-ethereum/blob/253447a4f5e5f7f65c0605d490360bb58fb5f8e0/core/types/receipt_test.go#L435
      payload = "01f901c58001b9010000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000010000080000000000000000000004000000000000000000000000000040000000000000000000000000000800000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000f8bef85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100fff85d940000000000000000000000000000000000000111f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff"
      receiptsBytes = hexToSeqByte(payload)

    let receipt = rlp.decode(receiptsBytes, Receipt)
    check receipt.receiptType == Eip2930Receipt
    let encoded = rlp.encode(receipt)
    check receiptsBytes == encoded

  test "Receipt EIP-1559":
    const
      # Test payload from
      # https://github.com/ethereum/go-ethereum/blob/253447a4f5e5f7f65c0605d490360bb58fb5f8e0/core/types/receipt_test.go#L453
      payload = "02f901c58001b9010000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000010000080000000000000000000004000000000000000000000000000040000000000000000000000000000800000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000f8bef85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100fff85d940000000000000000000000000000000000000111f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff"
      receiptsBytes = hexToSeqByte(payload)

    let receipt = rlp.decode(receiptsBytes, Receipt)
    check receipt.receiptType == Eip1559Receipt
    let encoded = rlp.encode(receipt)
    check receiptsBytes == encoded
