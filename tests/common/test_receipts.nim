# Nimbus
# Copyright (c) 2023-2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.
{.push raises: [].}
{.used.}

import
  unittest2,
  ../../eth/common/receipts_rlp

template roundTrip(v: untyped) =
  let bytes = rlp.encode(v)
  let v2 = rlp.decode(bytes, v.type)
  let bytes2 = rlp.encode(v2)
  check bytes == bytes2

suite "Receipts":
  test "EIP-4844":
    let rec = Receipt(
      receiptType: Eip4844Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    roundTrip(rec)

  test "EIP-7702":
    let rec = Receipt(
      receiptType: Eip7702Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    roundTrip(rec)

suite "Stored Receipt":
  test "EIP-4844":
    let rec = StoredReceipt(
      receiptType: Eip4844Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    roundTrip(rec)

  test "EIP-7702":
    let rec = StoredReceipt(
      receiptType: Eip7702Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    roundTrip(rec)

type
  ReceiptParts = object
    prefix: seq[byte] ## type byte of typed receipts
    fields: seq[seq[byte]] ## RLP encoded fields of the receipt list

const
  testLog = Log(address: default(Address), topics: @[default(Topic)], data: @[1'u8])
  receiptCases = [
    Receipt(receiptType: LegacyReceipt, status: true,
      cumulativeGasUsed: 21000.GasInt, logs: @[testLog]),
    Receipt(receiptType: Eip2930Receipt, status: true,
      cumulativeGasUsed: 21000.GasInt, logs: @[testLog]),
    Receipt(receiptType: Eip1559Receipt, status: true,
      cumulativeGasUsed: 21000.GasInt, logs: @[testLog]),
    Receipt(receiptType: Eip4844Receipt, status: true,
      cumulativeGasUsed: 21000.GasInt, logs: @[testLog]),
    Receipt(receiptType: Eip7702Receipt, status: true,
      cumulativeGasUsed: 21000.GasInt, logs: @[testLog])]
  storedCases = [
    StoredReceipt(receiptType: LegacyReceipt, status: true,
      cumulativeGasUsed: 21000.GasInt, logs: @[testLog]),
    StoredReceipt(receiptType: Eip1559Receipt, status: true,
      cumulativeGasUsed: 21000.GasInt, logs: @[testLog])]

proc parts(bytes: seq[byte], typed: bool): ReceiptParts {.raises: [RlpError].} =
  let prefix = if typed: bytes[0 ..< 1] else: newSeq[byte]()
  var
    r = rlpFromBytes(bytes[prefix.len .. ^1])
    fields: seq[seq[byte]]
  for item in r:
    fields.add @(item.rawData)
  ReceiptParts(prefix: prefix, fields: fields)

proc parts(rec: Receipt): ReceiptParts {.raises: [RlpError].} =
  parts(rlp.encode(rec), rec.receiptType != LegacyReceipt)

proc parts(rec: StoredReceipt): ReceiptParts {.raises: [RlpError].} =
  parts(rlp.encode(rec), false)

proc toBytes(p: ReceiptParts, extra: seq[byte] = @[]): seq[byte] =
  var w = initRlpList(p.fields.len)
  for f in p.fields:
    w.appendRawBytes(f)
  p.prefix & w.finish() & extra

suite "Receipt decoding":
  test "Decode all receipt types":
    for rec in receiptCases:
      checkpoint $rec.receiptType
      check rlp.encode(rlp.decode(rec.parts.toBytes(), Receipt)) == rlp.encode(rec)
    for rec in storedCases:
      checkpoint $rec.receiptType
      check rlp.encode(rlp.decode(rec.parts.toBytes(), StoredReceipt)) ==
        rlp.encode(rec)

  test "Missing fields":
    for rec in receiptCases:
      checkpoint $rec.receiptType
      var p = rec.parts
      p.fields.setLen(p.fields.len - 1)
      expect MalformedRlpError:
        discard rlp.decode(p.toBytes(), Receipt)
    for rec in storedCases:
      checkpoint $rec.receiptType
      var p = rec.parts
      p.fields.setLen(p.fields.len - 1)
      expect MalformedRlpError:
        discard rlp.decode(p.toBytes(), StoredReceipt)

  test "Extra field":
    for rec in receiptCases:
      checkpoint $rec.receiptType
      var p = rec.parts
      p.fields.add rlp.encode(1'u64)
      expect MalformedRlpError:
        discard rlp.decode(p.toBytes(), Receipt)
    for rec in storedCases:
      checkpoint $rec.receiptType
      var p = rec.parts
      p.fields.add rlp.encode(1'u64)
      expect MalformedRlpError:
        discard rlp.decode(p.toBytes(), StoredReceipt)

  test "Trailing bytes after typed receipt":
    for rec in receiptCases[1 .. ^1]:
      checkpoint $rec.receiptType
      let bytes = rec.parts.toBytes(extra = @[byte 0x01])
      expect MalformedRlpError:
        discard rlp.decode(bytes, Receipt)
      var w = initRlpList(1)
      w.append(bytes)
      expect MalformedRlpError:
        discard rlp.decode(w.finish(), seq[Receipt])

  test "Status other than 0 or 1":
    for rec in receiptCases:
      checkpoint $rec.receiptType
      var p = rec.parts
      p.fields[0] = @[byte 0x05]
      expect RlpTypeMismatch:
        discard rlp.decode(p.toBytes(), Receipt)
    for rec in storedCases:
      checkpoint $rec.receiptType
      var p = rec.parts
      p.fields[1] = @[byte 0x05]
      expect RlpTypeMismatch:
        discard rlp.decode(p.toBytes(), StoredReceipt)

  test "Log with extra element":
    for rec in receiptCases:
      checkpoint $rec.receiptType
      var p = rec.parts
      var w = initRlpList(1)
      w.startList(4)
      w.append(testLog.address)
      w.append(testLog.topics)
      w.append(testLog.data)
      w.append(1'u64)
      p.fields[3] = w.finish()
      expect MalformedRlpError:
        discard rlp.decode(p.toBytes(), Receipt)
