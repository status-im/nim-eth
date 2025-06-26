# eth
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ./[addresses_rlp, base_rlp, hashes_rlp, receipts], ../rlp

from stew/objects import checkedEnumAssign

export addresses_rlp, base_rlp, hashes_rlp, receipts, rlp

# RLP encoding for Receipt (eth/68)
proc append*(w: var RlpWriter, rec: Receipt) =
  if rec.receiptType in {Eip2930Receipt, Eip1559Receipt, Eip4844Receipt, Eip7702Receipt}:
    w.appendDetached(rec.receiptType.uint8)

  w.startList(4)
  if rec.isHash:
    w.append(rec.hash)
  else:
    w.append(rec.status.uint8)
  w.append(rec.cumulativeGasUsed)
  w.append(rec.logsBloom)
  w.append(rec.logs)

# RLP encoding for StoredReceipt (eth/69)
proc append*(w: var RlpWriter, rec: StoredReceipt) =
  w.startList(4)
  w.append(rec.receiptType.uint)
  if rec.isHash:
    w.append(rec.hash)
  else:
    w.append(rec.status.uint8)
  w.append(rec.cumulativeGasUsed)
  w.append(rec.logs)

# Decode legacy receipt (eth/68)
proc readReceiptLegacy(rlp: var Rlp, receipt: var Receipt) {.raises: [RlpError].} =
  receipt.receiptType = LegacyReceipt
  rlp.tryEnterList()
  if rlp.isBlob and rlp.blobLen in {0, 1}:
    receipt.isHash = false
    receipt.status = rlp.read(uint8) == 1
  elif rlp.isBlob and rlp.blobLen == 32:
    receipt.isHash = true
    receipt.hash = rlp.read(Hash32)
  else:
    raise newException(
      RlpTypeMismatch,
      "HashOrStatus expected, but the source RLP is not a blob of right size.",
    )
  rlp.read(receipt.cumulativeGasUsed)
  rlp.read(receipt.logsBloom)
  rlp.read(receipt.logs)

# Decode typed receipt (eth/68)
proc readReceiptTyped(rlp: var Rlp, receipt: var Receipt) {.raises: [RlpError].} =
  if not rlp.hasData:
    raise newException(MalformedRlpError, "Receipt expected but source RLP is empty")
  if not rlp.isSingleByte:
    raise newException(
      MalformedRlpError, "ReceiptType byte is out of range, must be 0x00 to 0x7f"
    )
  let recType = rlp.getByteValue
  rlp.position += 1

  var txVal: ReceiptType
  if checkedEnumAssign(txVal, recType):
    case txVal
    of Eip2930Receipt, Eip1559Receipt, Eip4844Receipt, Eip7702Receipt:
      receipt.receiptType = txVal
    of LegacyReceipt:
      raise newException(MalformedRlpError, "Invalid ReceiptType: " & $recType)
  else:
    raise newException(UnsupportedRlpError, "Unsupported ReceiptType: " & $recType)

  rlp.tryEnterList()
  if rlp.isBlob and rlp.blobLen in {0, 1}:
    receipt.isHash = false
    receipt.status = rlp.read(uint8) == 1
  elif rlp.isBlob and rlp.blobLen == 32:
    receipt.isHash = true
    receipt.hash = rlp.read(Hash32)
  else:
    raise newException(
      RlpTypeMismatch,
      "HashOrStatus expected, but the source RLP is not a blob of right size.",
    )

  rlp.read(receipt.cumulativeGasUsed)
  rlp.read(receipt.logsBloom)
  rlp.read(receipt.logs)

# Decode eth/69 StoredReceipt
proc read*(rlp: var Rlp, T: type StoredReceipt): StoredReceipt {.raises: [RlpError].} =
  var rec: StoredReceipt
  rlp.tryEnterList()

  let txType = rlp.read(uint8)
  if not checkedEnumAssign(rec.receiptType, txType):
    raise newException(UnsupportedRlpError, "Unsupported ReceiptType: " & $txType)

  if rlp.isBlob and rlp.blobLen in {0, 1}:
    rec.isHash = false
    rec.status = rlp.read(uint8) == 1
  elif rlp.isBlob and rlp.blobLen == 32:
    rec.isHash = true
    rec.hash = rlp.read(Hash32)
  else:
    raise newException(RlpTypeMismatch, "Expected status or 32-byte hash blob")

  rlp.read(rec.cumulativeGasUsed)
  rlp.read(rec.logs)

  rec

# Decode eth/68 Receipt
proc read*(rlp: var Rlp, T: type Receipt): Receipt {.raises: [RlpError].} =
  var receipt: Receipt
  if rlp.isList:
    rlp.readReceiptLegacy(receipt)
  else:
    rlp.readReceiptTyped(receipt)
  receipt

# Decode list of eth/68 Receipts
proc read*(
    rlp: var Rlp, T: (type seq[Receipt]) | (type openArray[Receipt])
): seq[Receipt] {.raises: [RlpError].} =
  if not rlp.isList:
    raise newException(
      RlpTypeMismatch, "Receipts list expected, but source RLP is not a list"
    )

  var receipts: seq[Receipt]
  for item in rlp:
    var receipt: Receipt
    if item.isList:
      item.readReceiptLegacy(receipt)
    else:
      var rr = rlpFromBytes(rlp.read(seq[byte]))
      rr.readReceiptTyped(receipt)
    receipts.add receipt

  receipts

# Decode list of eth/69 StoredReceipts
proc read*(
    rlp: var Rlp, T: (type seq[StoredReceipt]) | (type openArray[StoredReceipt])
): seq[StoredReceipt] {.raises: [RlpError].} =
  if not rlp.isList:
    raise newException(RlpTypeMismatch, "Expected a list of receipts")

  var receipts: seq[StoredReceipt]
  for item in rlp:
    receipts.add item.read(StoredReceipt)

  receipts

# Encode list of eth/68 Receipts
proc append*(w: var RlpWriter, receipts: seq[Receipt] | openArray[Receipt]) =
  w.startList(receipts.len)
  for rec in receipts:
    if rec.receiptType == LegacyReceipt:
      w.append(rec)
    else:
      w.append(rlp.encode(rec))

# Encode list of eth/69 StoredReceipts
proc append*(w: var RlpWriter, receipts: seq[StoredReceipt] | openArray[StoredReceipt]) =
  w.startList(receipts.len)
  for rec in receipts:
    w.append(rec)
