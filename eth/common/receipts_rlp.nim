# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ./[addresses_rlp, base_rlp, hashes_rlp, receipts], ../rlp

from stew/objects import checkedEnumAssign

export addresses_rlp, base_rlp, hashes_rlp, receipts, rlp

proc append*(w: var RlpWriter, rec: Receipt) =
  if rec.receiptType in {Eip2930Receipt, Eip1559Receipt, Eip4844Receipt, Eip7702Receipt}:
    w.append(rec.receiptType.uint)

  w.startList(4)
  if rec.isHash:
    w.append(rec.hash)
  else:
    w.append(rec.status.uint8)

  w.append(rec.cumulativeGasUsed)
  w.append(rec.logsBloom)
  w.append(rec.logs)

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
      # The legacy type should not be used here.
      raise newException(MalformedRlpError, "Invalid ReceiptType: " & $recType)
  else:
    raise newException(UnsupportedRlpError, "Unsupported ReceiptType: " & $recType)

  # Note: This currently remains the same as the legacy receipt.
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

proc read*(rlp: var Rlp, T: type Receipt): T {.raises: [RlpError].} =
  # Individual receipts are encoded and stored as either `RLP([fields..])`
  # for legacy receipts, or `Type || RLP([fields..])`. Both of these
  # encodings are byte sequences. The part after `Type` doesn't have to be
  # RLP in theory, but all types so far use RLP. EIP-2718 covers this.
  var receipt: Receipt
  if rlp.isList:
    rlp.readReceiptLegacy(receipt)
  else:
    rlp.readReceiptTyped(receipt)
  receipt

proc read*(
    rlp: var Rlp, T: (type seq[Receipt]) | (type openArray[Receipt])
): seq[Receipt] {.raises: [RlpError].} =
  # In arrays (sequences), receipts are encoded as either `RLP([fields..])`
  # for legacy receipts, or `RLP(Type || RLP([fields..]))` for all typed
  # receipts to date. Spot the extra `RLP(..)` blob encoding, to make it
  # valid RLP inside a larger RLP. EIP-2976 covers this, "Typed Transactions
  # over Gossip", although it's not very clear about the blob encoding.
  #
  # See also note about transactions above.
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

proc append*(rlpWriter: var RlpWriter, receipts: seq[Receipt] | openArray[Receipt]) =
  # See above about encoding arrays/sequences of receipts.
  rlpWriter.startList(receipts.len)
  for receipt in receipts:
    if receipt.receiptType == LegacyReceipt:
      rlpWriter.append(receipt)
    else:
      rlpWriter.append(rlp.encode(receipt))
