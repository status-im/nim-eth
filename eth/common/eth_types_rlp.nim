# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[sequtils, typetraits],
  ssz_serialization,
  "."/[eth_types, eth_hash_rlp],
  ".."/[keys, rlp]

from stew/objects
  import checkedEnumAssign

export
  eth_types, eth_hash_rlp, rlp

#
# Rlp serialization:
#

type RawRlp* = distinct seq[byte]

proc append*(w: var RlpWriter, value: RawRlp) =
  w.appendRawBytes(distinctBase(value))

func read*(rlp: var Rlp, T: type RawRlp): T =
  rlp.toBytes().T

proc read*(rlp: var Rlp, T: type StUint): T {.inline.} =
  if rlp.isBlob:
    let bytes = rlp.toBytes
    if bytes.len > 0:
      # be sure the amount of bytes matches the size of the stint
      if bytes.len <= sizeof(result):
        result.initFromBytesBE(bytes)
      else:
        raise newException(RlpTypeMismatch, "Unsigned integer expected, but the source RLP has the wrong length")
    else:
      result = 0.to(T)
  else:
    raise newException(RlpTypeMismatch, "Unsigned integer expected, but the source RLP is a list")

  rlp.skipElem

func significantBytesBE(val: openArray[byte]): int =
  ## Returns the number of significant trailing bytes in a big endian
  ## representation of a number.
  # TODO: move that in https://github.com/status-im/nim-byteutils
  for i in 0 ..< val.len:
    if val[i] != 0:
      return val.len - i
  return 1

proc append*(rlpWriter: var RlpWriter, value: StUint) =
  if value > 128:
    let bytes = value.toByteArrayBE
    let nonZeroBytes = significantBytesBE(bytes)
    rlpWriter.append bytes.toOpenArray(bytes.len - nonZeroBytes,
                                       bytes.len - 1)
  else:
    rlpWriter.append(value.truncate(int))

proc read*(rlp: var Rlp, T: type StInt): T {.inline.} =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.fatal: "RLP serialization of signed integers is not allowed".}
  discard

proc append*(rlpWriter: var RlpWriter, value: StInt) =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.fatal: "RLP serialization of signed integers is not allowed".}
  discard

func append*(w: var RlpWriter, val: ChainId) =
  w.append(distinctBase(val))

func read*(rlp: var Rlp, T: typedesc[ChainId]): T =
  rlp.read(distinctBase(T)).T

proc append*[T](w: var RlpWriter, val: Option[T] | Opt[T]) =
  if val.isSome:
    w.append(val.get())
  else:
    w.append("")

proc append*(w: var RlpWriter, val: List) =
  w.append(distinctBase(val))

proc read[T](rlp: var Rlp, val: var Option[T]) =
  if rlp.blobLen != 0:
    val = some(rlp.read(T))
  else:
    rlp.skipElem

proc read[T](rlp: var Rlp, val: var Opt[T]) =
  if rlp.blobLen != 0:
    val.ok rlp.read(T)
  else:
    rlp.skipElem

proc read*[E, N](rlp: var Rlp, T: typedesc[List[E, N]]): T =
  let v = rlp.read(seq[E])
  if v.len > N:
    raise newException(MalformedRlpError,
      "List[" & $E & ", Limit " & $N & "] cannot fit " & $v.len & " items")
  List[E, N].init(v)

template read*[T](rlp: var Rlp, val: var T) =
  val = rlp.read(type val)

proc append*(w: var RlpWriter, rec: Receipt) =
  if rec.receiptType in {Eip2930Receipt, Eip1559Receipt, Eip4844Receipt}:
    w.append(rec.receiptType.int)

  w.startList(4)
  if rec.isHash:
    w.append(rec.hash)
  else:
    w.append(rec.status.uint8)

  w.append(rec.cumulativeGasUsed)
  w.append(rec.bloom)
  w.append(rec.logs)

proc readReceiptLegacy(rlp: var Rlp, receipt: var Receipt) =
  receipt.receiptType = LegacyReceipt
  rlp.tryEnterList()
  if rlp.isBlob and rlp.blobLen in {0, 1}:
    receipt.isHash = false
    receipt.status = rlp.read(uint8) == 1
  elif rlp.isBlob and rlp.blobLen == 32:
    receipt.isHash = true
    receipt.hash = rlp.read(Hash256)
  else:
    raise newException(RlpTypeMismatch,
      "HashOrStatus expected, but the source RLP is not a blob of right size.")

  rlp.read(receipt.cumulativeGasUsed)
  rlp.read(receipt.bloom)
  rlp.read(receipt.logs)

proc readReceiptTyped(rlp: var Rlp, receipt: var Receipt) =
  if not rlp.hasData:
    raise newException(MalformedRlpError,
      "Receipt expected but source RLP is empty")
  if not rlp.isSingleByte:
    raise newException(MalformedRlpError,
      "ReceiptType byte is out of range, must be 0x00 to 0x7f")
  let recType = rlp.getByteValue
  rlp.position += 1

  var txVal: ReceiptType
  if checkedEnumAssign(txVal, recType):
    case txVal:
    of Eip2930Receipt, Eip1559Receipt, Eip4844Receipt:
      receipt.receiptType = txVal
    of LegacyReceipt:
      # The legacy type should not be used here.
      raise newException(MalformedRlpError,
        "Invalid ReceiptType: " & $recType)
  else:
    raise newException(UnsupportedRlpError,
      "Unsupported ReceiptType: " & $recType)

  # Note: This currently remains the same as the legacy receipt.
  rlp.tryEnterList()
  if rlp.isBlob and rlp.blobLen in {0, 1}:
    receipt.isHash = false
    receipt.status = rlp.read(uint8) == 1
  elif rlp.isBlob and rlp.blobLen == 32:
    receipt.isHash = true
    receipt.hash = rlp.read(Hash256)
  else:
    raise newException(RlpTypeMismatch,
      "HashOrStatus expected, but the source RLP is not a blob of right size.")

  rlp.read(receipt.cumulativeGasUsed)
  rlp.read(receipt.bloom)
  rlp.read(receipt.logs)

proc read*(rlp: var Rlp, T: type Receipt): T =
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
    rlp: var Rlp,
    T: (type seq[Receipt]) | (type openArray[Receipt])
  ): seq[Receipt] =
  # In arrays (sequences), receipts are encoded as either `RLP([fields..])`
  # for legacy receipts, or `RLP(Type || RLP([fields..]))` for all typed
  # receipts to date. Spot the extra `RLP(..)` blob encoding, to make it
  # valid RLP inside a larger RLP. EIP-2976 covers this, "Typed Transactions
  # over Gossip", although it's not very clear about the blob encoding.
  #
  # See also note about transactions above.
  if not rlp.isList:
    raise newException(RlpTypeMismatch,
      "Receipts list expected, but source RLP is not a list")

  var receipts: seq[Receipt]
  for item in rlp:
    var receipt: Receipt
    if item.isList:
      item.readReceiptLegacy(receipt)
    else:
      var rr = rlpFromBytes(rlp.read(Blob))
      rr.readReceiptTyped(receipt)
    receipts.add receipt

  receipts

proc append*(
    rlpWriter: var RlpWriter, receipts: seq[Receipt] | openArray[Receipt]
  ) =
  # See above about encoding arrays/sequences of receipts.
  rlpWriter.startList(receipts.len)
  for receipt in receipts:
    if receipt.receiptType == LegacyReceipt:
      rlpWriter.append(receipt)
    else:
      rlpWriter.append(rlp.encode(receipt))

proc read*(rlp: var Rlp, T: type EthTime): T {.inline.} =
  result = EthTime rlp.read(uint64)

proc append*(rlpWriter: var RlpWriter, value: HashOrNum) =
  case value.isHash
  of true:
    rlpWriter.append(value.hash)
  else:
    rlpWriter.append(value.number)

proc read*(rlp: var Rlp, T: type HashOrNum): T =
  if rlp.blobLen == 32:
    result = HashOrNum(isHash: true, hash: rlp.read(Hash256))
  else:
    result = HashOrNum(isHash: false, number: rlp.read(BlockNumber))

proc append*(rlpWriter: var RlpWriter, t: EthTime) {.inline.} =
  rlpWriter.append(t.uint64)

proc rlpHash*[T](v: T): Hash256 =
  keccakHash(rlp.encode(v))

func blockHash*(h: BlockHeader): KeccakHash {.inline.} = rlpHash(h)

proc append*(rlpWriter: var RlpWriter, id: NetworkId) =
  rlpWriter.append(id.uint)

proc read*(rlp: var Rlp, T: type NetworkId): T =
  rlp.read(uint).NetworkId
