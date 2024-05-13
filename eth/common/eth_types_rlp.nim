# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  "."/[eth_types, eth_hash_rlp],
  ../rlp

from stew/objects
  import checkedEnumAssign

export
  eth_types, eth_hash_rlp, rlp

#
# Rlp serialization:
#

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

proc append*[T](w: var RlpWriter, val: Option[T]) =
  if val.isSome:
    w.append(val.get())
  else:
    w.append("")

proc appendTxLegacy(w: var RlpWriter, tx: Transaction) =
  w.startList(9)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.V)
  w.append(tx.R)
  w.append(tx.S)

proc appendTxEip2930(w: var RlpWriter, tx: Transaction) =
  w.startList(11)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.V)
  w.append(tx.R)
  w.append(tx.S)

proc appendTxEip1559(w: var RlpWriter, tx: Transaction) =
  w.startList(12)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.maxPriorityFee)
  w.append(tx.maxFee)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.V)
  w.append(tx.R)
  w.append(tx.S)

proc appendTxEip4844(w: var RlpWriter, tx: Transaction) =
  w.startList(14)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.maxPriorityFee)
  w.append(tx.maxFee)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.maxFeePerBlobGas)
  w.append(tx.versionedHashes)
  w.append(tx.V)
  w.append(tx.R)
  w.append(tx.S)

proc appendTxPayload(w: var RlpWriter, tx: Transaction) =
  case tx.txType
  of TxLegacy:
    w.appendTxLegacy(tx)
  of TxEip2930:
    w.appendTxEip2930(tx)
  of TxEip1559:
    w.appendTxEip1559(tx)
  of TxEip4844:
    w.appendTxEip4844(tx)

proc append*(w: var RlpWriter, tx: Transaction) =
  if tx.txType != TxLegacy:
    w.append(tx.txType)
  w.appendTxPayload(tx)

proc append(w: var RlpWriter, networkPayload: NetworkPayload) =
  w.append(networkPayload.blobs)
  w.append(networkPayload.commitments)
  w.append(networkPayload.proofs)

proc append*(w: var RlpWriter, tx: PooledTransaction) =
  if tx.tx.txType != TxLegacy:
    w.append(tx.tx.txType)
  if tx.networkPayload != nil:
    w.startList(4)  # spec: rlp([tx_payload, blobs, commitments, proofs])
  w.appendTxPayload(tx.tx)
  if tx.networkPayload != nil:
    w.append(tx.networkPayload)

template read[T](rlp: var Rlp, val: var T) =
  val = rlp.read(type val)

proc read[T](rlp: var Rlp, val: var Option[T]) =
  if rlp.blobLen != 0:
    val = some(rlp.read(T))
  else:
    rlp.skipElem

proc readTxLegacy(rlp: var Rlp, tx: var Transaction) =
  tx.txType = TxLegacy
  rlp.tryEnterList()
  rlp.read(tx.nonce)
  rlp.read(tx.gasPrice)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxEip2930(rlp: var Rlp, tx: var Transaction) =
  tx.txType = TxEip2930
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.gasPrice)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.accessList)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxEip1559(rlp: var Rlp, tx: var Transaction) =
  tx.txType = TxEip1559
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.maxPriorityFee)
  rlp.read(tx.maxFee)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.accessList)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxEip4844(rlp: var Rlp, tx: var Transaction) =
  tx.txType = TxEip4844
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.maxPriorityFee)
  rlp.read(tx.maxFee)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.accessList)
  rlp.read(tx.maxFeePerBlobGas)
  rlp.read(tx.versionedHashes)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxType(rlp: var Rlp): TxType =
  if rlp.isList:
    raise newException(RlpTypeMismatch,
      "Transaction type expected, but source RLP is a list")

  # EIP-2718: We MUST decode the first byte as a byte, not `rlp.read(int)`.
  # If decoded with `rlp.read(int)`, bad transaction data (from the network)
  # or even just incorrectly framed data for other reasons fails with
  # any of these misleading error messages:
  # - "Message too large to fit in memory"
  # - "Number encoded with a leading zero"
  # - "Read past the end of the RLP stream"
  # - "Small number encoded in a non-canonical way"
  # - "Attempt to read an Int value past the RLP end"
  # - "The RLP contains a larger than expected Int value"
  if not rlp.isSingleByte:
    if not rlp.hasData:
      raise newException(MalformedRlpError,
        "Transaction expected but source RLP is empty")
    raise newException(MalformedRlpError,
      "TypedTransaction type byte is out of range, must be 0x00 to 0x7f")
  let txType = rlp.getByteValue
  rlp.position += 1

  var txVal: TxType
  if checkedEnumAssign(txVal, txType):
    return txVal

  raise newException(UnsupportedRlpError,
    "TypedTransaction type must be 1, 2, or 3 in this version, got " & $txType)

proc readTxPayload(rlp: var Rlp, tx: var Transaction, txType: TxType) =
  case txType
  of TxLegacy:
    raise newException(RlpTypeMismatch,
      "LegacyTransaction should not be wrapped in a list")
  of TxEip2930:
    rlp.readTxEip2930(tx)
  of TxEip1559:
    rlp.readTxEip1559(tx)
  of TxEip4844:
    rlp.readTxEip4844(tx)

proc readTxTyped(rlp: var Rlp, tx: var Transaction) =
  let txType = rlp.readTxType()
  rlp.readTxPayload(tx, txType)

proc read*(rlp: var Rlp, T: type Transaction): T =
  # Individual transactions are encoded and stored as either `RLP([fields..])`
  # for legacy transactions, or `Type || RLP([fields..])`.  Both of these
  # encodings are byte sequences.  The part after `Type` doesn't have to be
  # RLP in theory, but all types so far use RLP.  EIP-2718 covers this.
  if rlp.isList:
    rlp.readTxLegacy(result)
  else:
    rlp.readTxTyped(result)

proc read(rlp: var Rlp, T: type NetworkPayload): T =
  result = NetworkPayload()
  rlp.read(result.blobs)
  rlp.read(result.commitments)
  rlp.read(result.proofs)

proc readTxTyped(rlp: var Rlp, tx: var PooledTransaction) =
  let
    txType = rlp.readTxType()
    hasNetworkPayload =
      if txType == TxEip4844:
        rlp.listLen == 4
      else:
        false
  if hasNetworkPayload:
    rlp.tryEnterList()  # spec: rlp([tx_payload, blobs, commitments, proofs])
  rlp.readTxPayload(tx.tx, txType)
  if hasNetworkPayload:
    rlp.read(tx.networkPayload)

proc read*(rlp: var Rlp, T: type PooledTransaction): T =
  if rlp.isList:
    rlp.readTxLegacy(result.tx)
  else:
    rlp.readTxTyped(result)

proc read*(
    rlp: var Rlp,
    T: (type seq[Transaction]) | (type openArray[Transaction])
): seq[Transaction] =
  # In arrays (sequences), transactions are encoded as either `RLP([fields..])`
  # for legacy transactions, or `RLP(Type || RLP([fields..]))` for all typed
  # transactions to date.  Spot the extra `RLP(..)` blob encoding, to make it
  # valid RLP inside a larger RLP.  EIP-2976 covers this, "Typed Transactions
  # over Gossip", although it's not very clear about the blob encoding.
  #
  # In practice the extra `RLP(..)` applies to all arrays/sequences of
  # transactions.  In principle, all aggregates (objects etc.), but
  # arrays/sequences are enough.  In `eth/65` protocol this is essential for
  # the correct encoding/decoding of `Transactions`, `NewBlock`, and
  # `PooledTransactions` network calls.  We need a type match on both
  # `openArray[Transaction]` and `seq[Transaction]` to catch all cases.
  if not rlp.isList:
    raise newException(RlpTypeMismatch,
      "Transaction list expected, but source RLP is not a list")
  for item in rlp:
    var tx: Transaction
    if item.isList:
      item.readTxLegacy(tx)
    else:
      var rr = rlpFromBytes(rlp.read(Blob))
      rr.readTxTyped(tx)
    result.add tx

proc read*(
    rlp: var Rlp,
    T: (type seq[PooledTransaction]) | (type openArray[PooledTransaction])
): seq[PooledTransaction] =
  if not rlp.isList:
    raise newException(RlpTypeMismatch,
      "PooledTransaction list expected, but source RLP is not a list")
  for item in rlp:
    var tx: PooledTransaction
    if item.isList:
      item.readTxLegacy(tx.tx)
    else:
      var rr = rlpFromBytes(rlp.read(Blob))
      rr.readTxTyped(tx)
    result.add tx

proc append*(rlpWriter: var RlpWriter,
             txs: seq[Transaction] | openArray[Transaction]) {.inline.} =
  # See above about encoding arrays/sequences of transactions.
  rlpWriter.startList(txs.len)
  for tx in txs:
    if tx.txType == TxLegacy:
      rlpWriter.append(tx)
    else:
      rlpWriter.append(rlp.encode(tx))

proc append*(
    rlpWriter: var RlpWriter,
    txs: seq[PooledTransaction] | openArray[PooledTransaction]) {.inline.} =
  rlpWriter.startList(txs.len)
  for tx in txs:
    if tx.tx.txType == TxLegacy:
      rlpWriter.append(tx)
    else:
      rlpWriter.append(rlp.encode(tx))

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

proc rlpHash*(tx: PooledTransaction): Hash256 =
  keccakHash(rlp.encode(tx.tx))

func blockHash*(h: BlockHeader): KeccakHash {.inline.} = rlpHash(h)

proc append*(rlpWriter: var RlpWriter, id: NetworkId) =
  rlpWriter.append(id.uint)

proc read*(rlp: var Rlp, T: type NetworkId): T =
  rlp.read(uint).NetworkId
