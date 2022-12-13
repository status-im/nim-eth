# Copyright (c) 2022 Status Research & Development GmbH
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
  w.append(1)
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
  w.append(2)
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

proc append*(w: var RlpWriter, tx: Transaction) =
  case tx.txType
  of TxLegacy:
    w.appendTxLegacy(tx)
  of TxEip2930:
    w.appendTxEip2930(tx)
  of TxEip1559:
    w.appendTxEip1559(tx)

proc append*(w: var RlpWriter, withdrawal: Withdrawal) =
  w.startList(4)
  w.append(withdrawal.index)
  w.append(withdrawal.validatorIndex)
  w.append(withdrawal.address)
  w.append(withdrawal.amount)

template read[T](rlp: var Rlp, val: var T)=
  val = rlp.read(type val)

proc read[T](rlp: var Rlp, val: var Option[T])=
  if rlp.blobLen != 0:
    val = some(rlp.read(T))
  else:
    rlp.skipElem

proc readTxLegacy(rlp: var Rlp, tx: var Transaction)=
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

proc readTxEip2930(rlp: var Rlp, tx: var Transaction)=
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

proc readTxEip1559(rlp: var Rlp, tx: var Transaction)=
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

proc readTxTyped(rlp: var Rlp, tx: var Transaction) {.inline.} =
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
    case txVal:
    of TxEip2930:
      rlp.readTxEip2930(tx)
      return
    of TxEip1559:
      rlp.readTxEip1559(tx)
      return
    else:
      discard

  raise newException(UnsupportedRlpError,
    "TypedTransaction type must be 1 or 2 in this version, got " & $txType)


proc read*(rlp: var Rlp, T: type Transaction): T =
  # Individual transactions are encoded and stored as either `RLP([fields..])`
  # for legacy transactions, or `Type || RLP([fields..])`.  Both of these
  # encodings are byte sequences.  The part after `Type` doesn't have to be
  # RLP in theory, but all types so far use RLP.  EIP-2718 covers this.
  if rlp.isList:
    rlp.readTxLegacy(result)
  else:
    rlp.readTxTyped(result)

proc read*(rlp: var Rlp,
           T: (type seq[Transaction]) | (type openArray[Transaction])): seq[Transaction] =
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

proc append*(rlpWriter: var RlpWriter,
             txs: seq[Transaction] | openArray[Transaction]) {.inline.} =
  # See above about encoding arrays/sequences of transactions.
  rlpWriter.startList(txs.len)
  for tx in txs:
    if tx.txType == TxLegacy:
      rlpWriter.append(tx)
    else:
      rlpWriter.append(rlp.encode(tx))

proc append*(w: var RlpWriter, rec: Receipt) =
  if rec.receiptType in {Eip2930Receipt, Eip1559Receipt}:
    w.append(rec.receiptType.int)

  w.startList(4)
  if rec.isHash:
    w.append(rec.hash)
  else:
    w.append(rec.status.uint8)

  w.append(rec.cumulativeGasUsed)
  w.append(rec.bloom)
  w.append(rec.logs)

proc read*(rlp: var Rlp, T: type Receipt): T =
  if rlp.isList:
    result.receiptType = LegacyReceipt
  else:
    # EIP 2718
    let recType = rlp.read(int)
    if recType notin {1, 2}:
      raise newException(UnsupportedRlpError,
        "TxType expect 1 or 2 got " & $recType)
    result.receiptType = ReceiptType(recType)

  rlp.tryEnterList()
  if rlp.isBlob and rlp.blobLen in {0, 1}:
    result.isHash = false
    result.status = rlp.read(uint8) == 1
  elif rlp.isBlob and rlp.blobLen == 32:
    result.isHash = true
    result.hash   = rlp.read(Hash256)
  else:
    raise newException(RlpTypeMismatch,
      "HashOrStatus expected, but the source RLP is not a blob of right size.")

  rlp.read(result.cumulativeGasUsed)
  rlp.read(result.bloom)
  rlp.read(result.logs)

proc read*(rlp: var Rlp, T: type Time): T {.inline.} =
  result = fromUnix(rlp.read(int64))

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

proc append*(rlpWriter: var RlpWriter, t: Time) {.inline.} =
  rlpWriter.append(t.toUnix())

proc append*(w: var RlpWriter, h: BlockHeader) =
  var len = 15
  if h.fee.isSome: inc len
  if h.withdrawalsRoot.isSome: inc len
  if h.excessDataGas.isSome: inc len
  w.startList(len)
  for k, v in fieldPairs(h):
    when v isnot Option:
      w.append(v)
  if h.fee.isSome:
    w.append(h.fee.get())
  if h.withdrawalsRoot.isSome:
    w.append(h.withdrawalsRoot.get())
  if h.excessDataGas.isSome:
    w.append(h.excessDataGas.get())

proc read*(rlp: var Rlp, T: type BlockHeader): T =
  let len = rlp.listLen

  if len notin {15, 16, 17, 18}:
    raise newException(UnsupportedRlpError,
      "BlockHeader elems should be 15, 16, 17, or 18 got " & $len)

  rlp.tryEnterList()
  for k, v in fieldPairs(result):
    when v isnot Option:
      v = rlp.read(type v)

  if len >= 16:
    # EIP-1559
    result.baseFee = rlp.read(UInt256)
  if len >= 17:
    # EIP-4895
    result.withdrawalsRoot = some rlp.read(Hash256)
  if len >= 18:
    # EIP-4844
    result.excessDataGas = some rlp.read(GasInt)

proc rlpHash*[T](v: T): Hash256 =
  keccakHash(rlp.encode(v))

func blockHash*(h: BlockHeader): KeccakHash {.inline.} = rlpHash(h)

proc append*(rlpWriter: var RlpWriter, id: NetworkId) =
  rlpWriter.append(id.uint)

proc read*(rlp: var Rlp, T: type NetworkId): T =
  rlp.read(uint).NetworkId
