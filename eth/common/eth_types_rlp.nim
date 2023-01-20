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
  w.append(TxEip2930)
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
  w.append(TxEip1559)
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

proc appendTxEip4844Signed(w: var RlpWriter, tx: Transaction) =
  # exclude tx type
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
  w.append(tx.maxFeePerDataGas)
  w.append(tx.versionedHashes)
  w.append(tx.V)
  w.append(tx.R)
  w.append(tx.S)

proc appendTxEip4844Network(w: var RlpWriter, tx: Transaction) =
  # exclude tx type
  # spec: rlp([tx_payload, blobs, commitments, proofs])
  w.startList(4)
  w.appendTxEip4844Signed(tx)
  w.append(tx.networkPayload.blobs)
  w.append(tx.networkPayload.commitments)
  w.append(tx.networkPayload.proofs)

proc appendTxEip4844(w: var RlpWriter, tx: Transaction) =
  # append the tx type first
  w.append(TxEip4844)

  if tx.networkPayload.isNil:
    w.appendTxEip4844Signed(tx)
  else:
    w.appendTxEip4844Network(tx)

proc append*(w: var RlpWriter, tx: Transaction) =
  case tx.txType
  of TxLegacy:
    w.appendTxLegacy(tx)
  of TxEip2930:
    w.appendTxEip2930(tx)
  of TxEip1559:
    w.appendTxEip1559(tx)
  of TxEip4844:
    w.appendTxEip4844(tx)

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

proc readTxEip4844Signed(rlp: var Rlp, tx: var Transaction) =
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
  rlp.read(tx.maxFeePerDataGas)
  rlp.read(tx.versionedHashes)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxEip4844Network(rlp: var Rlp, tx: var Transaction) =
  # spec: rlp([tx_payload, blobs, commitments, proofs])
  rlp.tryEnterList()
  rlp.readTxEip4844Signed(tx)
  var np = NetworkPayload()
  rlp.read(np.blobs)
  rlp.read(np.commitments)
  rlp.read(np.proofs)
  tx.networkPayload = np

proc readTxEip4844(rlp: var Rlp, tx: var Transaction) =
  tx.txType = TxEip4844
  let listLen = rlp.listLen
  if listLen == 4:
    rlp.readTxEip4844Network(tx)
  elif listLen == 14:
    rlp.readTxEip4844Signed(tx)
  else:
    raise newException(MalformedRlpError,
      "Invalid EIP-4844 transaction: listLen should be in 4 or 14, got: " & $listLen)

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
    of TxEip4844:
      rlp.readTxEip4844(tx)
      return
    else:
      discard

  raise newException(UnsupportedRlpError,
    "TypedTransaction type must be 1, 2, or 3 in this version, got " & $txType)

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

proc read*(rlp: var Rlp, T: type Receipt): T =
  if rlp.isList:
    result.receiptType = LegacyReceipt
  else:
    # EIP 2718
    let recType = rlp.getByteValue
    rlp.position += 1

    if recType notin {1, 2, 3}:
      raise newException(UnsupportedRlpError,
        "TxType expect 1, 2, or 3 got " & $recType)
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

proc rlpHash*[T](v: T): Hash256 =
  keccakHash(rlp.encode(v))

func blockHash*(h: BlockHeader): KeccakHash {.inline.} = rlpHash(h)

proc append*(rlpWriter: var RlpWriter, id: NetworkId) =
  rlpWriter.append(id.uint)

proc read*(rlp: var Rlp, T: type NetworkId): T =
  rlp.read(uint).NetworkId
