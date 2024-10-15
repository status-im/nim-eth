# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import "."/[addresses_rlp, base_rlp, hashes_rlp, transactions], ../rlp

from stew/objects import checkedEnumAssign

export addresses_rlp, base_rlp, hashes_rlp, transactions, rlp

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
  w.append(tx.maxPriorityFeePerGas)
  w.append(tx.maxFeePerGas)
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
  w.append(tx.maxPriorityFeePerGas)
  w.append(tx.maxFeePerGas)
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

proc append*(w: var RlpWriter, x: Authorization) =
  w.startList(6)
  w.append(x.chainId.uint64)
  w.append(x.address)
  w.append(x.nonce)
  w.append(x.yParity)
  w.append(x.R)
  w.append(x.S)

proc appendTxEip7702(w: var RlpWriter, tx: Transaction) =
  w.startList(13)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.maxPriorityFeePerGas)
  w.append(tx.maxFeePerGas)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.authorizationList)
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
  of TxEip7702:
    w.appendTxEip7702(tx)

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
    w.startList(4) # spec: rlp([tx_payload, blobs, commitments, proofs])
  w.appendTxPayload(tx.tx)
  if tx.networkPayload != nil:
    w.append(tx.networkPayload)

proc rlpEncodeLegacy(tx: Transaction): seq[byte] =
  var w = initRlpWriter()
  w.startList(6)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.finish()

proc rlpEncodeEip155(tx: Transaction): seq[byte] =
  var w = initRlpWriter()
  w.startList(9)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.chainId)
  w.append(0'u8)
  w.append(0'u8)
  w.finish()

proc rlpEncodeEip2930(tx: Transaction): seq[byte] =
  var w = initRlpWriter()
  w.append(TxEip2930)
  w.startList(8)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.finish()

proc rlpEncodeEip1559(tx: Transaction): seq[byte] =
  var w = initRlpWriter()
  w.append(TxEip1559)
  w.startList(9)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.maxPriorityFeePerGas)
  w.append(tx.maxFeePerGas)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.finish()

proc rlpEncodeEip4844(tx: Transaction): seq[byte] =
  var w = initRlpWriter()
  w.append(TxEip4844)
  w.startList(11)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.maxPriorityFeePerGas)
  w.append(tx.maxFeePerGas)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.maxFeePerBlobGas)
  w.append(tx.versionedHashes)
  w.finish()

proc rlpEncodeEip7702(tx: Transaction): seq[byte] =
  var w = initRlpWriter()
  w.append(TxEip7702)
  w.startList(10)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.maxPriorityFeePerGas)
  w.append(tx.maxFeePerGas)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.authorizationList)
  w.finish()

proc encodeForSigning*(tx: Transaction, eip155: bool): seq[byte] =
  ## Encode transaction data in preparation for signing or signature checking.
  ## For signature checking, set `eip155 = tx.isEip155`
  case tx.txType
  of TxLegacy:
    if eip155: tx.rlpEncodeEip155 else: tx.rlpEncodeLegacy
  of TxEip2930:
    tx.rlpEncodeEip2930
  of TxEip1559:
    tx.rlpEncodeEip1559
  of TxEip4844:
    tx.rlpEncodeEip4844
  of TxEip7702:
    tx.rlpEncodeEip7702

template rlpEncode*(tx: Transaction): seq[byte] {.deprecated.} =
  encodeForSigning(tx, tx.isEip155())

func rlpHashForSigning*(tx: Transaction, eip155: bool): Hash32 =
  # Hash transaction without signature
  keccak256(encodeForSigning(tx, eip155))

template txHashNoSignature*(tx: Transaction): Hash32 {.deprecated.} =
  rlpHashForSigning(tx, tx.isEip155())

proc readTxLegacy(rlp: var Rlp, tx: var Transaction) {.raises: [RlpError].} =
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

  if tx.V >= EIP155_CHAIN_ID_OFFSET:
    tx.chainId = ChainId((tx.V - EIP155_CHAIN_ID_OFFSET) div 2)

proc readTxEip2930(rlp: var Rlp, tx: var Transaction) {.raises: [RlpError].} =
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

proc readTxEip1559(rlp: var Rlp, tx: var Transaction) {.raises: [RlpError].} =
  tx.txType = TxEip1559
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.maxPriorityFeePerGas)
  rlp.read(tx.maxFeePerGas)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.accessList)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxEip4844(rlp: var Rlp, tx: var Transaction) {.raises: [RlpError].} =
  tx.txType = TxEip4844
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.maxPriorityFeePerGas)
  rlp.read(tx.maxFeePerGas)
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

func rlpEncodeEip7702(auth: Authorization): seq[byte] =
  var w = initRlpWriter()
  w.append(0x05'u8)
  w.startList(3)
  w.append(auth.chainId.uint64)
  w.append(auth.address)
  w.append(auth.nonce)
  w.finish()

func encodeForSigning*(auth: Authorization): seq[byte] =
  ## Encode authorization data in preparation for signing or signature checking.
  auth.rlpEncodeEip7702

func rlpHashForSigning*(auth: Authorization): Hash32 =
  # Hash authorization without signature
  keccak256(encodeForSigning(auth))

proc read*(rlp: var Rlp, T: type Authorization): T {.raises: [RlpError].} =
  rlp.tryEnterList()
  result.chainId = rlp.read(uint64).ChainId
  rlp.read(result.address)
  rlp.read(result.nonce)
  rlp.read(result.yParity)
  rlp.read(result.R)
  rlp.read(result.S)

proc readTxEip7702(rlp: var Rlp, tx: var Transaction) {.raises: [RlpError].} =
  tx.txType = TxEip7702
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.maxPriorityFeePerGas)
  rlp.read(tx.maxFeePerGas)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.accessList)
  rlp.read(tx.authorizationList)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxType(rlp: var Rlp): TxType {.raises: [RlpError].} =
  if rlp.isList:
    raise newException(
      RlpTypeMismatch, "Transaction type expected, but source RLP is a list"
    )

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
      raise
        newException(MalformedRlpError, "Transaction expected but source RLP is empty")
    raise newException(
      MalformedRlpError,
      "TypedTransaction type byte is out of range, must be 0x00 to 0x7f",
    )
  let txType = rlp.getByteValue
  rlp.position += 1

  var txVal: TxType
  if checkedEnumAssign(txVal, txType):
    return txVal

  raise newException(
    UnsupportedRlpError,
    "TypedTransaction type must be 1, 2, or 3 in this version, got " & $txType,
  )

proc readTxPayload(
    rlp: var Rlp, tx: var Transaction, txType: TxType
) {.raises: [RlpError].} =
  case txType
  of TxLegacy:
    raise
      newException(RlpTypeMismatch, "LegacyTransaction should not be wrapped in a list")
  of TxEip2930:
    rlp.readTxEip2930(tx)
  of TxEip1559:
    rlp.readTxEip1559(tx)
  of TxEip4844:
    rlp.readTxEip4844(tx)
  of TxEip7702:
    rlp.readTxEip7702(tx)

proc readTxTyped(rlp: var Rlp, tx: var Transaction) {.raises: [RlpError].} =
  let txType = rlp.readTxType()
  rlp.readTxPayload(tx, txType)

proc read*(rlp: var Rlp, T: type Transaction): T {.raises: [RlpError].} =
  # Individual transactions are encoded and stored as either `RLP([fields..])`
  # for legacy transactions, or `Type || RLP([fields..])`.  Both of these
  # encodings are byte sequences.  The part after `Type` doesn't have to be
  # RLP in theory, but all types so far use RLP.  EIP-2718 covers this.
  if rlp.isList:
    rlp.readTxLegacy(result)
  else:
    rlp.readTxTyped(result)

proc read(rlp: var Rlp, T: type NetworkPayload): T {.raises: [RlpError].} =
  result = NetworkPayload()
  rlp.read(result.blobs)
  rlp.read(result.commitments)
  rlp.read(result.proofs)

proc readTxTyped(rlp: var Rlp, tx: var PooledTransaction) {.raises: [RlpError].} =
  let
    txType = rlp.readTxType()
    hasNetworkPayload =
      if txType == TxEip4844:
        rlp.listLen == 4
      else:
        false
  if hasNetworkPayload:
    rlp.tryEnterList() # spec: rlp([tx_payload, blobs, commitments, proofs])
  rlp.readTxPayload(tx.tx, txType)
  if hasNetworkPayload:
    rlp.read(tx.networkPayload)

proc read*(rlp: var Rlp, T: type PooledTransaction): T {.raises: [RlpError].} =
  if rlp.isList:
    rlp.readTxLegacy(result.tx)
  else:
    rlp.readTxTyped(result)

proc read*(
    rlp: var Rlp, T: (type seq[Transaction]) | (type openArray[Transaction])
): seq[Transaction] {.raises: [RlpError].} =
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
    raise newException(
      RlpTypeMismatch, "Transaction list expected, but source RLP is not a list"
    )
  for item in rlp:
    var tx: Transaction
    if item.isList:
      item.readTxLegacy(tx)
    else:
      var rr = rlpFromBytes(rlp.read(seq[byte]))
      rr.readTxTyped(tx)
    result.add tx

proc read*(
    rlp: var Rlp, T: (type seq[PooledTransaction]) | (type openArray[PooledTransaction])
): seq[PooledTransaction] {.raises: [RlpError].} =
  if not rlp.isList:
    raise newException(
      RlpTypeMismatch, "PooledTransaction list expected, but source RLP is not a list"
    )
  for item in rlp:
    var tx: PooledTransaction
    if item.isList:
      item.readTxLegacy(tx.tx)
    else:
      var rr = rlpFromBytes(rlp.read(seq[byte]))
      rr.readTxTyped(tx)
    result.add tx

proc append*(rlpWriter: var RlpWriter, txs: seq[Transaction] | openArray[Transaction]) =
  # See above about encoding arrays/sequences of transactions.
  rlpWriter.startList(txs.len)
  for tx in txs:
    if tx.txType == TxLegacy:
      rlpWriter.append(tx)
    else:
      rlpWriter.append(rlp.encode(tx))

proc append*(
    rlpWriter: var RlpWriter, txs: seq[PooledTransaction] | openArray[PooledTransaction]
) =
  rlpWriter.startList(txs.len)
  for tx in txs:
    if tx.tx.txType == TxLegacy:
      rlpWriter.append(tx)
    else:
      rlpWriter.append(rlp.encode(tx))
