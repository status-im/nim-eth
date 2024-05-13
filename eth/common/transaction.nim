# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/typetraits,
  ssz_serialization,
  ./eth_types_rlp,
  ".."/[keys, rlp]

export eth_types_rlp

const
  EIP155_CHAIN_ID_OFFSET* = 35'i64

type
  GasPrice* = ## \
    ## Handy definition distinct from `GasInt` which is a commodity unit while
    ## the `GasPrice` is the commodity valuation per unit of gas, similar to a
    ## kind of currency.
    distinct uint64

  GasPriceEx* = ## \
    ## Similar to `GasPrice` but is allowed to be negative.
    distinct int64

proc effectiveGasTip*(tx: Transaction; baseFee: GasPrice): GasPriceEx =
  ## The effective miner gas tip for the globally argument `baseFee`. The
  ## result (which is a price per gas) might well be negative.
  let
    maxFee = tx.payload.max_fee_per_gas
    maxPriorityFee = tx.payload.max_priority_fee_per_gas.get(maxFee)
  min(
    maxPriorityFee.truncate(int64),
    maxFee.truncate(int64) - baseFee.int64).GasPriceEx

proc effectiveGasTip*(tx: Transaction; baseFee: UInt256): GasPriceEx =
  ## Variant of `effectiveGasTip()`
  tx.effectiveGasTip(baseFee.truncate(uint64).GasPrice)

# https://eips.ethereum.org/EIPS/eip-6493#transaction-validation
func ecdsa_pack_signature*(
    y_parity: bool, r: UInt256, s: UInt256): array[ECDSA_SIGNATURE_SIZE, byte] =
  var res: array[ECDSA_SIGNATURE_SIZE, byte]
  res[0 ..< 32] = r.toBytesBE()
  res[32 ..< 64] = s.toBytesBE()
  res[64] = if y_parity: 0x01 else: 0x00
  res

func ecdsa_unpack_signature*(
    signature: array[ECDSA_SIGNATURE_SIZE, byte]
): tuple[y_parity: bool, r: UInt256, s: UInt256] =
  (
    y_parity: signature[64] != 0,
    r: UInt256.fromBytesBE(signature[0 ..< 32]),
    s: UInt256.fromBytesBE(signature[32 ..< 64]))

const SECP256K1N* =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141.u256

func ecdsa_validate_signature(
    signature: array[ECDSA_SIGNATURE_SIZE, byte]): Opt[void] =
  static: doAssert signature.len == 65
  if signature[64] > 1: return err()
  let (_, r, s) = ecdsa_unpack_signature(signature)
  if r >= SECP256K1N: return err()
  if s < UInt256.one or s >= SECP256K1N: return err()
  ok()

func ecdsa_recover_from_address*(
    signature: array[ECDSA_SIGNATURE_SIZE, byte],
    sig_hash: Hash256): Opt[EthAddress] =
  let
    recover_sig = Signature.fromRaw(signature).valueOr:
      return Opt.none EthAddress
    public_key = recover_sig.recover(sig_hash.data.SkMessage).valueOr:
      return Opt.none EthAddress
  Opt.some public_key.toCanonicalAddress()

# https://github.com/ethereum/EIPs/blob/master/assets/eip-6493/tx_hashes.py
func compute_sig_hash*(
    tx: ReplayableTransactionPayload, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.startList(6)
  w.append(tx.nonce)
  w.append(tx.max_fee_per_gas)
  w.append(tx.gas)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.input)
  keccakHash(w.finish())

func append_tx(w: var RlpWriter, tx: ReplayableTransaction, chain_id: ChainId) =
  let
    (y_parity, r, s) = ecdsa_unpack_signature(tx.signature.ecdsa_signature)
    v = (if y_parity: 28.u256 else: 27.u256)
  w.startList(9)
  w.append(tx.payload.nonce)
  w.append(tx.payload.max_fee_per_gas)
  w.append(tx.payload.gas)
  w.append(tx.payload.to)
  w.append(tx.payload.value)
  w.append(tx.payload.input)
  w.append(v)
  w.append(r)
  w.append(s)

func compute_tx_hash*(tx: ReplayableTransaction, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.append_tx(tx, chain_id)
  keccakHash(w.finish())

func compute_sig_hash*(
    tx: LegacyTransactionPayload, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.startList(9)
  w.append(tx.nonce)
  w.append(tx.max_fee_per_gas)
  w.append(tx.gas)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.input)
  w.append(chain_id)
  w.append(0)
  w.append(0)
  keccakHash(w.finish())

func append_tx(w: var RlpWriter, tx: LegacyTransaction, chain_id: ChainId) =
  let
    (y_parity, r, s) = ecdsa_unpack_signature(tx.signature.ecdsa_signature)
    v = distinctBase(chain_id).u256 * 2 + (if y_parity: 36.u256 else: 35.u256)
  w.startList(9)
  w.append(tx.payload.nonce)
  w.append(tx.payload.max_fee_per_gas)
  w.append(tx.payload.gas)
  w.append(tx.payload.to)
  w.append(tx.payload.value)
  w.append(tx.payload.input)
  w.append(v)
  w.append(r)
  w.append(s)

func compute_tx_hash*(tx: LegacyTransaction, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.append_tx(tx, chain_id)
  keccakHash(w.finish())

func compute_sig_hash*(
    tx: Eip2930TransactionPayload, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.append(TxEip2930)
  w.startList(8)
  w.append(chain_id)
  w.append(tx.nonce)
  w.append(tx.max_fee_per_gas)
  w.append(tx.gas)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.input)
  w.append(tx.access_list)
  keccakHash(w.finish())

func append_tx(w: var RlpWriter, tx: Eip2930Transaction, chain_id: ChainId) =
  let (y_parity, r, s) = ecdsa_unpack_signature(tx.signature.ecdsa_signature)
  w.startList(11)
  w.append(chain_id)
  w.append(tx.payload.nonce)
  w.append(tx.payload.max_fee_per_gas)
  w.append(tx.payload.gas)
  w.append(tx.payload.to)
  w.append(tx.payload.value)
  w.append(tx.payload.input)
  w.append(tx.payload.access_list)
  w.append(y_parity)
  w.append(r)
  w.append(s)

func compute_tx_hash*(tx: Eip2930Transaction, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.append(TxEip2930)
  w.append_tx(tx, chain_id)
  keccakHash(w.finish())

func compute_sig_hash*(
    tx: Eip1559TransactionPayload, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.append(TxEip1559)
  w.startList(9)
  w.append(chain_id)
  w.append(tx.nonce)
  w.append(tx.max_priority_fee_per_gas)
  w.append(tx.max_fee_per_gas)
  w.append(tx.gas)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.input)
  w.append(tx.access_list)
  keccakHash(w.finish())

func append_tx(w: var RlpWriter, tx: Eip1559Transaction, chain_id: ChainId) =
  let (y_parity, r, s) = ecdsa_unpack_signature(tx.signature.ecdsa_signature)
  w.startList(12)
  w.append(chain_id)
  w.append(tx.payload.nonce)
  w.append(tx.payload.max_priority_fee_per_gas)
  w.append(tx.payload.max_fee_per_gas)
  w.append(tx.payload.gas)
  w.append(tx.payload.to)
  w.append(tx.payload.value)
  w.append(tx.payload.input)
  w.append(tx.payload.access_list)
  w.append(y_parity)
  w.append(r)
  w.append(s)

func compute_tx_hash*(tx: Eip1559Transaction, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.append(TxEip1559)
  w.append_tx(tx, chain_id)
  keccakHash(w.finish())

func compute_sig_hash*(
    tx: Eip4844TransactionPayload, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.append(TxEip4844)
  w.startList(11)
  w.append(chain_id)
  w.append(tx.nonce)
  w.append(tx.max_priority_fee_per_gas)
  w.append(tx.max_fee_per_gas)
  w.append(tx.gas)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.input)
  w.append(tx.access_list)
  w.append(tx.max_fee_per_blob_gas)
  w.append(tx.blob_versioned_hashes)
  keccakHash(w.finish())

func append_tx(w: var RlpWriter, tx: Eip4844Transaction, chain_id: ChainId) =
  let (y_parity, r, s) = ecdsa_unpack_signature(tx.signature.ecdsa_signature)
  w.startList(14)
  w.append(tx.payload.nonce)
  w.append(tx.payload.max_priority_fee_per_gas)
  w.append(tx.payload.max_fee_per_gas)
  w.append(tx.payload.gas)
  w.append(tx.payload.to)
  w.append(tx.payload.value)
  w.append(tx.payload.input)
  w.append(tx.payload.access_list)
  w.append(tx.payload.max_fee_per_blob_gas)
  w.append(tx.payload.blob_versioned_hashes)
  w.append(y_parity)
  w.append(r)
  w.append(s)

func compute_tx_hash*(tx: Eip4844Transaction, chain_id: ChainId): Hash256 =
  var w = initRlpWriter()
  w.append(TxEip4844)
  w.append_tx(tx, chain_id)
  keccakHash(w.finish())

func compute_sig_hash*(tx: AnyTransactionPayload, chain_id: ChainId): Hash256 =
  withTxPayloadVariant(tx):
    txPayloadVariant.compute_sig_hash(chain_id)

func compute_sig_hash*(tx: TransactionPayload, chain_id: ChainId): Hash256 =
  let anyTx = AnyTransactionPayload.fromOneOfBase(tx).valueOr:
    raiseAssert "Cannot get sig hash for invalid `TransactionPayload`: " & $tx
  anyTx.compute_sig_hash(chain_id)

func compute_tx_hash*(tx: AnyTransaction, chain_id: ChainId): Hash256 =
  withTxVariant(tx):
    txVariant.compute_tx_hash(chain_id)

func compute_tx_hash*(tx: Transaction, chain_id: ChainId): Hash256 =
  let anyTx = AnyTransaction.fromOneOfBase(tx).valueOr:
    raiseAssert "Cannot get tx hash for invalid `Transaction`: " & $tx
  anyTx.compute_tx_hash(chain_id)

func validate_transaction*(
    tx: AnyTransactionVariant, chain_id: ChainId): Opt[void] =
  ? ecdsa_validate_signature(tx.signature.ecdsa_signature)
  let from_address = ? ecdsa_recover_from_address(
    tx.signature.ecdsa_signature,
    tx.payload.compute_sig_hash(chain_id))
  if tx.signature.from_address != from_address:
    return err()
  ok()

func toBytes(tx: AnyTransaction, chain_id: ChainId): seq[byte] =
  withTxVariant(tx):
    case txKind
    of TransactionKind.Eip4844:
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      @[TxEip4844.ord.uint8] & w.finish()
    of TransactionKind.Eip1559:
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      @[TxEip1559.ord.uint8] & w.finish()
    of TransactionKind.Eip2930:
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      @[TxEip2930.ord.uint8] & w.finish()
    of TransactionKind.Legacy:
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      w.finish()
    of TransactionKind.Replayable:
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      w.finish()

func toBytes*(tx: Transaction, chain_id: ChainId): seq[byte] =
  let anyTx = AnyTransaction.fromOneOfBase(tx).valueOr:
    raiseAssert "Cannot serialize invalid `Transaction`: " & $tx
  anyTx.toBytes(chain_id)

func toBytes*(txs: openArray[Transaction], chain_id: ChainId): seq[byte] =
  var writer = initRlpWriter()
  for tx in txs:
    let anyTx = AnyTransaction.fromOneOfBase(tx).valueOr:
      raiseAssert "Cannot serialize an invalid `Transaction`: " & $tx
    withTxVariant(anyTx):
      case txKind
      of TransactionKind.Eip4844:
        var w = initRlpWriter()
        w.append_tx(txVariant, chain_id)
        writer.append @[TxEip4844.ord.uint8] & w.finish()
      of TransactionKind.Eip1559:
        var w = initRlpWriter()
        w.append_tx(txVariant, chain_id)
        writer.append @[TxEip1559.ord.uint8] & w.finish()
      of TransactionKind.Eip2930:
        var w = initRlpWriter()
        w.append_tx(txVariant, chain_id)
        writer.append @[TxEip2930.ord.uint8] & w.finish()
      of TransactionKind.Legacy:
        writer.append_tx(txVariant, chain_id)
      of TransactionKind.Replayable:
        writer.append_tx(txVariant, chain_id)
  writer.finish()

func append_blob_data(w: var RlpWriter, blob_data: NetworkPayload) =
  w.append(distinctBase(blob_data.blobs))
  w.append(distinctBase(blob_data.commitments))
  w.append(distinctBase(blob_data.proofs))

func toBytes*(tx: PooledTransaction, chain_id: ChainId): seq[byte] =
  let anyTx = AnyTransaction.fromOneOfBase(tx.tx).valueOr:
    raiseAssert "Cannot serialize an invalid `PooledTransaction`: " & $tx
  withTxVariant(anyTx):
    case txKind
    of TransactionKind.Eip4844:
      doAssert tx.blob_data.isSome, "EIP-4844 requires `blob_data`"
      var w = initRlpWriter()
      w.startList(4)  # spec: rlp([tx_payload, blobs, commitments, proofs])
      w.append_tx(txVariant, chain_id)
      w.append_blob_data(tx.blob_data.unsafeGet)
      @[TxEip4844.ord.uint8] & w.finish()
    of TransactionKind.Eip1559:
      doAssert tx.blob_data.isNone, "`blob_data` requires EIP-4844"
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      @[TxEip1559.ord.uint8] & w.finish()
    of TransactionKind.Eip2930:
      doAssert tx.blob_data.isNone, "`blob_data` requires EIP-4844"
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      @[TxEip2930.ord.uint8] & w.finish()
    of TransactionKind.Legacy:
      doAssert tx.blob_data.isNone, "`blob_data` requires EIP-4844"
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      w.finish()
    of TransactionKind.Replayable:
      doAssert tx.blob_data.isNone, "`blob_data` requires EIP-4844"
      var w = initRlpWriter()
      w.append_tx(txVariant, chain_id)
      w.finish()

func toBytes*(txs: openArray[PooledTransaction], chain_id: ChainId): seq[byte] =
  var writer = initRlpWriter()
  for tx in txs:
    let anyTx = AnyTransaction.fromOneOfBase(tx.tx).valueOr:
      raiseAssert "Cannot serialize an invalid `PooledTransaction`: " & $tx
    withTxVariant(anyTx):
      case txKind
      of TransactionKind.Eip4844:
        doAssert tx.blob_data.isSome, "EIP-4844 requires `blob_data`"
        var w = initRlpWriter()
        w.startList(4)  # spec: rlp([tx_payload, blobs, commitments, proofs])
        w.append_tx(txVariant, chain_id)
        w.append_blob_data(tx.blob_data.unsafeGet)
        writer.append @[TxEip4844.ord.uint8] & w.finish()
      of TransactionKind.Eip1559:
        doAssert tx.blob_data.isNone, "`blob_data` requires EIP-4844"
        var w = initRlpWriter()
        w.append_tx(txVariant, chain_id)
        writer.append @[TxEip1559.ord.uint8] & w.finish()
      of TransactionKind.Eip2930:
        doAssert tx.blob_data.isNone, "`blob_data` requires EIP-4844"
        var w = initRlpWriter()
        w.append_tx(txVariant, chain_id)
        writer.append @[TxEip2930.ord.uint8] & w.finish()
      of TransactionKind.Legacy:
        doAssert tx.blob_data.isNone, "`blob_data` requires EIP-4844"
        writer.append_tx(txVariant, chain_id)
      of TransactionKind.Replayable:
        doAssert tx.blob_data.isNone, "`blob_data` requires EIP-4844"
        writer.append_tx(txVariant, chain_id)
  writer.finish()

# https://github.com/ethereum/EIPs/blob/master/assets/eip-6493/convert.py
func read_tx[T: LegacyTransactionPayload](
    rlp: var Rlp, t: typedesc[T], chain_id: ChainId
): Opt[tuple[tx: T, y_parity: bool, r: UInt256, s: UInt256, has_eip155: bool]] =
  try:
    var
      tx = LegacyTransactionPayload(tx_type: TxLegacy)
      v: UInt256
      r: UInt256
      s: UInt256
    rlp.tryEnterList()
    rlp.read(tx.nonce)
    rlp.read(tx.max_fee_per_gas)
    rlp.read(tx.gas)
    rlp.read(tx.to)
    rlp.read(tx.value)
    rlp.read(tx.input)
    rlp.read(v)
    rlp.read(r)
    rlp.read(s)
    let
      y_parity = v.isEven
      has_eip155 = (v > 28.u256 or v < 27.u256)
    if has_eip155:
      let expected_v =
        distinctBase(chain_id).u256 * 2 + (if y_parity: 36.u256 else: 35.u256)
      if v != expected_v: return err()
    if r >= SECP256K1N: return err()
    if s < UInt256.one or s >= SECP256K1N: return err()
    Opt.some (tx: tx, y_parity: y_parity, r: r, s: s, has_eip155: has_eip155)
  except RlpError:
    err()

func read_tx[T: Eip2930TransactionPayload](
    rlp: var Rlp, t: typedesc[T], chain_id: ChainId
): Opt[tuple[tx: T, y_parity: bool, r: UInt256, s: UInt256]] =
  try:
    var
      tx = Eip2930TransactionPayload(tx_type: TxEip2930)
      y_parity: uint8
      r: UInt256
      s: UInt256
    rlp.tryEnterList()
    if rlp.read(ChainId) != chain_id: return err()
    rlp.read(tx.nonce)
    rlp.read(tx.max_fee_per_gas)
    rlp.read(tx.gas)
    rlp.read(tx.to)
    rlp.read(tx.value)
    rlp.read(tx.input)
    rlp.read(tx.access_list)
    rlp.read(y_parity)
    rlp.read(r)
    rlp.read(s)
    if y_parity > 1: return err()
    if r >= SECP256K1N: return err()
    if s < UInt256.one or s >= SECP256K1N: return err()
    Opt.some (tx: tx, y_parity: y_parity != 0, r: r, s: s)
  except RlpError:
    err()

func read_tx[T: Eip1559TransactionPayload](
    rlp: var Rlp, t: typedesc[T], chain_id: ChainId
): Opt[tuple[tx: T, y_parity: bool, r: UInt256, s: UInt256]] =
  try:
    var
      tx = Eip1559TransactionPayload(tx_type: TxEip1559)
      y_parity: uint8
      r: UInt256
      s: UInt256
    rlp.tryEnterList()
    if rlp.read(ChainId) != chain_id: return err()
    rlp.read(tx.nonce)
    rlp.read(tx.max_priority_fee_per_gas)
    rlp.read(tx.max_fee_per_gas)
    rlp.read(tx.gas)
    rlp.read(tx.to)
    rlp.read(tx.value)
    rlp.read(tx.input)
    rlp.read(tx.access_list)
    rlp.read(y_parity)
    rlp.read(r)
    rlp.read(s)
    if y_parity > 1: return err()
    if r >= SECP256K1N: return err()
    if s < UInt256.one or s >= SECP256K1N: return err()
    Opt.some (tx: tx, y_parity: y_parity != 0, r: r, s: s)
  except RlpError:
    err()

func read_tx[T: Eip4844TransactionPayload](
    rlp: var Rlp, t: typedesc[T], chain_id: ChainId
): Opt[tuple[tx: T, y_parity: bool, r: UInt256, s: UInt256]] =
  try:
    var
      tx = Eip4844TransactionPayload(tx_type: TxEip4844)
      y_parity: uint8
      r: UInt256
      s: UInt256
    rlp.tryEnterList()
    if rlp.read(ChainId) != chain_id: return err()
    rlp.read(tx.nonce)
    rlp.read(tx.max_priority_fee_per_gas)
    rlp.read(tx.max_fee_per_gas)
    rlp.read(tx.gas)
    rlp.read(tx.to)
    rlp.read(tx.value)
    rlp.read(tx.input)
    rlp.read(tx.access_list)
    rlp.read(tx.max_fee_per_blob_gas)
    rlp.read(tx.blob_versioned_hashes)
    rlp.read(y_parity)
    rlp.read(r)
    rlp.read(s)
    if y_parity > 1: return err()
    if r >= SECP256K1N: return err()
    if s < UInt256.one or s >= SECP256K1N: return err()
    Opt.some (tx: tx, y_parity: y_parity != 0, r: r, s: s)
  except RlpError:
    err()

func read_tx(
    rlp: var Rlp,
    chain_id: ChainId,
    tx_type: TxType): Opt[AnyTransaction] =
  case tx_type
  of TxEip4844:
    let (tx, y_parity, r, s) =
      ? rlp.read_tx(Eip4844TransactionPayload, chain_id)
    var signature: TransactionSignature
    signature.ecdsa_signature = ecdsa_pack_signature(y_parity, r, s)
    signature.from_address = ? ecdsa_recover_from_address(
      signature.ecdsa_signature, tx.compute_sig_hash(chain_id))
    Opt.some AnyTransaction.init(
      Eip4844Transaction(payload: tx, signature: signature))
  of TxEip1559:
    let (tx, y_parity, r, s) =
      ? rlp.read_tx(Eip1559TransactionPayload, chain_id)
    var signature: TransactionSignature
    signature.ecdsa_signature = ecdsa_pack_signature(y_parity, r, s)
    signature.from_address = ? ecdsa_recover_from_address(
      signature.ecdsa_signature, tx.compute_sig_hash(chain_id))
    Opt.some AnyTransaction.init(
      Eip1559Transaction(payload: tx, signature: signature))
  of TxEip2930:
    let (tx, y_parity, r, s) =
      ? rlp.read_tx(Eip2930TransactionPayload, chain_id)
    var signature: TransactionSignature
    signature.ecdsa_signature = ecdsa_pack_signature(y_parity, r, s)
    signature.from_address = ? ecdsa_recover_from_address(
      signature.ecdsa_signature, tx.compute_sig_hash(chain_id))
    Opt.some AnyTransaction.init(
      Eip2930Transaction(payload: tx, signature: signature))
  of TxLegacy:
    let (tx, y_parity, r, s, has_eip155) =
      ? rlp.read_tx(LegacyTransactionPayload, chain_id)
    if has_eip155:
      var signature: TransactionSignature
      signature.ecdsa_signature = ecdsa_pack_signature(y_parity, r, s)
      signature.from_address = ? ecdsa_recover_from_address(
        signature.ecdsa_signature, tx.compute_sig_hash(chain_id))
      Opt.some AnyTransaction.init(
        LegacyTransaction(payload: tx, signature: signature))
    else:
      let tx = ReplayableTransactionPayload(
        nonce: tx.nonce,
        max_fee_per_gas: tx.max_fee_per_gas,
        gas: tx.gas,
        to: tx.to,
        value: tx.value,
        input: tx.input)
      var signature: TransactionSignature
      signature.ecdsa_signature = ecdsa_pack_signature(y_parity, r, s)
      signature.from_address = ? ecdsa_recover_from_address(
        signature.ecdsa_signature, tx.compute_sig_hash(chain_id))
      Opt.some AnyTransaction.init(
        ReplayableTransaction(payload: tx, signature: signature))

func fromBytes(
    T: typedesc[AnyTransaction],
    data: openArray[byte],
    chain_id: ChainId): Opt[AnyTransaction] =
  if data.len < 1:
    return Opt.none AnyTransaction
  case data[0]
  of TxEip4844.ord:
    var rlp = rlpFromBytes(data[1 ..< data.len])
    let tx = rlp.read_tx(chain_id, TxEip4844)
    if tx.isSome and rlp.hasData:
      return Opt.none AnyTransaction
    tx
  of TxEip1559.ord:
    var rlp = rlpFromBytes(data[1 ..< data.len])
    let tx = rlp.read_tx(chain_id, TxEip1559)
    if tx.isSome and rlp.hasData:
      return Opt.none AnyTransaction
    tx
  of TxEip2930.ord:
    var rlp = rlpFromBytes(data[1 ..< data.len])
    let tx = rlp.read_tx(chain_id, TxEip2930)
    if tx.isSome and rlp.hasData:
      return Opt.none AnyTransaction
    tx
  of 0xc0 .. 0xfe:
    var rlp = rlpFromBytes(data)
    let tx = rlp.read_tx(chain_id, TxLegacy)
    if tx.isSome and rlp.hasData:
      return Opt.none AnyTransaction
    tx
  else:
    Opt.none AnyTransaction

func fromBytes*(
    T: typedesc[Transaction],
    data: openArray[byte],
    chain_id: ChainId): Opt[Transaction] =
  let tx = ? AnyTransaction.fromBytes(data, chain_id)
  Opt.some tx.toOneOfBase()

func fromBytesWrapped(
    T: typedesc[AnyTransaction],
    data: openArray[byte],
    chain_id: ChainId): Opt[AnyTransaction] =
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
  var rlp = rlpFromBytes(data)
  if rlp.isList:
    let tx = rlp.read_tx(chain_id, TxLegacy)
    if tx.isSome and rlp.hasData:
      return Opt.none AnyTransaction
    tx
  else:
    try:
      var data = rlp.read(Blob)
      if rlp.hasData:
        return Opt.none AnyTransaction
      if data.len < 1:
        return Opt.none AnyTransaction
      case data[0]
      of TxEip4844.ord:
        var rlp = rlpFromBytes(data[1 ..< data.len])
        let tx = rlp.read_tx(chain_id, TxEip4844)
        if tx.isSome and rlp.hasData:
          return Opt.none AnyTransaction
        tx
      of TxEip1559.ord:
        var rlp = rlpFromBytes(data[1 ..< data.len])
        let tx = rlp.read_tx(chain_id, TxEip1559)
        if tx.isSome and rlp.hasData:
          return Opt.none AnyTransaction
        tx
      of TxEip2930.ord:
        var rlp = rlpFromBytes(data[1 ..< data.len])
        let tx = rlp.read_tx(chain_id, TxEip2930)
        if tx.isSome and rlp.hasData:
          return Opt.none AnyTransaction
        tx
      else:
        Opt.none AnyTransaction
    except RlpError:
      Opt.none AnyTransaction

func fromBytesWrapped(
    T: typedesc[Transaction],
    data: openArray[byte],
    chain_id: ChainId): Opt[Transaction] =
  let tx = ? AnyTransaction.fromBytesWrapped(data, chain_id)
  Opt.some tx.toOneOfBase()

func fromBytes*(
    T: typedesc[seq[Transaction]],
    data: openArray[byte],
    chain_id: ChainId): Opt[seq[Transaction]] =
  var rlp = rlpFromBytes(data)
  if not rlp.isList:
    return Opt.none seq[Transaction]
  try:
    var res: seq[Transaction]
    for item in rlp:
      res.add(? Transaction.fromBytesWrapped(item.toBytes(), chain_id))
    if rlp.hasData:
      return Opt.none seq[Transaction]
    Opt.some res
  except RlpError:
    Opt.none seq[Transaction]

func read_blob_data(rlp: var Rlp): Opt[NetworkPayload] =
  try:
    var
      blobs: seq[NetworkBlob]
      commitments: seq[KzgCommitment]
      proofs: seq[KzgProof]
    rlp.read(blobs)
    rlp.read(commitments)
    rlp.read(proofs)
    Opt.some NetworkPayload(
      blobs: List[NetworkBlob, MAX_BLOB_COMMITMENTS_PER_BLOCK]
        .init blobs,
      commitments: List[KzgCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]
        .init commitments,
      proofs: List[KzgProof, MAX_BLOB_COMMITMENTS_PER_BLOCK]
        .init proofs)
  except RlpError:
    Opt.none NetworkPayload

func fromBytes*(
    T: typedesc[PooledTransaction],
    data: openArray[byte],
    chain_id: ChainId): Opt[PooledTransaction] =
  if data.len < 1:
    return Opt.none PooledTransaction
  try:
    case data[0]
    of TxEip4844.ord:
      var rlp = rlpFromBytes(data[1 ..< data.len])
      rlp.tryEnterList()  # spec: rlp([tx_payload, blobs, commitments, proofs])
      let tx = Opt.some PooledTransaction(
        tx: (? rlp.read_tx(chain_id, TxEip4844)).toOneOfBase(),
        blob_data: Opt.some(? rlp.read_blob_data()))
      if rlp.hasData:
        return Opt.none PooledTransaction
      tx
    of TxEip1559.ord:
      var rlp = rlpFromBytes(data[1 ..< data.len])
      let tx = Opt.some PooledTransaction(
        tx: (? rlp.read_tx(chain_id, TxEip1559)).toOneOfBase())
      if rlp.hasData:
        return Opt.none PooledTransaction
      tx
    of TxEip2930.ord:
      var rlp = rlpFromBytes(data[1 ..< data.len])
      let tx = Opt.some PooledTransaction(
        tx: (? rlp.read_tx(chain_id, TxEip2930)).toOneOfBase())
      if rlp.hasData:
        return Opt.none PooledTransaction
      tx
    of 0xc0 .. 0xfe:
      var rlp = rlpFromBytes(data)
      let tx = Opt.some PooledTransaction(
        tx: (? rlp.read_tx(chain_id, TxLegacy)).toOneOfBase())
      if rlp.hasData:
        return Opt.none PooledTransaction
      tx
    else:
      Opt.none PooledTransaction
  except RlpError:
    Opt.none PooledTransaction

func fromBytesWrapped(
    T: typedesc[PooledTransaction],
    data: openArray[byte],
    chain_id: ChainId): Opt[PooledTransaction] =
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
  var rlp = rlpFromBytes(data)
  if rlp.isList:
    let tx = Opt.some PooledTransaction(
      tx: (? rlp.read_tx(chain_id, TxLegacy)).toOneOfBase())
    if tx.isSome and rlp.hasData:
      return Opt.none PooledTransaction
    tx
  else:
    try:
      var data = rlp.read(Blob)
      if rlp.hasData:
        return Opt.none PooledTransaction
      if data.len < 1:
        return Opt.none PooledTransaction
      case data[0]
      of TxEip4844.ord:
        var rlp = rlpFromBytes(data[1 ..< data.len])
        rlp.tryEnterList()
        let tx = Opt.some PooledTransaction(
          tx: (? rlp.read_tx(chain_id, TxEip4844)).toOneOfBase(),
          blob_data: Opt.some(? rlp.read_blob_data()))
        if rlp.hasData:
          return Opt.none PooledTransaction
        tx
      of TxEip1559.ord:
        var rlp = rlpFromBytes(data[1 ..< data.len])
        let tx = Opt.some PooledTransaction(
          tx: (? rlp.read_tx(chain_id, TxEip1559)).toOneOfBase())
        if rlp.hasData:
          return Opt.none PooledTransaction
        tx
      of TxEip2930.ord:
        var rlp = rlpFromBytes(data[1 ..< data.len])
        let tx = Opt.some PooledTransaction(
          tx: (? rlp.read_tx(chain_id, TxEip2930)).toOneOfBase())
        if rlp.hasData:
          return Opt.none PooledTransaction
        tx
      of 0xc0 .. 0xfe:
        var rlp = rlpFromBytes(data)
        let tx = Opt.some PooledTransaction(
          tx: (? rlp.read_tx(chain_id, TxLegacy)).toOneOfBase())
        if rlp.hasData:
          return Opt.none PooledTransaction
        tx
      else:
        Opt.none PooledTransaction
    except RlpError:
      Opt.none PooledTransaction

func fromBytes*(
    T: typedesc[seq[PooledTransaction]],
    data: openArray[byte],
    chain_id: ChainId): Opt[seq[PooledTransaction]] =
  var rlp = rlpFromBytes(data)
  if not rlp.isList:
    return Opt.none seq[PooledTransaction]
  try:
    var res: seq[PooledTransaction]
    for item in rlp:
      res.add(? PooledTransaction.fromBytesWrapped(item.toBytes(), chain_id))
    if rlp.hasData:
      return Opt.none seq[PooledTransaction]
    Opt.some res
  except RlpError:
    Opt.none seq[PooledTransaction]

proc signTransaction*(
    tx: TransactionPayload,
    privateKey: PrivateKey,
    chainId: ChainId): Transaction =
  var signature: TransactionSignature
  signature.ecdsa_signature = privateKey.sign(
    tx.compute_sig_hash(chainId).data.SkMessage).toRaw()
  signature.from_address = ecdsa_recover_from_address(
    signature.ecdsa_signature, tx.compute_sig_hash(chainId)).expect("Sig OK")
  Transaction(payload: tx, signature: signature)
