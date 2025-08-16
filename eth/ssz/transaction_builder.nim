import
  stint,
  "."/transaction_ssz,
  "."/utils,
  ".."/common/[addresses, base, hashes]

type
  TxBuildError* = object of ValueError

# what to do about  gas check ??
# when compiles(p.gas) ??

template fail(msg: string): untyped =
  raise newException(TxBuildError, msg)

# Legacy (EIP-155) — basic (call)
proc validate*(p: RlpLegacyBasicTransactionPayload) =
  if p.txType != TxLegacy: fail("legacy basic: txType must be 0x00 (TxLegacy)")
  if p.chain_id == ChainId(0.u256): fail("legacy basic: chain_id must be non-zero")
#   if not p.gas > 0'u64: fail("legacy basic: gas must be > 0")

# Legacy (EIP-155) — create
proc validate*(p: RlpLegacyCreateTransactionPayload) =
  if p.txType != TxLegacy: fail("legacy create: txType must be 0x00 (TxLegacy)")
  if p.chain_id == ChainId(0.u256): fail("legacy create: chain_id must be non-zero")
#   if not p.gas > 0'u64: fail("legacy create: gas must be > 0")
  if p.input.len == 0: fail("legacy create: initcode (input) must be non-empty")

# 2930 — basic (call)
proc validate*(p: RlpAccessListBasicTransactionPayload) =
  if p.txType != TxAccessList: fail("2930 basic: txType must be 0x01 (TxAccessList)")
  if p.chain_id == ChainId(0.u256): fail("2930 basic: chain_id must be non-zero")
#   if not p.gas > 0'u64: fail("2930 basic: gas must be > 0")

# 2930 — create
proc validate*(p: RlpAccessListCreateTransactionPayload) =
  if p.txType != TxAccessList: fail("2930 create: txType must be 0x01 (TxAccessList)")
  if p.chain_id == ChainId(0.u256): fail("2930 create: chain_id must be non-zero")
#   if not p.gas > 0'u64: fail("2930 create: gas must be > 0")
  if p.input.len == 0: fail("2930 create: initcode (input) must be non-empty")

# 1559 — basic (call)
proc validate*(p: RlpBasicTransactionPayload) =
  if p.txType != TxDynamicFee: fail("1559 basic: txType must be 0x02 (TxDynamicFee)")
  if p.chain_id == ChainId(0.u256): fail("1559 basic: chain_id must be non-zero")
#   if not p.gas > 0'u64: fail("1559 basic: gas must be > 0")
  if p.max_priority_fees_per_gas.regular > p.max_fees_per_gas.regular:
    fail("1559 basic: max_fees_per_gas.regular < max_priority_fees_per_gas.regular")

# 1559 — create
proc validate*(p: RlpCreateTransactionPayload) =
  if p.txType != TxDynamicFee: fail("1559 create: txType must be 0x02 (TxDynamicFee)")
  if p.chain_id == ChainId(0.u256): fail("1559 create: chain_id must be non-zero")
#   if not p.gas > 0'u64: fail("1559 create: gas must be > 0")
  if p.input.len == 0: fail("1559 create: initcode (input) must be non-empty")
  if p.max_priority_fees_per_gas.regular > p.max_fees_per_gas.regular:
    fail("1559 create: max_fees_per_gas.regular < max_priority_fees_per_gas.regular")

# 4844 — blob (call only per EIP-4844)
proc validate*(p: RlpBlobTransactionPayload) =
  if p.txType != TxBlob: fail("4844 blob: txType must be 0x03 (TxBlob)")
  if p.chain_id == ChainId(0.u256): fail("4844 blob: chain_id must be non-zero")
#   if not p.gas > 0'u64: fail("4844 blob: gas must be > 0")
  if p.blob_versioned_hashes.len == 0:
    fail("4844 blob: blob_versioned_hashes must be non-empty")
  if p.max_priority_fees_per_gas.regular > p.max_fees_per_gas.regular:
    fail("4844 blob: max_fees_per_gas.regular < max_priority_fees_per_gas.regular")
  # NOTE: The spec does not mandate blob fee > 0 — do not enforce here.

# 7702 — setCode (call)
proc validate*(p: RlpSetCodeTransactionPayload) =
  if p.txType != 0x04'u8: fail("7702: txType must be 0x04 (SetCode)")
  if p.chain_id == ChainId(0.u256): fail("7702: chain_id must be non-zero")
#   if not p.gas > 0'u64: fail("7702: gas must be > 0")
  if p.authorization_list.len == 0:
    fail("7702: authorization_list must be non-empty")

proc validate*(sig: Secp256k1ExecutionSignature) =
  if not secp256k1Validate(sig):
    fail("invalid secp256k1 signature")


# TODO: make a marco that does this to get rid of these many build
proc build*(payload: RlpLegacyBasicTransactionPayload,
            signature: Secp256k1ExecutionSignature): Transaction =
  validate(payload); validate(signature)
  let inner = RlpLegacyBasicTransaction(payload: payload, signature: signature)
  Transaction(kind: txRlp, rlp: RlpTransaction(kind: legacyBasic, legacyBasicTx: inner))

proc build*(payload: RlpLegacyCreateTransactionPayload,
            signature: Secp256k1ExecutionSignature): Transaction =
  validate(payload); validate(signature)
  let inner = RlpLegacyCreateTransaction(payload: payload, signature: signature)
  Transaction(kind: txRlp, rlp: RlpTransaction(kind: legacyCreate, legacyCreateTx: inner))

proc build*(payload: RlpAccessListBasicTransactionPayload,
            signature: Secp256k1ExecutionSignature): Transaction =
  validate(payload); validate(signature)
  let inner = RlpAccessListBasicTransaction(payload: payload, signature: signature)
  Transaction(kind: txRlp, rlp: RlpTransaction(kind: accessListBasic, accessListBasicTx: inner))

proc build*(payload: RlpAccessListCreateTransactionPayload,
            signature: Secp256k1ExecutionSignature): Transaction =
  validate(payload); validate(signature)
  let inner = RlpAccessListCreateTransaction(payload: payload, signature: signature)
  Transaction(kind: txRlp, rlp: RlpTransaction(kind: accessListCreate, accessListCreateTx: inner))

proc build*(payload: RlpBasicTransactionPayload,
            signature: Secp256k1ExecutionSignature): Transaction =
  validate(payload); validate(signature)
  let inner = RlpBasicTransaction(payload: payload, signature: signature)
  Transaction(kind: txRlp, rlp: RlpTransaction(kind: basic1559, basic1559Tx: inner))

proc build*(payload: RlpCreateTransactionPayload,
            signature: Secp256k1ExecutionSignature): Transaction =
  validate(payload); validate(signature)
  let inner = RlpCreateTransaction(payload: payload, signature: signature)
  Transaction(kind: txRlp, rlp: RlpTransaction(kind: create1559, create1559Tx: inner))

proc build*(payload: RlpBlobTransactionPayload,
            signature: Secp256k1ExecutionSignature): Transaction =
  validate(payload); validate(signature)
  let inner = RlpBlobTransaction(payload: payload, signature: signature)
  Transaction(kind: txRlp, rlp: RlpTransaction(kind: blob4844, blobTx: inner))

proc build*(payload: RlpSetCodeTransactionPayload,
            signature: Secp256k1ExecutionSignature): Transaction =
  validate(payload); validate(signature)
  let inner = RlpSetCodeTransaction(payload: payload, signature: signature)
  Transaction(kind: txRlp, rlp: RlpTransaction(kind: setCode7702, setCodeTx: inner))

proc Transaction*(
  txType: uint8,                                 # 0x00 legacy, 0x01 2930, 0x02 1559, 0x03 4844, 0x04 7702
  chain_id: ChainId,
  nonce: uint64,
  gas: GasAmount,
  to: Opt[Address],                              # some(addr) => call, none => create
  value: UInt256,
  input: openArray[byte],
  max_fees_per_gas: BasicFeesPerGas,
  signature: Secp256k1ExecutionSignature,
  # optional / per-type extras:
  max_priority_fees_per_gas: BasicFeesPerGas = BasicFeesPerGas(regular: 0.u256),
  access_list: seq[AccessTuple] = @[],
  blob_versioned_hashes: seq[VersionedHash] = @[],
  blob_fee: FeePerGas = 0.u256,
  authorization_list: seq[RlpAuthorization] = @[]
): Transaction =
  case txType
  of 0x00'u8: # Legacy
    if to.isSome:
      let p = RlpLegacyBasicTransactionPayload(
        txType: txType, 
        chain_id: chain_id, 
        nonce: nonce,
        max_fees_per_gas: max_fees_per_gas, 
        gas: gas,
        to: to.get, 
        value: value,
         input: @input)
      return build(p, signature)                  # -> Transaction(kind=txRlp, rlp.kind=legacyBasic)
    else:
      let p = RlpLegacyCreateTransactionPayload(
        txType: txType,
        chain_id: chain_id, 
        nonce: nonce,
        max_fees_per_gas: max_fees_per_gas, 
        gas: gas,
        value: value, 
        input: @input)
      return build(p, signature)                  # -> legacyCreate

  of 0x01'u8: # EIP-2930
    if to.isSome:
      let p = RlpAccessListBasicTransactionPayload(
        txType: txType, 
        chain_id: chain_id, 
        nonce: nonce,
        max_fees_per_gas: max_fees_per_gas, 
        gas: gas,
        to: to.get, 
        value: value, 
        input: @input,
        access_list: access_list)
      return build(p, signature)                  # -> accessListBasic
    else:
      let p = RlpAccessListCreateTransactionPayload(
        txType: txType, 
        chain_id: chain_id, 
        nonce: nonce,
        max_fees_per_gas: max_fees_per_gas, 
        gas: gas,
        value: value, 
        input: @input,
        access_list: access_list)
      return build(p, signature)                  # -> accessListCreate

  of 0x02'u8: # EIP-1559
    if to.isSome:
      let p = RlpBasicTransactionPayload(
        txType: txType, 
        chain_id: chain_id, 
        nonce: nonce,
        max_fees_per_gas: max_fees_per_gas, 
        gas: gas,
        to: to.get, 
        value: value, 
        input: @input,
        access_list: access_list,
        max_priority_fees_per_gas: max_priority_fees_per_gas)
      return build(p, signature)                  # -> basic1559
    else:
      let p = RlpCreateTransactionPayload(
        txType: txType, 
        chain_id: chain_id, 
        nonce: nonce,
        max_fees_per_gas: max_fees_per_gas, 
        gas: gas,
        value: value, 
        input: @input,
        access_list: access_list,
        max_priority_fees_per_gas: max_priority_fees_per_gas)
      return build(p, signature)                  # -> create1559

  of 0x03'u8:
    if to.isNone:
      fail("4844 blob: create-style not supported")
    when compiles(BlobFeesPerGas):
      let blobFees = BlobFeesPerGas(regular: max_fees_per_gas.regular, blob: blob_fee)
      let p = RlpBlobTransactionPayload(
        txType: txType, 
        chain_id: chain_id, 
        nonce: nonce,
        max_fees_per_gas: blobFees, 
        gas: gas,
        to: to.get, 
        value: value, 
        input: @input,
        access_list: access_list,
        max_priority_fees_per_gas: max_priority_fees_per_gas,
        blob_versioned_hashes: blob_versioned_hashes)
      return build(p, signature)                  # -> blob4844
    else:
      fail("4844 blob: BlobFeesPerGas type not available in this build")

  of 0x04'u8: # EIP-7702 setCode (call-only)
    if to.isNone:
      fail("7702 setCode: requires 'to'")
    if authorization_list.len == 0:
      fail("7702 setCode: authorization_list must be non-empty")
    let p = RlpSetCodeTransactionPayload(
      txType: 0x04'u8, 
      chain_id: chain_id, 
      nonce: nonce,
      max_fees_per_gas: max_fees_per_gas, 
      gas: gas,
      to: to.get, 
      value: value, 
      input: @input,
      access_list: access_list,
      max_priority_fees_per_gas: max_priority_fees_per_gas,
      authorization_list: authorization_list)
    return build(p, signature)                    # -> setCode7702

  else:
    fail("Unsupported txType (expected 0x00..0x04)")
