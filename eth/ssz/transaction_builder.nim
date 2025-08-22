import stint, "."/transaction_ssz, "."/utils, ".."/common/[addresses, base, hashes]

type TxBuildError* = object of ValueError

template fail(msg: string): untyped =
  raise newException(TxBuildError, msg)

# template requireGasPositiveIfEnabled(payload: untyped, contextName: static[string]) =
#     when compiles(payload.gas):
#       if payload.gas == 0'u64:
#         fail(contextName & ": gas must be > 0")

template requirePriorityFeeNotAboveMax(payload: untyped, contextName: static[string]) =
  when compiles(payload.max_priority_fees_per_gas):
    if payload.max_priority_fees_per_gas.regular > payload.max_fees_per_gas.regular:
      fail(
        contextName & ": max_fees_per_gas.regular < max_priority_fees_per_gas.regular"
      )

template validateCommonFields(
    payload: untyped,
    expectedTxType: static[uint8],
    contextName: static[string],
    txTypeErrorMsg: static[string],
) =
  if payload.txType != expectedTxType:
    fail(txTypeErrorMsg)
  if payload.chain_id == ChainId(0.u256):
    fail(contextName & ": chain_id must be non-zero")
  # requireGasPositiveIfEnabled(payload, contextName)
  requirePriorityFeeNotAboveMax(payload, contextName)

# Legacy (EIP-155) — basic (call)
proc validate*(p: RlpLegacyBasicTransactionPayload) =
  validateCommonFields(
    p, 0x00'u8, "legacy basic", "legacy basic: txType must be 0x00 (TxLegacy)"
  )

# Legacy (EIP-155) — create
proc validate*(p: RlpLegacyCreateTransactionPayload) =
  validateCommonFields(
    p, 0x00'u8, "legacy create", "legacy create: txType must be 0x00 (TxLegacy)"
  )
  if p.input.len == 0:
    fail("legacy create: initcode (input) must be non-empty")

# 2930 — basic (call)
proc validate*(p: RlpAccessListBasicTransactionPayload) =
  validateCommonFields(
    p, 0x01'u8, "2930 basic", "2930 basic: txType must be 0x01 (TxAccessList)"
  )

# 2930 — create
proc validate*(p: RlpAccessListCreateTransactionPayload) =
  validateCommonFields(
    p, 0x01'u8, "2930 create", "2930 create: txType must be 0x01 (TxAccessList)"
  )
  if p.input.len == 0:
    fail("2930 create: initcode (input) must be non-empty")

# 1559 — basic (call)
proc validate*(p: RlpBasicTransactionPayload) =
  validateCommonFields(
    p, 0x02'u8, "1559 basic", "1559 basic: txType must be 0x02 (TxDynamicFee)"
  )

# 1559 — create
proc validate*(p: RlpCreateTransactionPayload) =
  validateCommonFields(
    p, 0x02'u8, "1559 create", "1559 create: txType must be 0x02 (TxDynamicFee)"
  )
  if p.input.len == 0:
    fail("1559 create: initcode (input) must be non-empty")

# 4844 — blob (call-only)
proc validate*(p: RlpBlobTransactionPayload) =
  validateCommonFields(
    p, 0x03'u8, "4844 blob", "4844 blob: txType must be 0x03 (TxBlob)"
  )
  if p.blob_versioned_hashes.len == 0:
    fail("4844 blob: blob_versioned_hashes must be non-empty")

# 7702 — setCode (call)
proc validate*(p: RlpSetCodeTransactionPayload) =
  validateCommonFields(p, 0x04'u8, "7702", "7702: txType must be 0x04 (SetCode)")
  if p.authorization_list.len == 0:
    fail("7702: authorization_list must be non-empty")

proc validate*(sig: Secp256k1ExecutionSignature) =
  if not secp256k1Validate(sig):
    fail("invalid secp256k1 signature")

template defBuild(PayloadT, WrapperT: typedesc) =
  proc build*(
      payload: PayloadT, signature: Secp256k1ExecutionSignature
  ): WrapperT {.inline.} =
    validate(payload)
    validate(signature)
    WrapperT(payload: payload, signature: signature)

defBuild(RlpLegacyBasicTransactionPayload, RlpLegacyBasicTransaction)
defBuild(RlpLegacyCreateTransactionPayload, RlpLegacyCreateTransaction)
defBuild(RlpAccessListBasicTransactionPayload, RlpAccessListBasicTransaction)
defBuild(RlpAccessListCreateTransactionPayload, RlpAccessListCreateTransaction)
defBuild(RlpBasicTransactionPayload, RlpBasicTransaction)
defBuild(RlpCreateTransactionPayload, RlpCreateTransaction)
defBuild(RlpBlobTransactionPayload, RlpBlobTransaction)
defBuild(RlpSetCodeTransactionPayload, RlpSetCodeTransaction)

proc Transaction*(
    txType: uint8,
    chain_id: ChainId,
    nonce: uint64,
    gas: GasAmount,
    to: Opt[Address], # some(addr) => call, none => create
    value: UInt256,
    input: openArray[byte],
    max_fees_per_gas: BasicFeesPerGas,
    signature: Secp256k1ExecutionSignature,
    max_priority_fees_per_gas: BasicFeesPerGas = BasicFeesPerGas(regular: 0.u256),
    access_list: seq[AccessTuple] = @[],
    blob_versioned_hashes: seq[VersionedHash] = @[],
    blob_fee: FeePerGas = 0.u256,
    authorization_list: seq[RlpAuthorization] = @[],
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
        input: @input,
      )
      return build(p, signature)
    else:
      let p = RlpLegacyCreateTransactionPayload(
        txType: txType,
        chain_id: chain_id,
        nonce: nonce,
        max_fees_per_gas: max_fees_per_gas,
        gas: gas,
        value: value,
        input: @input,
      )
      return build(p, signature)
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
        access_list: access_list,
      )
      return build(p, signature)
    else:
      let p = RlpAccessListCreateTransactionPayload(
        txType: txType,
        chain_id: chain_id,
        nonce: nonce,
        max_fees_per_gas: max_fees_per_gas,
        gas: gas,
        value: value,
        input: @input,
        access_list: access_list,
      )
      return build(p, signature)
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
        max_priority_fees_per_gas: max_priority_fees_per_gas,
      )
      return build(p, signature)
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
        max_priority_fees_per_gas: max_priority_fees_per_gas,
      )
      return build(p, signature)
  of 0x03'u8: # EIP-4844 (call only)
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
        blob_versioned_hashes: blob_versioned_hashes,
      )
      return build(p, signature)
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
      authorization_list: authorization_list,
    )
    return build(p, signature)
  else:
    fail("Unsupported txType (expected 0x00..0x04)")
