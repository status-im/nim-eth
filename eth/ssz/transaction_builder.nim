import
  stint,
  ./transaction_ssz,
  ./signatures,
  ../common/[addresses, base, hashes]

type TxBuildError* = object of ValueError

template fail(msg: string): untyped =
  raise newException(TxBuildError, msg)

proc makeAuthorization*(t: AuthTuple): Authorization =
  let payload =
    if t.chain_id == ChainId(0.u256):
      AuthorizationPayload(
        kind: authReplayableBasic,
        replayable: RlpReplayableBasicAuthorizationPayload(
          magic: AuthMagic7702,
          address: t.address,
          nonce:   t.nonce
        )
      )
    else:
      AuthorizationPayload(
        kind: authBasic,
        basic: RlpBasicAuthorizationPayload(
          magic:    AuthMagic7702,
          chain_id: t.chain_id,
          address:  t.address,
          nonce:    t.nonce
        )
      )

  Authorization(
    payload:    payload,
    signature:  secp256k1Pack(t.r, t.s, t.y_parity)
  )

proc makeAuthorizationList*(xs: openArray[AuthTuple]): seq[Authorization] =
  result = newSeqOfCap[Authorization](xs.len)
  for x in xs:
    result.add makeAuthorization(x)

template BuildWrap(
    PayloadT, WrapperT: typedesc, tag: static[RLPTransactionKind], fieldSym: untyped
) =
  proc build*(
      payload: PayloadT, signature: Secp256k1ExecutionSignature
  ): Transaction {.inline.} =
    let inner = WrapperT(payload: payload, signature: signature)
    Transaction(
      kind: RlpTransaction, rlp: RlpTransactionObject(kind: tag, fieldSym: inner)
    )

BuildWrap( RlpLegacyBasicTransactionPayload, RlpLegacyBasicTransaction, txLegacyBasic, legacyBasic)
BuildWrap( RlpLegacyCreateTransactionPayload, RlpLegacyCreateTransaction, txLegacyCreate, legacyCreate)
BuildWrap(RlpAccessListBasicTransactionPayload, RlpAccessListBasicTransaction, txAccessListBasic, accessListBasic,)
BuildWrap(RlpAccessListCreateTransactionPayload, RlpAccessListCreateTransaction, txAccessListCreate, accessListCreate,)
BuildWrap(RlpBasicTransactionPayload, RlpBasicTransaction, txBasic, basic)
BuildWrap(RlpCreateTransactionPayload, RlpCreateTransaction, txCreate, create)
BuildWrap(RlpBlobTransactionPayload, RlpBlobTransaction, txBlob, blob)
BuildWrap(RlpSetCodeTransactionPayload, RlpSetCodeTransaction, txSetCode, setCode)
BuildWrap(RlpLegacyReplayableBasicTransactionPayload, RlpLegacyReplayableBasicTransaction, txLegacyReplayableBasic, legacyReplayableBasic)
BuildWrap(RlpLegacyReplayableCreateTransactionPayload, RlpLegacyReplayableCreateTransaction, txLegacyReplayableCreate, legacyReplayableCreate)

proc Transaction*(
    txType: uint8,
    chain_id: ChainId,
    nonce: uint64,
    gas: GasAmount,
    to: Opt[Address],
    value: UInt256,
    input: openArray[byte],
    max_fees_per_gas: BasicFeesPerGas,
    signature: Secp256k1ExecutionSignature,
    max_priority_fees_per_gas: BasicFeesPerGas = BasicFeesPerGas(regular: 0.u256),
    access_list: seq[AccessTuple] = @[],
    blob_versioned_hashes: seq[VersionedHash] = @[],
    blob_fee: FeePerGas = 0.u256,
  authorization_list: seq[AuthTuple] = @[],
): Transaction =
  let auths = makeAuthorizationList(authorization_list)
  case txType
  of TxLegacy:
    if to.isSome:
      if chain_id == ChainId(0.u256):
        let p = RlpLegacyReplayableBasicTransactionPayload(
          txType: txType,
          nonce: nonce,
          max_fees_per_gas: max_fees_per_gas,
          gas: gas,
          to: to.get,
          value: value,
          input: @input,
        )
        return build(p, signature)
      else:
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
      if chain_id == ChainId(0.u256):
        let p = RlpLegacyReplayableCreateTransactionPayload(
          txType: txType,
          nonce: nonce,
          max_fees_per_gas: max_fees_per_gas,
          gas: gas,
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
  of TxAccessList:
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
  of TxDynamicFee:
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
  of TxBlob:
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
  of TxSetCode:
    let p = RlpSetCodeTransactionPayload(
      txType: TxSetCode,
      chain_id: chain_id,
      nonce: nonce,
      max_fees_per_gas: max_fees_per_gas,
      gas: gas,
      to: to.get,
      value: value,
      input: @input,
      access_list: access_list,
      max_priority_fees_per_gas: max_priority_fees_per_gas,
      authorization_list: auths,
    )
    return build(p, signature)
  else:
    fail("Unsupported txType (expected 0x00..0x04)")

