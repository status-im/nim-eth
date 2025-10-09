import
  std/[sequtils],
  stint,
  ./signatures,
  ./transaction_ssz as ssz_tx,
  ./transaction_builder,
  ../common/[addresses_rlp, base_rlp],
  ../common/transactions as rlp_tx_mod

# Gas -> FeePerGas
proc feeFromGas(x: rlp_tx_mod.GasInt): ssz_tx.FeePerGas =
  when compiles(x.u256):
    x.u256
  else:
    UInt256.fromInt(int(x))

proc toGasInt(x: ssz_tx.FeePerGas): rlp_tx_mod.GasInt =
  if x > u256(high(uint64)):
    raise newException(ValueError, "FeePerGas too large to fit into GasInt")
  # TODO:verify with etan+advaita(advaita say sanity check one is ok)
  rlp_tx_mod.GasInt(x.limbs[0])

proc accessTupleFrom(pair: rlp_tx_mod.AccessPair): ssz_tx.AccessTuple =
  # Old storageKeys: seq[Bytes32]; new  seq[Hash32]
  result.address = pair.address
  result.storage_keys = newSeq[Hash32](pair.storageKeys.len)
  for i, k in pair.storageKeys:
    result.storage_keys[i] = cast[Hash32](k)

proc accessListFrom(al: rlp_tx_mod.AccessList): seq[ssz_tx.AccessTuple] =
  al.map(accessTupleFrom)

proc toAuthTuples*(al: seq[rlp_tx_mod.Authorization]): seq[ssz_tx.AuthTuple] =
  ## Convert RLP-style authorizations -> AuthTuple expected by builder
  result = newSeq[ssz_tx.AuthTuple](al.len)
  for i, a in al:
    result[i] = (
      chain_id: a.chainId,
      address: a.address,
      nonce: uint64(a.nonce),
      y_parity: a.yParity,
      r: a.r,
      s: a.s
    )

proc toSszSignedAuthList*(al: seq[rlp_tx_mod.Authorization]):
    seq[ssz_tx.Authorization] =
  result = newSeq[ssz_tx.Authorization](al.len)
  for i, a in al:
    let payload =
      if a.chainId == ChainId(0.u256):
        ssz_tx.AuthorizationPayload(
          kind: ssz_tx.authReplayableBasic,
          replayable: ssz_tx.RlpReplayableBasicAuthorizationPayload(
            magic: ssz_tx.AuthMagic7702,
            address: a.address,
            nonce: uint64(a.nonce),
          )
        )
      else:
        ssz_tx.AuthorizationPayload(
          kind: ssz_tx.authBasic,
          basic: ssz_tx.RlpBasicAuthorizationPayload(
            magic: ssz_tx.AuthMagic7702,
            chain_id: a.chainId,
            address: a.address,
            nonce: uint64(a.nonce),
          )
        )

    let sig = secp256k1Pack(a.r, a.s, a.yParity)
    result[i] = ssz_tx.Authorization(
      payload: payload,
      signature: sig
    )

proc toSszAuthList*(al: seq[rlp_tx_mod.Authorization]):
    seq[ssz_tx.Authorization] =
  toSszSignedAuthList(al)

proc toRlpAuthList*(al: seq[ssz_tx.Authorization]): seq[rlp_tx_mod.Authorization] =
  result = newSeq[rlp_tx_mod.Authorization](al.len)
  for i, a in al:
    let (R, S, parity) = secp256k1Unpack(a.signature)
    case a.payload.kind
    of ssz_tx.authReplayableBasic:
      let p = a.payload.replayable
      result[i] = rlp_tx_mod.Authorization(
        chainId: ChainId(0.u256),
        address: p.address,
        nonce: AccountNonce(p.nonce),
        yParity: parity,
        r: R,
        s: S
      )
    of ssz_tx.authBasic:
      let p = a.payload.basic
      result[i] = rlp_tx_mod.Authorization(
        chainId: p.chain_id,
        address: p.address,
        nonce: AccountNonce(p.nonce),
        yParity: parity,
        r: R,
        s: S
      )


proc packSigFromTx(tx: rlp_tx_mod.Transaction): Secp256k1ExecutionSignature =
  let y: uint8 =
    case tx.txType
    of rlp_tx_mod.TxLegacy:
      yParityFromLegacyV(uint64(tx.V), tx.isEip155)
    else:
      uint8(uint64(tx.V) and 1'u64)
  secp256k1Pack(tx.R, tx.S, y)

proc toSszTx*(tx: rlp_tx_mod.Transaction): ssz_tx.Transaction =
  let sig = packSigFromTx(tx)
  let legacyChain: ChainId =
    if tx.isEip155:
      tx.chainId
    else:
      ChainId(0.u256)
  let accessSSZ = accessListFrom(tx.accessList)

  case tx.txType
  of rlp_tx_mod.TxLegacy:
    return transaction_builder.Transaction(
      txType = ssz_tx.TxLegacy,
      chain_id = legacyChain,
      nonce = tx.nonce,
      gas = tx.gasLimit,
      to = tx.to,
      value = tx.value,
      input = tx.payload,
      max_fees_per_gas = ssz_tx.BasicFeesPerGas(regular: feeFromGas(tx.gasPrice)),
      signature = sig,
    )
  of rlp_tx_mod.TxEip2930:
    return transaction_builder.Transaction(
      txType = ssz_tx.TxAccessList,
      chain_id = tx.chainId,
      nonce = tx.nonce,
      gas = tx.gasLimit,
      to = tx.to,
      value = tx.value,
      input = tx.payload,
      max_fees_per_gas = ssz_tx.BasicFeesPerGas(regular: feeFromGas(tx.gasPrice)),
      signature = sig,
      access_list = accessSSZ,
    )
  of rlp_tx_mod.TxEip1559:
    return transaction_builder.Transaction(
      txType = ssz_tx.TxDynamicFee,
      chain_id = tx.chainId,
      nonce = tx.nonce,
      gas = tx.gasLimit,
      to = tx.to,
      value = tx.value,
      input = tx.payload,
      max_fees_per_gas = ssz_tx.BasicFeesPerGas(regular: feeFromGas(tx.maxFeePerGas)),
      max_priority_fees_per_gas =
        ssz_tx.BasicFeesPerGas(regular: feeFromGas(tx.maxPriorityFeePerGas)),
      signature = sig,
      access_list = accessSSZ,
    )
  of rlp_tx_mod.TxEip4844:
    return transaction_builder.Transaction(
      txType = ssz_tx.TxBlob,
      chain_id = tx.chainId,
      nonce = tx.nonce,
      gas = tx.gasLimit,
      to = tx.to,
      value = tx.value,
      input = tx.payload,
      max_fees_per_gas = ssz_tx.BasicFeesPerGas(regular: feeFromGas(tx.maxFeePerGas)),
      max_priority_fees_per_gas =
        ssz_tx.BasicFeesPerGas(regular: feeFromGas(tx.maxPriorityFeePerGas)),
      signature = sig,
      access_list = accessSSZ,
      blob_versioned_hashes = tx.versionedHashes,
      blob_fee = tx.maxFeePerBlobGas,
    )
  of rlp_tx_mod.TxEip7702:
    if tx.to.isNone:
      raise newException(ValueError, "7702 setCode: requires 'to'")
    return transaction_builder.Transaction(
      txType = ssz_tx.TxSetCode,
      chain_id = tx.chainId,
      nonce = tx.nonce,
      gas = tx.gasLimit,
      to = tx.to,
      value = tx.value,
      input = tx.payload,
      max_fees_per_gas = ssz_tx.BasicFeesPerGas(regular: feeFromGas(tx.maxFeePerGas)),
      max_priority_fees_per_gas =
        ssz_tx.BasicFeesPerGas(regular: feeFromGas(tx.maxPriorityFeePerGas)),
      signature = sig,
      access_list = accessSSZ,
      authorization_list = toAuthTuples(tx.authorizationList),
    )

proc toOldTx*(tx: ssz_tx.Transaction): rlp_tx_mod.Transaction =
  if tx.kind != RlpTransaction:
    raise newException(ValueError, "only RLP transaction variant supported")

  proc toOldAccessList(al: seq[ssz_tx.AccessTuple]): rlp_tx_mod.AccessList =
    result = @[]
    for t in al:
      result.add rlp_tx_mod.AccessPair(
        address: t.address, storageKeys: t.storage_keys.mapIt(cast[Bytes32](it))
      )

  let r = tx.rlp

  case r.kind
  of txLegacyReplayableBasic:
    let p = r.legacyReplayableBasic.payload
    let sig = r.legacyReplayableBasic.signature
    let (R, S, y) = secp256k1Unpack (sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxLegacy,
      chainId: ChainId(0.u256),
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.some(p.to),
      value: p.value,
      payload: p.input,
      gasPrice: toGasInt(p.max_fees_per_gas.regular),
      V: 27'u64 + uint64(y),
      R: R,
      S: S,
    )
  of txLegacyReplayableCreate:
    let p = r.legacyReplayableCreate.payload
    let sig = r.legacyReplayableCreate.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxLegacy,
      chainId: ChainId(0.u256),
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.none(Address),
      value: p.value,
      payload: p.input,
      gasPrice: toGasInt(p.max_fees_per_gas.regular),
      V: 27'u64 + uint64(y),
      R: R,
      S: S,
    )
  of txLegacyBasic:
    let p = r.legacyBasic.payload
    let sig = r.legacyBasic.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxLegacy,
      chainId: p.chain_id,
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.some(p.to),
      value: p.value,
      payload: p.input,
      gasPrice: toGasInt(p.max_fees_per_gas.regular),
      V: rlp_tx_mod.EIP155_CHAIN_ID_OFFSET + ((2 * p.chain_id).limbs[0]) + uint64(y),
      R: R,
      S: S,
    )
  of txLegacyCreate:
    let p = r.legacyCreate.payload
    let sig = r.legacyCreate.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxLegacy,
      chainId: p.chain_id,
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.none(Address),
      value: p.value,
      payload: p.input,
      gasPrice: toGasInt(p.max_fees_per_gas.regular),
      V: rlp_tx_mod.EIP155_CHAIN_ID_OFFSET + ((2 * p.chain_id).limbs[0]) + uint64(y),
      R: R,
      S: S,
    )
  of txAccessListBasic:
    let p = r.accessListBasic.payload
    let sig = r.accessListBasic.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxEip2930,
      chainId: p.chain_id,
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.some(p.to),
      value: p.value,
      payload: p.input,
      gasPrice: toGasInt(p.max_fees_per_gas.regular),
      accessList: toOldAccessList(p.access_list),
      V: uint64(y),
      R: R,
      S: S,
    )
  of txAccessListCreate:
    let p = r.accessListCreate.payload
    let sig = r.accessListCreate.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxEip2930,
      chainId: p.chain_id,
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.none(Address),
      value: p.value,
      payload: p.input,
      gasPrice: toGasInt(p.max_fees_per_gas.regular),
      accessList: toOldAccessList(p.access_list),
      V: uint64(y),
      R: R,
      S: S,
    )
  of txBasic:
    let p = r.basic.payload
    let sig = r.basic.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxEip1559,
      chainId: p.chain_id,
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.some(p.to),
      value: p.value,
      payload: p.input,
      maxPriorityFeePerGas: toGasInt(p.max_priority_fees_per_gas.regular),
      maxFeePerGas: toGasInt(p.max_fees_per_gas.regular),
      accessList: toOldAccessList(p.access_list),
      V: uint64(y),
      R: R,
      S: S,
    )
  of txCreate:
    let p = r.create.payload
    let sig = r.create.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxEip1559,
      chainId: p.chain_id,
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.none(Address),
      value: p.value,
      payload: p.input,
      maxPriorityFeePerGas: toGasInt(p.max_priority_fees_per_gas.regular),
      maxFeePerGas: toGasInt(p.max_fees_per_gas.regular),
      accessList: toOldAccessList(p.access_list),
      V: uint64(y),
      R: R,
      S: S,
    )
  of txBlob:
    let p = r.blob.payload
    let sig = r.blob.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxEip4844,
      chainId: p.chain_id,
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.some(p.to),
      value: p.value,
      payload: p.input,
      maxPriorityFeePerGas: toGasInt(p.max_priority_fees_per_gas.regular),
      maxFeePerGas: toGasInt(p.max_fees_per_gas.regular),
        # BlobFeesPerGas → BasicFeesPerGas.regular
      maxFeePerBlobGas: p.max_fees_per_gas.blob,
      versionedHashes: p.blob_versioned_hashes,
      accessList: toOldAccessList(p.access_list),
      V: uint64(y),
      R: R,
      S: S,
    )
  of txSetCode:
    let p = r.setCode.payload
    let sig = r.setCode.signature
    let (R, S, y) = secp256k1Unpack(sig)
    result = rlp_tx_mod.Transaction(
      txType: rlp_tx_mod.TxEip7702,
      chainId: p.chain_id,
      nonce: p.nonce,
      gasLimit: p.gas,
      to: Opt.some(p.to),
      value: p.value,
      payload: p.input,
      maxPriorityFeePerGas: toGasInt(p.max_priority_fees_per_gas.regular),
      maxFeePerGas: toGasInt(p.max_fees_per_gas.regular),
      accessList: toOldAccessList(p.access_list),
      authorizationList: toRlpAuthList(p.authorization_list),
      V: uint64(y),
      R: R,
      S: S,
    )
