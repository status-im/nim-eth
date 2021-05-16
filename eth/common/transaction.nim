import
  nimcrypto/keccak,
  ".."/[common, rlp, keys]

proc initLegacyTx*(nonce: AccountNonce, gasPrice, gasLimit: GasInt, to: EthAddress,
  value: UInt256, payload: Blob, V: int64, R, S: UInt256, isContractCreation = false): LegacyTx =
  result.nonce = nonce
  result.gasPrice = gasPrice
  result.gasLimit = gasLimit
  result.to = to
  result.value = value
  result.payload = payload
  result.V = V
  result.R = R
  result.S = S
  result.isContractCreation = isContractCreation

type
  LegacyUnsignedTx* = object
    nonce*:  AccountNonce
    gasPrice*:      GasInt
    gasLimit*:      GasInt
    to* {.rlpCustomSerialization.}: EthAddress
    value*:         UInt256
    payload*:       Blob
    isContractCreation* {.rlpIgnore.}: bool

  AccessListUnsignedTx* = object
    chainId* {.rlpCustomSerialization.}: ChainId
    nonce*     : AccountNonce
    gasPrice*  : GasInt
    gasLimit*  : GasInt
    to* {.rlpCustomSerialization.}: EthAddress
    value*     : UInt256
    payload*   : Blob
    accessList*: AccessList
    isContractCreation* {.rlpIgnore.}: bool

  UnsignedTxTypes* = LegacyUnsignedTx | AccessListUnsignedTx

proc read*(rlp: var Rlp, t: var UnsignedTxTypes, _: type EthAddress): EthAddress {.inline.} =
  if rlp.blobLen != 0:
    result = rlp.read(EthAddress)
  else:
    t.isContractCreation = true

proc append*(rlpWriter: var RlpWriter, t: UnsignedTxTypes, a: EthAddress) {.inline.} =
  if t.isContractCreation:
    rlpWriter.append("")
  else:
    rlpWriter.append(a)

proc read*(rlp: var Rlp, t: var AccessListUnsignedTx, _: type ChainId): ChainId  {.inline.} =
  rlp.read(uint64).ChainId

proc append*(rlpWriter: var RlpWriter, t: AccessListUnsignedTx, a: ChainId) {.inline.} =
  rlpWriter.append(a.uint64)

const
  EIP155_CHAIN_ID_OFFSET* = 35'i64

func rlpEncode*(tx: LegacyTx): auto =
  # Encode transaction without signature
  return rlp.encode(LegacyUnsignedTx(
    nonce: tx.nonce,
    gasPrice: tx.gasPrice,
    gasLimit: tx.gasLimit,
    to: tx.to,
    value: tx.value,
    payload: tx.payload,
    isContractCreation: tx.isContractCreation
    ))

func rlpEncodeEIP155*(tx: LegacyTx): auto =
  let V = (tx.V - EIP155_CHAIN_ID_OFFSET) div 2
  # Encode transaction without signature
  return rlp.encode(LegacyTx(
    nonce: tx.nonce,
    gasPrice: tx.gasPrice,
    gasLimit: tx.gasLimit,
    to: tx.to,
    value: tx.value,
    payload: tx.payload,
    isContractCreation: tx.isContractCreation,
    V: V,
    R: 0.u256,
    S: 0.u256
    ))

func rlpEncode*(tx: AccessListTx): auto =
  # EIP 2718/2930
  let unsignedTx = AccessListUnsignedTx(
    chainId: tx.chainId,
    nonce: tx.nonce,
    gasPrice: tx.gasPrice,
    gasLimit: tx.gasLimit,
    to: tx.to,
    value: tx.value,
    payload: tx.payload,
    accessList: tx.accessList,
    isContractCreation: tx.isContractCreation
    )
  var rw = initRlpWriter()
  rw.append(1)
  rw.append(unsignedTx)
  rw.finish()

func txHashNoSignature*(tx: LegacyTx): Hash256 =
  # Hash transaction without signature
  keccak256.digest(if tx.V >= EIP155_CHAIN_ID_OFFSET: tx.rlpEncodeEIP155 else: tx.rlpEncode)

func txHashNoSignature*(tx: AccessListTx): Hash256 =
  keccak256.digest(tx.rlpEncode)

func txHashNoSignature*(tx: Transaction): Hash256 =
  if tx.txType == LegacyTxType:
    txHashNoSignature(tx.legacyTx)
  else:
    txHashNoSignature(tx.accessListTx)
