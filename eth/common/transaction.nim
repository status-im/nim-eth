import
  eth/[common, rlp, keys], nimcrypto/keccak

proc initTransaction*(nonce: AccountNonce, gasPrice, gasLimit: GasInt, to: EthAddress,
  value: UInt256, payload: Blob, V: byte, R, S: UInt256, isContractCreation = false): Transaction =
  result.accountNonce = nonce
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
  TransHashObj = object
    accountNonce:  AccountNonce
    gasPrice:      GasInt
    gasLimit:      GasInt
    to {.rlpCustomSerialization.}: EthAddress
    value:         UInt256
    payload:       Blob
    mIsContractCreation {.rlpIgnore.}: bool

proc read(rlp: var Rlp, t: var TransHashObj, _: type EthAddress): EthAddress {.inline.} =
  if rlp.blobLen != 0:
    result = rlp.read(EthAddress)
  else:
    t.mIsContractCreation = true

proc append(rlpWriter: var RlpWriter, t: TransHashObj, a: EthAddress) {.inline.} =
  if t.mIsContractCreation:
    rlpWriter.append("")
  else:
    rlpWriter.append(a)

const
  EIP155_CHAIN_ID_OFFSET* = 35

func rlpEncode*(transaction: Transaction): auto =
  # Encode transaction without signature
  return rlp.encode(TransHashObj(
    accountNonce: transaction.accountNonce,
    gasPrice: transaction.gasPrice,
    gasLimit: transaction.gasLimit,
    to: transaction.to,
    value: transaction.value,
    payload: transaction.payload,
    mIsContractCreation: transaction.isContractCreation
    ))

func rlpEncodeEIP155*(tx: Transaction): auto =
  let V = (tx.V.int - EIP155_CHAIN_ID_OFFSET) div 2
  # Encode transaction without signature
  return rlp.encode(Transaction(
    accountNonce: tx.accountNonce,
    gasPrice: tx.gasPrice,
    gasLimit: tx.gasLimit,
    to: tx.to,
    value: tx.value,
    payload: tx.payload,
    isContractCreation: tx.isContractCreation,
    V: V.byte,
    R: 0.u256,
    S: 0.u256
    ))

func txHashNoSignature*(tx: Transaction): Hash256 =
  # Hash transaction without signature
  return keccak256.digest(if tx.V.int >= EIP155_CHAIN_ID_OFFSET: tx.rlpEncodeEIP155 else: tx.rlpEncode)
