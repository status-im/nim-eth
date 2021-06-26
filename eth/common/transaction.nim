import
  nimcrypto/keccak,
  ".."/[common, rlp, keys]

const
  EIP155_CHAIN_ID_OFFSET* = 35'i64

func rlpEncodeLegacy(tx: Transaction): auto =
  var w = initRlpWriter()
  w.startList(6)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.finish()

func rlpEncodeEip155(tx: Transaction): auto =
  let chainId = (tx.V - EIP155_CHAIN_ID_OFFSET) div 2
  var w = initRlpWriter()
  w.startList(9)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(chainId)
  w.append(0)
  w.append(0)
  w.finish()

func rlpEncodeEip2930(tx: Transaction): auto =
  var w = initRlpWriter()
  w.append(1)
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

func rlpEncodeEip1559(tx: Transaction): auto =
  var w = initRlpWriter()
  w.append(2)
  w.startList(9)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.maxPriorityFee)
  w.append(tx.maxFee)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.finish()

func rlpEncode*(tx: Transaction): auto =
  case tx.txType
  of TxLegacy:
    if tx.V >= EIP155_CHAIN_ID_OFFSET:
      tx.rlpEncodeEIP155
    else:
      tx.rlpEncodeLegacy
  of TxEip2930:
    tx.rlpEncodeEip2930
  of TxEip1559:
    tx.rlpEncodeEip1559

func txHashNoSignature*(tx: Transaction): Hash256 =
  # Hash transaction without signature
  keccak256.digest(rlpEncode(tx))
