import
  ./eth_types_rlp

export eth_types_rlp

const
  EIP155_CHAIN_ID_OFFSET* = 35'u64

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
  w.append(0'u8)
  w.append(0'u8)
  w.finish()

func rlpEncodeEip2930(tx: Transaction): auto =
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

func rlpEncodeEip1559(tx: Transaction): auto =
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

func rlpEncodeEip4844(tx: Transaction): auto =
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

func rlpEncodeEip7702(tx: Transaction): auto =
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

func rlpEncode*(tx: Transaction): auto =
  case tx.txType
  of TxLegacy:
    if tx.V >= EIP155_CHAIN_ID_OFFSET:
      tx.rlpEncodeEip155
    else:
      tx.rlpEncodeLegacy
  of TxEip2930:
    tx.rlpEncodeEip2930
  of TxEip1559:
    tx.rlpEncodeEip1559
  of TxEip4844:
    tx.rlpEncodeEip4844
  of TxEip7702:
    tx.rlpEncodeEip7702

func txHashNoSignature*(tx: Transaction): Hash256 =
  # Hash transaction without signature
  keccakHash(rlpEncode(tx))
