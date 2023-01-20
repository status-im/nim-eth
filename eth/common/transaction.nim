import
  ./eth_types_rlp

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
  if tx.txType != TxEip1559:
    (tx.gasPrice - baseFee.int64).GasPriceEx
  else:
    # London, EIP1559
    min(tx.maxPriorityFee, tx.maxFee - baseFee.int64).GasPriceEx

proc effectiveGasTip*(tx: Transaction; baseFee: UInt256): GasPriceEx =
  ## Variant of `effectiveGasTip()`
  tx.effectiveGasTip(baseFee.truncate(uint64).GasPrice)

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
  w.append(tx.maxPriorityFee)
  w.append(tx.maxFee)
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
  w.append(tx.maxPriorityFee)
  w.append(tx.maxFee)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.maxFeePerDataGas)
  w.append(tx.versionedHashes)
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

func txHashNoSignature*(tx: Transaction): Hash256 =
  # Hash transaction without signature
  keccakHash(rlpEncode(tx))
