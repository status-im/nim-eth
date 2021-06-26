import
  std/[strutils, options, times],
  stew/[endians2, byteutils], chronicles, stint, nimcrypto/[keccak, hash],
  ../rlp, ../trie/[trie_defs, db]

export
  stint, read, append, KeccakHash, rlp, options

type
  Hash256* = MDigest[256]
  EthTime* = Time
  VMWord* = UInt256
  BlockNonce* = array[8, byte]
  AccountNonce* = uint64
  Blob* = seq[byte]

  BloomFilter* = array[256, byte]
  EthAddress* = array[20, byte]

  WhisperIdentity* = array[60, byte]

  DifficultyInt* = UInt256
  GasInt* = int64
  ## Type alias used for gas computation
  # For reference - https://github.com/status-im/nimbus/issues/35#issuecomment-391726518

  Topic* = array[32, byte]
  # topic can be Hash256 or zero padded bytes array

  ForkID* = tuple[crc: uint32, nextFork: uint64]
  # EIP 2364/2124

  BlockNumber* = UInt256
  StorageKey* = array[32, byte]

  # beware that although in some cases
  # chainId have identical value to networkId
  # they are separate entity
  ChainId* = distinct uint64

  Account* = object
    nonce*:       AccountNonce
    balance*:     UInt256
    storageRoot*: Hash256
    codeHash*:    Hash256

  AccessPair* = object
    address*    : EthAddress
    storageKeys*: seq[StorageKey]

  AccessList* = seq[AccessPair]

  TxType* = enum
    TxLegacy
    TxEip2930
    TxEip1559

  Transaction* = object
    txType*        : TxType               # EIP-2718
    chainId*       : ChainId              # EIP-2930
    nonce*         : AccountNonce
    gasPrice*      : GasInt
    maxPriorityFee*: GasInt               # EIP-1559
    maxFee*        : GasInt               # EIP-1559
    gasLimit*      : GasInt
    to*            : Option[EthAddress]
    value*         : UInt256
    payload*       : Blob
    accessList*    : AccessList           # EIP-2930
    V*             : int64
    R*, S*         : UInt256

  TransactionStatus* = enum
    Unknown,
    Queued,
    Pending,
    Included,
    Error

  TransactionStatusMsg* = object
    status*: TransactionStatus
    data*: Blob

  BlockHeader* = object
    parentHash*:    Hash256
    ommersHash*:    Hash256
    coinbase*:      EthAddress
    stateRoot*:     Hash256
    txRoot*:        Hash256
    receiptRoot*:   Hash256
    bloom*:         BloomFilter
    difficulty*:    DifficultyInt
    blockNumber*:   BlockNumber
    gasLimit*:      GasInt
    gasUsed*:       GasInt
    timestamp*:     EthTime
    extraData*:     Blob
    mixDigest*:     Hash256
    nonce*:         BlockNonce
    # `baseFee` is the get/set of `fee`
    fee*:           Option[UInt256]   # EIP-1559

  BlockBody* = object
    transactions*{.rlpCustomSerialization.}: seq[Transaction]
    uncles*:        seq[BlockHeader]

  Log* = object
    address*:       EthAddress
    topics*:        seq[Topic]
    data*:          Blob

  # easily convertible between
  # ReceiptType and TxType
  ReceiptType* = TxType
    # LegacyReceipt  = TxLegacy
    # Eip2930Receipt = TxEip2930
    # Eip1559Receipt = TxEip1559

  Receipt* = object
    receiptType*      : ReceiptType
    isHash*           : bool          # hash or status
    status*           : bool          # EIP-658
    hash*             : Hash256
    cumulativeGasUsed*: GasInt
    bloom*            : BloomFilter
    logs*             : seq[Log]

  EthBlock* = object
    header*: BlockHeader
    txs* {.rlpCustomSerialization.}: seq[Transaction]
    uncles*: seq[BlockHeader]

  CollationHeader* = object
    shard*:         uint
    expectedPeriod*: uint
    periodStartPrevHash*: Hash256
    parentHash*:    Hash256
    txRoot*:        Hash256
    coinbase*:      EthAddress
    stateRoot*:     Hash256
    receiptRoot*:   Hash256
    blockNumber*:   BlockNumber

  # TODO: Make BlockNumber a uint64 and deprecate either this or BlockHashOrNumber
  HashOrNum* = object
    case isHash*: bool
    of true:
      hash*: Hash256
    else:
      number*: BlockNumber

  BlockHashOrNumber* = object
    case isHash*: bool
    of true:
      hash*: Hash256
    else:
      number*: uint64

  BlocksRequest* = object
    startBlock*: HashOrNum
    maxResults*, skip*: uint
    reverse*: bool

  ProofRequest* = object
    blockHash*: KeccakHash
    accountKey*: Blob
    key*: Blob
    fromLevel*: uint

  HeaderProofRequest* = object
    chtNumber*: uint
    blockNumber*: uint
    fromLevel*: uint

  ContractCodeRequest* = object
    blockHash*: KeccakHash
    key*: EthAddress

  HelperTrieProofRequest* = object
    subType*: uint
    sectionIdx*: uint
    key*: Blob
    fromLevel*: uint
    auxReq*: uint

  AbstractChainDB* = ref object of RootRef

  BlockHeaderRef* = ref BlockHeader
  BlockBodyRef* = ref BlockBody
  ReceiptRef* = ref Receipt

  EthResourceRefs = BlockHeaderRef | BlockBodyRef | ReceiptRef

  ValidationResult* {.pure.} = enum
    OK
    Error

const
  LegacyReceipt*  = TxLegacy
  Eip2930Receipt* = TxEip2930
  Eip1559Receipt* = TxEip1559

when BlockNumber is int64:
  ## The goal of these templates is to make it easier to switch
  ## the block number type to a different representation
  template vmWordToBlockNumber*(word: VMWord): BlockNumber =
    BlockNumber(word.toInt)

  template blockNumberToVmWord*(n: BlockNumber): VMWord =
    u256(n)

  template toBlockNumber*(n: SomeInteger): BlockNumber =
    int64(n)

  template toBlockNumber*(n: UInt256): BlockNumber =
    n.toInt

  template toInt*(n: BlockNumber): int =
    int(n)

else:
  template vmWordToBlockNumber*(word: VMWord): BlockNumber =
    word

  template blockNumberToVmWord*(n: BlockNumber): VMWord =
    n

  template toBlockNumber*(n: SomeInteger): BlockNumber =
    u256(n)

  template toBlockNumber*(n: UInt256): BlockNumber =
    n

  template u256*(n: BlockNumber): UInt256 =
    n

# EIP-1559 conveniences
func baseFee*(h: BlockHeader | BlockHeaderRef): UInt256 =
  if h.fee.isSome:
    h.fee.get()
  else:
    0.u256

template `baseFee=`*(h: BlockHeader | BlockHeaderRef, data: UInt256) =
  h.fee = some(data)

func toBlockNonce*(n: uint64): BlockNonce =
  n.toBytesBE()

func toUint*(n: BlockNonce): uint64 =
  uint64.fromBytesBE(n)

proc newAccount*(nonce: AccountNonce = 0, balance: UInt256 = 0.u256): Account =
  result.nonce = nonce
  result.balance = balance
  result.storageRoot = emptyRlpHash
  result.codeHash = blankStringHash

proc hasStatus*(rec: Receipt): bool {.inline.} =
  rec.isHash == false

proc hasStateRoot*(rec: Receipt): bool {.inline.} =
  rec.isHash == true

proc stateRoot*(rec: Receipt): Hash256 {.inline.} =
  doAssert(rec.hasStateRoot)
  rec.hash

template contractCreation*(tx: Transaction): bool =
  tx.to.isNone

func destination*(tx: Transaction): EthAddress =
  # use getRecipient if you also want to get
  # the contract address
  if tx.to.isSome:
    return tx.to.get

#
# Rlp serialization:
#

proc read*(rlp: var Rlp, T: type StUint): T {.inline.} =
  if rlp.isBlob:
    let bytes = rlp.toBytes
    if bytes.len > 0:
      # be sure the amount of bytes matches the size of the stint
      if bytes.len <= sizeof(result):
        result.initFromBytesBE(bytes)
      else:
        raise newException(RlpTypeMismatch, "Unsigned integer expected, but the source RLP has the wrong length")
    else:
      result = 0.to(T)
  else:
    raise newException(RlpTypeMismatch, "Unsigned integer expected, but the source RLP is a list")

  rlp.skipElem

proc append*(rlpWriter: var RlpWriter, value: StUint) =
  if value > 128:
    let bytes = value.toByteArrayBE
    let nonZeroBytes = significantBytesBE(bytes)
    rlpWriter.append bytes.toOpenArray(bytes.len - nonZeroBytes,
                                       bytes.len - 1)
  else:
    rlpWriter.append(value.truncate(int))

proc read*(rlp: var Rlp, T: type Stint): T {.inline.} =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.fatal: "RLP serialization of signed integers is not allowed".}
  discard

proc append*(rlpWriter: var RlpWriter, value: Stint) =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.fatal: "RLP serialization of signed integers is not allowed".}
  discard

proc append*[T](w: var RlpWriter, val: Option[T]) =
  if val.isSome:
    w.append(val.get())
  else:
    w.append("")

proc appendTxLegacy(w: var RlpWriter, tx: Transaction) =
  w.startList(9)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.V)
  w.append(tx.R)
  w.append(tx.S)

proc appendTxEip2930(w: var RlpWriter, tx: Transaction) =
  w.append(1)
  w.startList(11)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.gasPrice)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.V)
  w.append(tx.R)
  w.append(tx.S)

proc appendTxEip1559(w: var RlpWriter, tx: Transaction) =
  w.append(2)
  w.startList(12)
  w.append(tx.chainId.uint64)
  w.append(tx.nonce)
  w.append(tx.maxPriorityFee)
  w.append(tx.maxFee)
  w.append(tx.gasLimit)
  w.append(tx.to)
  w.append(tx.value)
  w.append(tx.payload)
  w.append(tx.accessList)
  w.append(tx.V)
  w.append(tx.R)
  w.append(tx.S)

proc append*(w: var RlpWriter, tx: Transaction) =
  case tx.txType
  of TxLegacy:
    w.appendTxLegacy(tx)
  of TxEip2930:
    w.appendTxEip2930(tx)
  of TxEip1559:
    w.appendTxEip1559(tx)

template read[T](rlp: var Rlp, val: var T)=
  val = rlp.read(type val)

proc read[T](rlp: var Rlp, val: var Option[T])=
  if rlp.blobLen != 0:
    val = some(rlp.read(T))
  else:
    rlp.skipElem

proc readTxLegacy(rlp: var Rlp, tx: var Transaction)=
  tx.txType = TxLegacy
  rlp.tryEnterList()
  rlp.read(tx.nonce)
  rlp.read(tx.gasPrice)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxEip2930(rlp: var Rlp, tx: var Transaction)=
  tx.txType = TxEip2930
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.gasPrice)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.accessList)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc readTxEip1559(rlp: var Rlp, tx: var Transaction)=
  tx.txType = TxEip1559
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.maxPriorityFee)
  rlp.read(tx.maxFee)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.accessList)
  rlp.read(tx.V)
  rlp.read(tx.R)
  rlp.read(tx.S)

proc read*(rlp: var Rlp, T: type Transaction): T =
  if rlp.isList:
    rlp.readTxLegacy(result)
    return

  # EIP 2718
  let txType = rlp.read(int)
  if txType notin {1, 2}:
    raise newException(UnsupportedRlpError,
      "TxType expect 1 or 2 got " & $txType)

  if TxType(txType) == TxEip2930:
    rlp.readTxEip2930(result)
  else:
    rlp.readTxEip1559(result)

proc read*(rlp: var Rlp, t: var (EthBlock | BlockBody), _: type seq[Transaction]): seq[Transaction] {.inline.} =
  # EIP 2718/2930: we have to override this field
  # for reasons described below in `append` proc
  if not rlp.isList:
    raise newException(MalformedRlpError,
      "List expected, but got blob.")
  for tx in rlp:
    if tx.isList:
      result.add tx.read(Transaction)
    else:
      let bytes = rlp.read(Blob)
      var rr = rlpFromBytes(bytes)
      result.add rr.read(Transaction)

proc append*(rlpWriter: var RlpWriter, blk: EthBlock | BlockBody, txs: seq[Transaction]) {.inline.} =
  # EIP 2718/2930: the new Tx is rlp(txType || txPlayload) -> one blob/one list elem
  # not rlp(txType, txPayload) -> two list elem, wrong!
  rlpWriter.startList(txs.len)
  for tx in txs:
    if tx.txType == TxLegacy:
      rlpWriter.append(tx)
    else:
      rlpWriter.append(rlp.encode(tx))

func init*(T: type BlockHashOrNumber, str: string): T
          {.raises: [ValueError, Defect].} =
  if str.startsWith "0x":
    if str.len != sizeof(result.hash.data) * 2 + 2:
      raise newException(ValueError, "Block hash has incorrect length")

    result.isHash = true
    hexToByteArray(str, result.hash.data)
  else:
    result.isHash = false
    result.number = parseBiggestUInt str

func `$`*(x: BlockHashOrNumber): string =
  if x.isHash:
    "0x" & x.hash.data.toHex
  else:
    $x.number

proc append*(w: var RlpWriter, rec: Receipt) =
  if rec.receiptType in {Eip2930Receipt, Eip1559Receipt}:
    w.append(rec.receiptType.int)

  w.startList(4)
  if rec.isHash:
    w.append(rec.hash)
  else:
    w.append(rec.status.uint8)

  w.append(rec.cumulativeGasUsed)
  w.append(rec.bloom)
  w.append(rec.logs)

proc read*(rlp: var Rlp, T: type Receipt): T =
  if rlp.isList:
    result.receiptType = LegacyReceipt
  else:
    # EIP 2718
    let recType = rlp.read(int)
    if recType notin {1, 2}:
      raise newException(UnsupportedRlpError,
        "TxType expect 1 or 2 got " & $recType)
    result.receiptType = ReceiptType(recType)

  rlp.tryEnterList()
  if rlp.isBlob and rlp.blobLen in {0, 1}:
    result.isHash = false
    result.status = rlp.read(uint8) == 1
  elif rlp.isBlob and rlp.blobLen == 32:
    result.isHash = true
    result.hash   = rlp.read(Hash256)
  else:
    raise newException(RlpTypeMismatch,
      "HashOrStatus expected, but the source RLP is not a blob of right size.")

  rlp.read(result.cumulativeGasUsed)
  rlp.read(result.bloom)
  rlp.read(result.logs)

proc read*(rlp: var Rlp, T: type Time): T {.inline.} =
  result = fromUnix(rlp.read(int64))

proc append*(rlpWriter: var RlpWriter, value: HashOrNum) =
  case value.isHash
  of true:
    rlpWriter.append(value.hash)
  else:
    rlpWriter.append(value.number)

proc read*(rlp: var Rlp, T: type HashOrNum): T =
  if rlp.blobLen == 32:
    result = HashOrNum(isHash: true, hash: rlp.read(Hash256))
  else:
    result = HashOrNum(isHash: false, number: rlp.read(BlockNumber))

proc append*(rlpWriter: var RlpWriter, t: Time) {.inline.} =
  rlpWriter.append(t.toUnix())

proc append*(w: var RlpWriter, h: BlockHeader) =
  w.startList(if h.fee.isSome: 16 else: 15)
  for k, v in fieldPairs(h):
    when k != "fee":
      w.append(v)
  if h.fee.isSome:
    w.append(h.fee.get())

proc read*(rlp: var Rlp, T: type BlockHeader): T =
  let len = rlp.listLen

  if len notin {15, 16}:
    raise newException(UnsupportedRlpError,
      "BlockHeader elems should be 15 or 16 got " & $len)

  rlp.tryEnterList()
  for k, v in fieldPairs(result):
    when k != "fee":
      v = rlp.read(type v)

  if len == 16:
    # EIP-1559
    result.baseFee = rlp.read(UInt256)

proc rlpHash*[T](v: T): Hash256 =
  keccak256.digest(rlp.encode(v))

func blockHash*(h: BlockHeader): KeccakHash {.inline.} = rlpHash(h)

proc notImplemented =
  debug "Method not implemented"

template hasData*(b: Blob): bool = b.len > 0
template hasData*(r: EthResourceRefs): bool = r != nil

template deref*(b: Blob): auto = b
template deref*(o: Option): auto = o.get
template deref*(r: EthResourceRefs): auto = r[]

method genesisHash*(db: AbstractChainDB): KeccakHash
    {.base, gcsafe, raises: [Defect].} =
  notImplemented()

method getBlockHeader*(db: AbstractChainDB, b: HashOrNum,
    output: var BlockHeader): bool {.base, gcsafe, raises: [RlpError, Defect].} =
  notImplemented()

proc getBlockHeader*(db: AbstractChainDB, hash: KeccakHash): BlockHeaderRef {.gcsafe.} =
  new result
  if not db.getBlockHeader(HashOrNum(isHash: true, hash: hash), result[]):
    return nil

proc getBlockHeader*(db: AbstractChainDB, b: BlockNumber): BlockHeaderRef {.gcsafe.} =
  new result
  if not db.getBlockHeader(HashOrNum(isHash: false, number: b), result[]):
    return nil

# Need to add `RlpError` and sometimes `CatchableError` as the implementations
# of these methods in nimbus-eth1 will raise these. Using `CatchableError`
# because some can raise for errors not know to this repository such as
# `CanonicalHeadNotFound`. It would probably be better to use Result.
method getBestBlockHeader*(self: AbstractChainDB): BlockHeader
    {.base, gcsafe, raises: [RlpError, CatchableError, Defect].} =
  notImplemented()

method getSuccessorHeader*(db: AbstractChainDB, h: BlockHeader,
    output: var BlockHeader, skip = 0'u): bool
    {.base, gcsafe, raises: [RlpError, Defect].} =
  notImplemented()

method getAncestorHeader*(db: AbstractChainDB, h: BlockHeader,
    output: var BlockHeader, skip = 0'u): bool
    {.base, gcsafe, raises: [RlpError, Defect].} =
  notImplemented()

method getBlockBody*(db: AbstractChainDB, blockHash: KeccakHash): BlockBodyRef
    {.base, gcsafe, raises: [Defect].} =
  notImplemented()

method getReceipt*(db: AbstractChainDB, hash: KeccakHash): ReceiptRef {.base, gcsafe.} =
  notImplemented()

method getTrieDB*(db: AbstractChainDB): TrieDatabaseRef
    {.base, gcsafe, raises: [Defect].} =
  notImplemented()

method getCodeByHash*(db: AbstractChainDB, hash: KeccakHash): Blob {.base, gcsafe.} =
  notImplemented()

method getSetting*(db: AbstractChainDB, key: string): seq[byte] {.base, gcsafe.} =
  notImplemented()

method setSetting*(db: AbstractChainDB, key: string, val: openarray[byte]) {.base, gcsafe.} =
  notImplemented()

method getHeaderProof*(db: AbstractChainDB, req: ProofRequest): Blob {.base, gcsafe.} =
  notImplemented()

method getProof*(db: AbstractChainDB, req: ProofRequest): Blob {.base, gcsafe.} =
  notImplemented()

method getHelperTrieProof*(db: AbstractChainDB, req: HelperTrieProofRequest): Blob {.base, gcsafe.} =
  notImplemented()

method getTransactionStatus*(db: AbstractChainDB, txHash: KeccakHash): TransactionStatusMsg {.base, gcsafe.} =
  notImplemented()

method addTransactions*(db: AbstractChainDB, transactions: openarray[Transaction]) {.base, gcsafe.} =
  notImplemented()

method persistBlocks*(db: AbstractChainDB, headers: openarray[BlockHeader], bodies: openarray[BlockBody]): ValidationResult {.base, gcsafe.} =
  notImplemented()

method getForkId*(db: AbstractChainDB, n: BlockNumber): ForkID {.base, gcsafe.} =
  # EIP 2364/2124
  notImplemented()
