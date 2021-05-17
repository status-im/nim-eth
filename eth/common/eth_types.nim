import
  std/[strutils, options, times],
  stew/[endians2, byteutils], chronicles, stint, nimcrypto/[keccak, hash],
  ../rlp, ../trie/[trie_defs, db]

export
  stint, read, append, KeccakHash, rlp

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
    nonce*:             AccountNonce
    balance*:           UInt256
    storageRoot*:       Hash256
    codeHash*:          Hash256

  LegacyTx* = object
    nonce*   : AccountNonce
    gasPrice*: GasInt
    gasLimit*: GasInt
    to* {.rlpCustomSerialization.}: EthAddress
    value*   : UInt256
    payload* : Blob
    V*       : int64
    R*, S*   : UInt256
    isContractCreation* {.rlpIgnore.}: bool

  AccessPair* = object
    address*    : EthAddress
    storageKeys*: seq[StorageKey]

  AccessList* = seq[AccessPair]

  AccessListTx* = object
    chainId* {.rlpCustomSerialization.}: ChainId
    nonce*     : AccountNonce
    gasPrice*  : GasInt
    gasLimit*  : GasInt
    to* {.rlpCustomSerialization.}: EthAddress
    value*     : UInt256
    payload*   : Blob
    accessList*: AccessList
    V*         : int64
    R*, S*     : UInt256
    isContractCreation* {.rlpIgnore.}: bool

  TxType* = enum
    LegacyTxType
    AccessListTxType

  Transaction* = object
    case txType*: TxType
    of LegacyTxType:
      legacyTx*: LegacyTx
    of AccessListTxType:
      accessListTx*: AccessListTx

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

  BlockBody* = object
    transactions*{.rlpCustomSerialization.}: seq[Transaction]
    uncles*:        seq[BlockHeader]

  Log* = object
    address*:       EthAddress
    topics*:        seq[Topic]
    data*:          Blob

  HashOrStatus* = object
    case isHash*: bool
    of true:
      hash*: Hash256
    else:
      status*: bool

  LegacyReceipt* = object
    stateRootOrStatus*: HashOrStatus
    cumulativeGasUsed*: GasInt
    bloom*: BloomFilter
    logs* : seq[Log]

  AccessListReceipt* = object
    status*: bool
    cumulativeGasUsed*: GasInt
    bloom* : BloomFilter
    logs*  : seq[Log]

  ReceiptType* = enum
    LegacyReceiptType
    AccessListReceiptType

  Receipt* = object
    case receiptType*: ReceiptType
    of LegacyReceiptType:
      legacyReceipt*: LegacyReceipt
    of AccessListReceiptType:
      accessListReceipt*: AccessListReceipt

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

func toBlockNonce*(n: uint64): BlockNonce =
  n.toBytesBE()

func toUint*(n: BlockNonce): uint64 =
  uint64.fromBytesBE(n)

proc newAccount*(nonce: AccountNonce = 0, balance: UInt256 = 0.u256): Account =
  result.nonce = nonce
  result.balance = balance
  result.storageRoot = emptyRlpHash
  result.codeHash = blankStringHash

proc hashOrStatus*(hash: Hash256): HashOrStatus =
  HashOrStatus(isHash: true, hash: hash)

proc hashOrStatus*(status: bool): HashOrStatus =
  HashOrStatus(isHash: false, status: status)

proc hasStatus*(rec: LegacyReceipt): bool {.inline.} =
  rec.stateRootOrStatus.isHash == false

proc hasStateRoot*(rec: LegacyReceipt): bool {.inline.} =
  rec.stateRootOrStatus.isHash == true

proc stateRoot*(rec: LegacyReceipt): Hash256 {.inline.} =
  doAssert(rec.hasStateRoot)
  rec.stateRootOrStatus.hash

proc status*(rec: LegacyReceipt): int {.inline.} =
  doAssert(rec.hasStatus)
  if rec.stateRootOrStatus.status: 1 else: 0

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

type
  TxTypes* = LegacyTx | AccessListTx

proc read*(rlp: var Rlp, t: var TxTypes, _: type EthAddress): EthAddress {.inline.} =
  if rlp.blobLen != 0:
    result = rlp.read(EthAddress)
  else:
    t.isContractCreation = true
    rlp.skipElem()

proc append*(rlpWriter: var RlpWriter, t: TxTypes, a: EthAddress) {.inline.} =
  if t.isContractCreation:
    rlpWriter.append("")
  else:
    rlpWriter.append(a)

proc read*(rlp: var Rlp, t: var AccessListTx, _: type ChainId): ChainId  {.inline.} =
  rlp.read(uint64).ChainId

proc append*(rlpWriter: var RlpWriter, t: AccessListTx, a: ChainId) {.inline.} =
  rlpWriter.append(a.uint64)

proc append*(rlpWriter: var RlpWriter, tx: Transaction) =
  if tx.txType == LegacyTxType:
    rlpWriter.append(tx.legacyTx)
  else:
    # EIP 2718/2930
    rlpWriter.append(1)
    rlpWriter.append(tx.accessListTx)

proc read*(rlp: var Rlp, T: type Transaction): T =
  if rlp.isList:
    return Transaction(
      txType: LegacyTxType,
      legacyTx: rlp.read(LegacyTx)
    )

  # EIP 2718/2930
  let txType = rlp.read(int)
  if txType != 1:
    raise newException(UnsupportedRlpError,
      "TxType expect 1 got " & $txType)
  return Transaction(
    txType: AccessListTxType,
    accessListTx: rlp.read(AccessListTx)
  )

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
    if tx.txType == LegacyTxType:
      rlpWriter.append(tx)
    else:
      rlpWriter.append(rlp.encode(tx))

proc read*(rlp: var Rlp, T: type HashOrStatus): T {.inline.} =
  if rlp.isBlob() and (rlp.blobLen() == 32 or rlp.blobLen() == 1):
    if rlp.blobLen == 1:
      result = hashOrStatus(rlp.read(uint8) == 1)
    else:
      result = hashOrStatus(rlp.read(Hash256))
  else:
    raise newException(RlpTypeMismatch,
      "HashOrStatus expected, but the source RLP is not a blob of right size.")

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

proc append*(rlpWriter: var RlpWriter, value: HashOrStatus) {.inline.} =
  if value.isHash:
    rlpWriter.append(value.hash)
  else:
    rlpWriter.append(if value.status: 1'u8 else: 0'u8)

proc append*(rlpWriter: var RlpWriter, rec: Receipt) =
  if rec.receiptType == LegacyReceiptType:
    rlpWriter.append(rec.legacyReceipt)
  else:
    # EIP 2718/2930
    rlpWriter.append(1)
    rlpWriter.append(rec.accessListReceipt)

proc read*(rlp: var Rlp, T: type Receipt): T =
  if rlp.isList:
    return Receipt(
      receiptType: LegacyReceiptType,
      legacyReceipt: rlp.read(LegacyReceipt)
    )

  # EIP 2718/2930
  let recType = rlp.read(int)
  if recType != 1:
    raise newException(UnsupportedRlpError,
      "TxType expect 1 got " & $recType)
  return Receipt(
    receiptType: AccessListReceiptType,
    accessListReceipt: rlp.read(AccessListReceipt)
  )

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
