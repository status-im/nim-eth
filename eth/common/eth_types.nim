import
  endians, options, times,
  stint, nimcrypto, rlp, eth_trie/[defs, db]

export
  stint, read, append, KeccakHash

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

  Account* = object
    nonce*:             AccountNonce
    balance*:           UInt256
    storageRoot*:       Hash256
    codeHash*:          Hash256

  Transaction* = object
    accountNonce*:  AccountNonce
    gasPrice*:      GasInt
    gasLimit*:      GasInt
    to* {.rlpCustomSerialization.}: EthAddress
    value*:         UInt256
    payload*:       Blob
    V*:             byte
    R*, S*:         UInt256
    isContractCreation* {.rlpIgnore.}: bool

  TransactionStatus* = enum
    Unknown,
    Queued,
    Pending,
    Included,
    Error

  TransactionStatusMsg* = object
    status*: TransactionStatus
    data*: Blob

  BlockNumber* = UInt256

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
    transactions*:  seq[Transaction]
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

  Receipt* = object
    stateRootOrStatus*: HashOrStatus
    cumulativeGasUsed*: GasInt
    bloom*:         BloomFilter
    logs*:          seq[Log]

  AccessList* = object
    # XXX: Specify the structure of this

  ShardTransaction* = object
    chain*:         uint
    shard*:         uint
    to*:            EthAddress
    data*:          Blob
    gas*:           GasInt
    accessList*:    AccessList
    code*:          Blob
    salt*:          Hash256

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

  HashOrNum* = object
    case isHash*: bool
    of true:
      hash*: Hash256
    else:
      number*: BlockNumber

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

else:
  template vmWordToBlockNumber*(word: VMWord): BlockNumber =
    word

  template blockNumberToVmWord*(n: BlockNumber): VMWord =
    n

  template toBlockNumber*(n: SomeInteger): BlockNumber =
    u256(n)

proc toBlockNonce*(n: uint64): BlockNonce =
  bigEndian64(addr result[0], unsafeAddr n)

proc toUint*(n: BlockNonce): uint64 =
  bigEndian64(addr result, unsafeAddr n[0])

proc newAccount*(nonce: AccountNonce = 0, balance: UInt256 = 0.u256): Account =
  result.nonce = nonce
  result.balance = balance
  result.storageRoot = emptyRlpHash
  result.codeHash = blankStringHash

proc hashOrStatus*(hash: Hash256): HashOrStatus =
  HashOrStatus(isHash: true, hash: hash)

proc hashOrStatus*(status: bool): HashOrStatus =
  HashOrStatus(isHash: false, status: status)

proc hasStatus*(rec: Receipt): bool {.inline.} =
  rec.stateRootOrStatus.isHash == false

proc hasStateRoot*(rec: Receipt): bool {.inline.} =
  rec.stateRootOrStatus.isHash == true

proc stateRoot*(rec: Receipt): Hash256 {.inline.} =
  assert(rec.hasStateRoot)
  rec.stateRootOrStatus.hash

proc status*(rec: Receipt): int {.inline.} =
  assert(rec.hasStatus)
  if rec.stateRootOrStatus.status: 1 else: 0

#
# Rlp serialization:
#

proc read*(rlp: var Rlp, T: typedesc[StUint]): T {.inline.} =
  if rlp.isBlob:
    let bytes = rlp.toBytes
    if bytes.len > 0:
      result.initFromBytesBE(bytes.toOpenArray)
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
    rlpWriter.append(value.toInt)

proc read*(rlp: var Rlp, T: typedesc[Stint]): T {.inline.} =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.error: "RLP serialization of signed integers is not allowed".}
  discard

proc append*(rlpWriter: var RlpWriter, value: Stint) =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.error: "RLP serialization of signed integers is not allowed".}
  discard

proc read*(rlp: var Rlp, t: var Transaction, _: type EthAddress): EthAddress {.inline.} =
  if rlp.blobLen != 0:
    result = rlp.read(EthAddress)
  else:
    t.isContractCreation = true
    rlp.skipElem()

proc append*(rlpWriter: var RlpWriter, t: Transaction, a: EthAddress) {.inline.} =
  if t.isContractCreation:
    rlpWriter.append("")
  else:
    rlpWriter.append(a)

proc read*(rlp: var Rlp, T: typedesc[HashOrStatus]): T {.inline.} =
  assert(rlp.blobLen() == 32 or rlp.blobLen() == 1)
  if rlp.blobLen == 1:
    result = hashOrStatus(rlp.read(uint8) == 1)
  else:
    result = hashOrStatus(rlp.read(Hash256))

proc append*(rlpWriter: var RlpWriter, value: HashOrStatus) {.inline.} =
  if value.isHash:
    rlpWriter.append(value.hash)
  else:
    rlpWriter.append(if value.status: 1'u8 else: 0'u8)

proc read*(rlp: var Rlp, T: typedesc[Time]): T {.inline.} =
  result = fromUnix(rlp.read(int64))

proc append*(rlpWriter: var RlpWriter, value: HashOrNum) =
  case value.isHash
  of true:
    rlpWriter.append(value.hash)
  else:
    rlpWriter.append(value.number)

proc read*(rlp: var Rlp, T: typedesc[HashOrNum]): T =
  if rlp.blobLen == 32:
    result = HashOrNum(isHash: true, hash: rlp.read(Hash256))
  else:
    result = HashOrNum(isHash: false, number: rlp.read(UInt256))

proc append*(rlpWriter: var RlpWriter, t: Time) {.inline.} =
  rlpWriter.append(t.toUnix())

proc rlpHash*[T](v: T): Hash256 =
  keccak256.digest(rlp.encode(v))

func blockHash*(h: BlockHeader): KeccakHash {.inline.} = rlpHash(h)

proc notImplemented =
  assert false, "Method not impelemented"

template hasData*(b: Blob): bool = b.len > 0
template hasData*(r: EthResourceRefs): bool = r != nil

template deref*(b: Blob): auto = b
template deref*(o: Option): auto = o.get
template deref*(r: EthResourceRefs): auto = r[]

method genesisHash*(db: AbstractChainDB): KeccakHash {.base, gcsafe.} =
  notImplemented()

method getBlockHeader*(db: AbstractChainDB, b: HashOrNum, output: var BlockHeader): bool {.base, gcsafe.} =
  notImplemented()

proc getBlockHeader*(db: AbstractChainDB, hash: KeccakHash): BlockHeaderRef {.gcsafe.} =
  new result
  if not db.getBlockHeader(HashOrNum(isHash: true, hash: hash), result[]):
    return nil

proc getBlockHeader*(db: AbstractChainDB, b: BlockNumber): BlockHeaderRef {.gcsafe.} =
  new result
  if not db.getBlockHeader(HashOrNum(isHash: false, number: b), result[]):
    return nil

method getBestBlockHeader*(self: AbstractChainDB): BlockHeader {.base, gcsafe.} =
  notImplemented()

method getSuccessorHeader*(db: AbstractChainDB, h: BlockHeader, output: var BlockHeader): bool {.base, gcsafe.} =
  notImplemented()

method getBlockBody*(db: AbstractChainDB, blockHash: KeccakHash): BlockBodyRef {.base, gcsafe.} =
  notImplemented()

method getReceipt*(db: AbstractChainDB, hash: KeccakHash): ReceiptRef {.base, gcsafe.} =
  notImplemented()

method getStateDb*(db: AbstractChainDB): TrieDatabaseRef {.base, gcsafe.} =
  notImplemented()

method getCodeByHash*(db: AbstractChainDB, hash: KeccakHash): Blob {.base, gcsafe.} =
  notImplemented()

method getSetting*(db: AbstractChainDb, key: string): Bytes {.base, gcsafe.} =
  notImplemented()

method setSetting*(db: AbstractChainDb, key: string, val: openarray[byte]) {.base, gcsafe.} =
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

