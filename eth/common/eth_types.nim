# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

## Core ethereum types and smalll helpers - keep focused as it gets imported
## from many places

import
  std/[options, strutils, times],
  stew/[byteutils, endians2], stint,
  ./eth_hash

export
  options, stint, eth_hash,
  times.Time, times.fromUnix, times.toUnix

type
  Hash256* = MDigest[256]
  EthTime* = Time
  VMWord* = UInt256
  BlockNonce* = array[8, byte]
  AccountNonce* = uint64
  Blob* = seq[byte]

  BloomFilter* = array[256, byte]
  EthAddress* = array[20, byte]

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
    transactions*:  seq[Transaction]
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
    txs*:    seq[Transaction]
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

  # TODO clean these up
  EMPTY_ROOT_HASH* = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".toDigest
  EMPTY_UNCLE_HASH* = "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".toDigest
  EMPTY_CODE_HASH* = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".toDigest

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

# starting from EIP-4399, `mixHash`/`mixDigest` field will be alled `prevRandao`
template prevRandao*(h: BlockHeader | BlockHeaderRef): Hash256 =
  h.mixDigest

template `prevRandao=`*(h: BlockHeader | BlockHeaderRef, hash: Hash256) =
  h.mixDigest = hash

func toBlockNonce*(n: uint64): BlockNonce =
  n.toBytesBE()

func toUint*(n: BlockNonce): uint64 =
  uint64.fromBytesBE(n)

proc newAccount*(nonce: AccountNonce = 0, balance: UInt256 = 0.u256): Account =
  result.nonce = nonce
  result.balance = balance
  result.storageRoot = EMPTY_ROOT_HASH
  result.codeHash = EMPTY_CODE_HASH

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

template hasData*(b: Blob): bool = b.len > 0
template hasData*(r: EthResourceRefs): bool = r != nil

template deref*(b: Blob): auto = b
template deref*(o: Option): auto = o.get
template deref*(r: EthResourceRefs): auto = r[]
