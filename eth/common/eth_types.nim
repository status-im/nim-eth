# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## Core ethereum types and small helpers - keep focused as it gets imported
## from many places

import
  std/[options, hashes, strutils],
  stew/[byteutils, endians2], stint,
  ./eth_hash, ./eth_times

export
  options, stint, eth_hash, eth_times

type
  Hash256* = MDigest[256]
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

  NetworkId* = distinct uint

  Account* = object
    nonce*:       AccountNonce
    balance*:     UInt256
    storageRoot*: Hash256
    codeHash*:    Hash256

  AccessPair* = object
    address*    : EthAddress
    storageKeys*: seq[StorageKey]

  AccessList* = seq[AccessPair]

  VersionedHash* = Hash256
  VersionedHashes* = seq[VersionedHash]
  KzgCommitment* = array[48, byte]
  KzgProof* = array[48, byte]

  # 32 -> UInt256
  # 4096 -> FIELD_ELEMENTS_PER_BLOB
  NetworkBlob* = array[32*4096, byte]

  TxType* = enum
    TxLegacy    # 0
    TxEip2930   # 1
    TxEip1559   # 2
    TxEip4844   # 3

  NetworkPayload* = ref object
    blobs*       : seq[NetworkBlob]
    commitments* : seq[KzgCommitment]
    proofs*      : seq[KzgProof]

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
    maxFeePerBlobGas*: UInt256            # EIP-4844
    versionedHashes*: VersionedHashes     # EIP-4844
    V*             : int64
    R*, S*         : UInt256

  PooledTransaction* = object
    tx*: Transaction
    networkPayload*: NetworkPayload       # EIP-4844

  TransactionStatus* = enum
    Unknown,
    Queued,
    Pending,
    Included,
    Error

  TransactionStatusMsg* = object
    status*: TransactionStatus
    data*: Blob

  Withdrawal* = object  # EIP-4895
    index*         : uint64
    validatorIndex*: uint64
    address*       : EthAddress
    amount*        : uint64

  # https://eips.ethereum.org/EIPS/eip-4844#header-extension
  BlockHeader* = object
    parentHash*:      Hash256
    ommersHash*:      Hash256
    coinbase*:        EthAddress
    stateRoot*:       Hash256
    txRoot*:          Hash256
    receiptRoot*:     Hash256
    bloom*:           BloomFilter
    difficulty*:      DifficultyInt
    blockNumber*:     BlockNumber
    gasLimit*:        GasInt
    gasUsed*:         GasInt
    timestamp*:       EthTime
    extraData*:       Blob
    mixDigest*:       Hash256
    nonce*:           BlockNonce
    # `baseFee` is the get/set of `fee`
    fee*:             Option[UInt256]   # EIP-1559
    withdrawalsRoot*: Option[Hash256]   # EIP-4895
    blobGasUsed*:     Option[uint64]    # EIP-4844
    excessBlobGas*:   Option[uint64]    # EIP-4844
    parentBeaconBlockRoot*: Option[Hash256] # EIP-4788

  BlockBody* = object
    transactions*:  seq[Transaction]
    uncles*:        seq[BlockHeader]
    withdrawals*:   Option[seq[Withdrawal]]   # EIP-4895

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
    # Eip4844Receipt = TxEip4844

  Receipt* = object
    receiptType*      : ReceiptType
    isHash*           : bool          # hash or status
    status*           : bool          # EIP-658
    hash*             : Hash256
    cumulativeGasUsed*: GasInt
    bloom*            : BloomFilter
    logs*             : seq[Log]

  EthBlock* = object
    header*     : BlockHeader
    transactions*: seq[Transaction]
    uncles*     : seq[BlockHeader]
    withdrawals*: Option[seq[Withdrawal]]   # EIP-4895

  BlobsBundle* = object
    commitments*: seq[KzgCommitment]
    proofs*: seq[KzgProof]
    blobs*: seq[NetworkBlob]

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

  ValidationResult* {.pure.} = enum
    OK
    Error

const
  LegacyReceipt*  = TxLegacy
  Eip2930Receipt* = TxEip2930
  Eip1559Receipt* = TxEip1559
  Eip4844Receipt* = TxEip4844

  EMPTY_ROOT_HASH* = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".toDigest
  EMPTY_UNCLE_HASH* = "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".toDigest
  EMPTY_CODE_HASH* = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".toDigest

template txs*(blk: EthBlock): seq[Transaction] =
  # Legacy name emulation
  blk.transactions

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
func baseFee*(h: BlockHeader): UInt256 =
  if h.fee.isSome:
    h.fee.get()
  else:
    0.u256

template `baseFee=`*(h: BlockHeader, data: UInt256) =
  h.fee = some(data)

# starting from EIP-4399, `mixHash`/`mixDigest` field will be alled `prevRandao`
template prevRandao*(h: BlockHeader): Hash256 =
  h.mixDigest

template `prevRandao=`*(h: BlockHeader, hash: Hash256) =
  h.mixDigest = hash

func toBlockNonce*(n: uint64): BlockNonce =
  n.toBytesBE()

func toUint*(n: BlockNonce): uint64 =
  uint64.fromBytesBE(n)

func newAccount*(nonce: AccountNonce = 0, balance: UInt256 = 0.u256): Account =
  result.nonce = nonce
  result.balance = balance
  result.storageRoot = EMPTY_ROOT_HASH
  result.codeHash = EMPTY_CODE_HASH

func hasStatus*(rec: Receipt): bool {.inline.} =
  rec.isHash == false

func hasStateRoot*(rec: Receipt): bool {.inline.} =
  rec.isHash == true

func stateRoot*(rec: Receipt): Hash256 {.inline.} =
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
          {.raises: [ValueError].} =
  if str.startsWith "0x":
    if str.len != sizeof(default(T).hash.data) * 2 + 2:
      raise newException(ValueError, "Block hash has incorrect length")

    var res = T(isHash: true)
    hexToByteArray(str, res.hash.data)
    res
  else:
    T(isHash: false, number: parseBiggestUInt str)

func `$`*(x: BlockHashOrNumber): string =
  if x.isHash:
    "0x" & x.hash.data.toHex
  else:
    $x.number

template hasData*(b: Blob): bool = b.len > 0

template deref*(b: Blob): auto = b
template deref*(o: Option): auto = o.get

func `==`*(a, b: NetworkId): bool =
  a.uint == b.uint

func `$`*(x: NetworkId): string =
  `$`(uint(x))

func `==`*(a, b: EthAddress): bool {.inline.} =
  equalMem(unsafeAddr a[0], unsafeAddr b[0], a.len)

# TODO https://github.com/nim-lang/Nim/issues/23678
func hash*(a: EthAddress): Hash {.inline.} =
  static: doAssert sizeof(a) == 20
  var a0{.noinit.}, a1 {.noinit.}: uint64
  var a2{.noinit.}: uint32

  # Addresses are more or less random so we should not need a fancy mixing
  # function
  copyMem(addr a0, unsafeAddr a[0], sizeof(a0))
  copyMem(addr a1, unsafeAddr a[8], sizeof(a1))
  copyMem(addr a2, unsafeAddr a[16], sizeof(a2))

  cast[Hash](a0 xor a1 xor uint64(a2))

# TODO https://github.com/nim-lang/Nim/issues/23354 - parameters should be sink
func init*(T: type EthBlock, header: BlockHeader, body: BlockBody): T =
  T(
    header: header,
    transactions: body.transactions,
    uncles: body.uncles,
    withdrawals: body.withdrawals,
  )
