# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## Core ethereum types and small helpers - keep focused as it gets imported
## from many places

import
  std/[options, strutils],
  results, stew/[byteutils, endians2], stint,
  ssz_serialization,
  ./eth_hash, ./eth_times

export
  options, results, stint, ssz_serialization, eth_hash, eth_times

const
  MAX_CALLDATA_SIZE* = 1 shl 24 # 2^24
  MAX_ACCESS_LIST_STORAGE_KEYS* = 1 shl 24 # 2^24
  MAX_ACCESS_LIST_SIZE* = 1 shl 24 # 2^24
  MAX_BLOB_COMMITMENTS_PER_BLOCK* = 4_096
  ECDSA_SIGNATURE_SIZE* = 65
  MAX_TRANSACTION_PAYLOAD_FIELDS* = 32
  MAX_TRANSACTION_SIGNATURE_FIELDS* = 16
  MAX_POOLED_TRANSACTION_FIELDS* = 8

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

  VersionedHash* = Hash256
  VersionedHashes* = seq[VersionedHash]
  KzgCommitment* = array[48, byte]
  KzgProof* = array[48, byte]

  # 32 -> UInt256
  # 4096 -> FIELD_ELEMENTS_PER_BLOB
  NetworkBlob* = array[32*4096, byte]

  TxType* = enum  # EIP-2718
    TxLegacy    # 0
    TxEip2930   # 1
    TxEip1559   # 2
    TxEip4844   # 3

  StorageKeys* = List[StorageKey, Limit MAX_ACCESS_LIST_STORAGE_KEYS]

  AccessPair* = object
    address*: EthAddress
    storage_keys*: StorageKeys

  AccessList* = List[AccessPair, Limit MAX_ACCESS_LIST_SIZE]

  TransactionPayload* {.
      sszStableContainer: MAX_TRANSACTION_PAYLOAD_FIELDS.} = object
    nonce*: uint64
    max_fee_per_gas*: UInt256
    gas*: uint64
    to*: Opt[EthAddress]
    value*: UInt256
    input*: List[byte, Limit MAX_CALLDATA_SIZE]

    # EIP-2718
    tx_type* {.serializedFieldName: "type".}: Opt[TxType]

    # EIP-2930
    access_list*: Opt[AccessList]

    # EIP-1559
    max_priority_fee_per_gas*: Opt[UInt256]

    # EIP-4844
    max_fee_per_blob_gas*: Opt[UInt256]
    blob_versioned_hashes*:
      Opt[List[VersionedHash, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]]

  TransactionSignature* {.
      sszStableContainer: MAX_TRANSACTION_SIGNATURE_FIELDS.} = object
    from_address* {.serializedFieldName: "from".}: EthAddress
    ecdsa_signature*: array[ECDSA_SIGNATURE_SIZE, byte]

  Transaction* = object  # EIP-6493
    payload*: TransactionPayload
    signature*: TransactionSignature

  ReplayableTransactionPayload* {.sszVariant: TransactionPayload.} = object
    nonce*: uint64
    max_fee_per_gas*: UInt256
    gas*: uint64
    to*: Opt[EthAddress]
    value*: UInt256
    input*: List[byte, Limit MAX_CALLDATA_SIZE]

  ReplayableTransaction* {.sszVariant: Transaction.} = object  # EIP-6493
    payload*: ReplayableTransactionPayload
    signature*: TransactionSignature

  LegacyTransactionPayload* {.sszVariant: TransactionPayload.} = object
    nonce*: uint64
    max_fee_per_gas*: UInt256
    gas*: uint64
    to*: Opt[EthAddress]
    value*: UInt256
    input*: List[byte, Limit MAX_CALLDATA_SIZE]
    tx_type* {.serializedFieldName: "type".}: TxType

  LegacyTransaction* {.sszVariant: Transaction.} = object  # EIP-6493
    payload*: LegacyTransactionPayload
    signature*: TransactionSignature

  Eip2930TransactionPayload* {.sszVariant: TransactionPayload.} = object
    nonce*: uint64
    max_fee_per_gas*: UInt256
    gas*: uint64
    to*: Opt[EthAddress]
    value*: UInt256
    input*: List[byte, Limit MAX_CALLDATA_SIZE]
    tx_type* {.serializedFieldName: "type".}: TxType
    access_list*: AccessList

  Eip2930Transaction* {.sszVariant: Transaction.} = object  # EIP-6493
    payload*: Eip2930TransactionPayload
    signature*: TransactionSignature

  Eip1559TransactionPayload* {.sszVariant: TransactionPayload.} = object
    nonce*: uint64
    max_fee_per_gas*: UInt256
    gas*: uint64
    to*: Opt[EthAddress]
    value*: UInt256
    input*: List[byte, Limit MAX_CALLDATA_SIZE]
    tx_type* {.serializedFieldName: "type".}: TxType
    access_list*: AccessList
    max_priority_fee_per_gas*: UInt256

  Eip1559Transaction* {.sszVariant: Transaction.} = object  # EIP-6493
    payload*: Eip1559TransactionPayload
    signature*: TransactionSignature

  Eip4844TransactionPayload* {.sszVariant: TransactionPayload.} = object
    nonce*: uint64
    max_fee_per_gas*: UInt256
    gas*: uint64
    to*: EthAddress
    value*: UInt256
    input*: List[byte, Limit MAX_CALLDATA_SIZE]
    tx_type* {.serializedFieldName: "type".}: TxType
    access_list*: AccessList
    max_priority_fee_per_gas*: UInt256
    max_fee_per_blob_gas*: UInt256
    blob_versioned_hashes*:
      List[VersionedHash, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]

  Eip4844Transaction* {.sszVariant: Transaction.} = object  # EIP-6493
    payload*: Eip4844TransactionPayload
    signature*: TransactionSignature

  TransactionKind* {.pure.} = enum
    Replayable
    Legacy
    Eip2930
    Eip1559
    Eip4844

  AnyTransactionPayloadVariant* =
    ReplayableTransactionPayload |
    LegacyTransactionPayload |
    Eip2930TransactionPayload |
    Eip1559TransactionPayload |
    Eip4844TransactionPayload

  AnyTransactionPayload* {.sszOneOf: TransactionPayload.} = object
    case kind*: TransactionKind
    of TransactionKind.Eip4844:
      eip4844Data*: Eip4844TransactionPayload
    of TransactionKind.Eip1559:
      eip1559Data*: Eip1559TransactionPayload
    of TransactionKind.Eip2930:
      eip2930Data*: Eip2930TransactionPayload
    of TransactionKind.Legacy:
      legacyData*: LegacyTransactionPayload
    of TransactionKind.Replayable:
      replayableData*: ReplayableTransactionPayload

  AnyTransactionVariant* =
    ReplayableTransaction |
    LegacyTransaction |
    Eip2930Transaction |
    Eip1559Transaction |
    Eip4844Transaction

  AnyTransaction* {.sszOneOf: Transaction.} = object
    case kind*: TransactionKind
    of TransactionKind.Eip4844:
      eip4844Data*: Eip4844Transaction
    of TransactionKind.Eip1559:
      eip1559Data*: Eip1559Transaction
    of TransactionKind.Eip2930:
      eip2930Data*: Eip2930Transaction
    of TransactionKind.Legacy:
      legacyData*: LegacyTransaction
    of TransactionKind.Replayable:
      replayableData*: ReplayableTransaction

template withTxPayloadVariant*(
    x: AnyTransactionPayload, body: untyped): untyped =
  case x.kind
  of TransactionKind.Eip4844:
    const txKind {.inject, used.} = TransactionKind.Eip4844
    template txPayloadVariant: untyped {.inject, used.} = x.eip4844Data
    body
  of TransactionKind.Eip1559:
    const txKind {.inject, used.} = TransactionKind.Eip1559
    template txPayloadVariant: untyped {.inject, used.} = x.eip1559Data
    body
  of TransactionKind.Eip2930:
    const txKind {.inject, used.} = TransactionKind.Eip2930
    template txPayloadVariant: untyped {.inject, used.} = x.eip2930Data
    body
  of TransactionKind.Legacy:
    const txKind {.inject, used.} = TransactionKind.Legacy
    template txPayloadVariant: untyped {.inject, used.} = x.legacyData
    body
  of TransactionKind.Replayable:
    const txKind {.inject, used.} = TransactionKind.Replayable
    template txPayloadVariant: untyped {.inject, used.} = x.replayableData
    body

func init*(T: typedesc[AnyTransaction], tx: Eip4844Transaction): T =
  T(kind: TransactionKind.Eip4844, eip4844Data: tx)

func init*(T: typedesc[AnyTransaction], tx: Eip1559Transaction): T =
  T(kind: TransactionKind.Eip1559, eip1559Data: tx)

func init*(T: typedesc[AnyTransaction], tx: Eip2930Transaction): T =
  T(kind: TransactionKind.Eip2930, eip2930Data: tx)

func init*(T: typedesc[AnyTransaction], tx: LegacyTransaction): T =
  T(kind: TransactionKind.Legacy, legacyData: tx)

func init*(T: typedesc[AnyTransaction], tx: ReplayableTransaction): T =
  T(kind: TransactionKind.Replayable, replayableData: tx)

template withTxVariant*(x: AnyTransaction, body: untyped): untyped =
  case x.kind
  of TransactionKind.Eip4844:
    const txKind {.inject, used.} = TransactionKind.Eip4844
    template txVariant: untyped {.inject, used.} = x.eip4844Data
    body
  of TransactionKind.Eip1559:
    const txKind {.inject, used.} = TransactionKind.Eip1559
    template txVariant: untyped {.inject, used.} = x.eip1559Data
    body
  of TransactionKind.Eip2930:
    const txKind {.inject, used.} = TransactionKind.Eip2930
    template txVariant: untyped {.inject, used.} = x.eip2930Data
    body
  of TransactionKind.Legacy:
    const txKind {.inject, used.} = TransactionKind.Legacy
    template txVariant: untyped {.inject, used.} = x.legacyData
    body
  of TransactionKind.Replayable:
    const txKind {.inject, used.} = TransactionKind.Replayable
    template txVariant: untyped {.inject, used.} = x.replayableData
    body

# https://eips.ethereum.org/EIPS/eip-6493#ssz-signedtransaction-container
func selectVariant*(value: TransactionPayload): Opt[TransactionKind] =
  if value.tx_type == Opt.some TxEip4844:
    return Opt.some TransactionKind.Eip4844

  if value.tx_type == Opt.some TxEip1559:
    return Opt.some TransactionKind.Eip1559

  if value.tx_type == Opt.some TxEip2930:
    return Opt.some TransactionKind.Eip2930

  if value.tx_type == Opt.some TxLegacy:
    return Opt.some TransactionKind.Legacy

  if value.tx_type.isNone:
    return Opt.some TransactionKind.Replayable

  Opt.none TransactionKind

func selectVariant*(value: Transaction): Opt[TransactionKind] =
  selectVariant(value.payload)

type
  NetworkPayload* = ref object
    blobs*       : List[NetworkBlob, MAX_BLOB_COMMITMENTS_PER_BLOCK]
    commitments* : List[KzgCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]
    proofs*      : List[KzgProof, MAX_BLOB_COMMITMENTS_PER_BLOCK]

  PooledTransaction* {.
      sszStableContainer: MAX_POOLED_TRANSACTION_FIELDS.} = object
    tx*: Transaction
    blob_data*: Opt[NetworkPayload]  # EIP-4844

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
    txs*        : seq[Transaction]
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
  Eip4844Receipt* = TxEip4844

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
  tx.payload.to.isNone

func destination*(tx: TransactionPayload): EthAddress =
  # use getRecipient if you also want to get
  # the contract address
  if tx.to.isSome:
    return tx.to.get

func destination*(tx: Transaction): EthAddress =
  tx.payload.destination

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
template hasData*(r: EthResourceRefs): bool = r != nil

template deref*(b: Blob): auto = b
template deref*(o: Option): auto = o.get
template deref*(r: EthResourceRefs): auto = r[]

func `==`*(a, b: ChainId): bool {.borrow.}

func `==`*(a, b: NetworkId): bool =
  a.uint == b.uint

func `$`*(x: NetworkId): string =
  `$`(uint(x))
