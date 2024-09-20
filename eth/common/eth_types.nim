# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## Core ethereum types and small helpers - keep focused as it gets imported
## from many places

import
  std/[hashes, strutils, typetraits],
  stew/[byteutils, endians2],
  stint,
  results,
  nimcrypto/hash,
  ./base_types,
  ./eth_address,
  ./eth_hash,
  ./eth_times

export
  results,
  stint,
  hash,
  base_types,
  eth_address,
  eth_hash,
  eth_times

type
  Root* = Hash32
  BlockNonce* = Bytes8
  AccountNonce* = uint64
  Blob* = seq[byte]

  BloomFilter* = Bytes256

  DifficultyInt* = UInt256
  GasInt* = uint64
  ## Type alias used for gas computation
  # For reference - https://github.com/status-im/nimbus/issues/35#issuecomment-391726518

  Topic* = array[32, byte]
  # topic can be Hash32 or zero padded bytes array

  ForkID* = tuple[crc: uint32, nextFork: uint64]
  # EIP 2364/2124

  BlockNumber* = uint64
  StorageKey* = array[32, byte]

  # beware that although in some cases
  # chainId have identical value to networkId
  # they are separate entity
  ChainId* = distinct uint64

  NetworkId* = distinct uint

  Account* = object
    nonce*:       AccountNonce
    balance*:     UInt256
    storageRoot*: Root
    codeHash*:    Hash32

  AccessPair* = object
    address*    : Address
    storageKeys*: seq[StorageKey]

  AccessList* = seq[AccessPair]

  VersionedHash* = Bytes32
  VersionedHashes* = seq[VersionedHash]
  KzgCommitment* = Bytes48
  KzgProof* = Bytes48

  # 32 -> UInt256
  # 4096 -> FIELD_ELEMENTS_PER_BLOB
  NetworkBlob* = array[32*4096, byte]

  TxType* = enum
    TxLegacy    # 0
    TxEip2930   # 1
    TxEip1559   # 2
    TxEip4844   # 3
    TxEip7702   # 4

  NetworkPayload* = ref object
    blobs*       : seq[NetworkBlob]
    commitments* : seq[KzgCommitment]
    proofs*      : seq[KzgProof]

  Authorization* = object
    chainId*: ChainId
    address*: Address
    nonce*: AccountNonce
    yParity*: uint64
    R*: UInt256
    S*: UInt256

  Transaction* = object
    txType*        : TxType               # EIP-2718
    chainId*       : ChainId              # EIP-2930
    nonce*         : AccountNonce
    gasPrice*      : GasInt
    maxPriorityFeePerGas*: GasInt         # EIP-1559
    maxFeePerGas*  : GasInt               # EIP-1559
    gasLimit*      : GasInt
    to*            : Opt[Address]
    value*         : UInt256
    payload*       : Blob
    accessList*    : AccessList           # EIP-2930
    maxFeePerBlobGas*: UInt256            # EIP-4844
    versionedHashes*: VersionedHashes     # EIP-4844
    authorizationList*: seq[Authorization]# EIP-7702
    V*             : uint64
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
    address*       : Address
    amount*        : uint64

  DepositRequest* = object  # EIP-6110
    pubkey*               : Bytes48
    withdrawalCredentials*: Bytes32
    amount*               : uint64
    signature*            : Bytes96
    index*                : uint64

  WithdrawalRequest* = object  # EIP-7002
    sourceAddress*  : Address
    validatorPubkey*: Bytes48
    amount*         : uint64

  ConsolidationRequest* = object  # EIP-7251
    sourceAddress*: Address
    sourcePubkey* : Bytes48
    targetPubkey* : Bytes48

  # https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/paris/blocks.py#L22
  BlockHeader* = object
    parentHash*:      Hash32
    ommersHash*:      Hash32
    coinbase*:        Address
    stateRoot*:       Hash32
    txRoot*:          Hash32
    receiptsRoot*:    Hash32
    logsBloom*:       BloomFilter
    difficulty*:      DifficultyInt
    number*:          BlockNumber
    gasLimit*:        GasInt
    gasUsed*:         GasInt
    timestamp*:       EthTime
    extraData*:       Blob
    mixHash*:         Hash32
    nonce*:           BlockNonce
    baseFeePerGas*:   Opt[UInt256]   # EIP-1559
    withdrawalsRoot*: Opt[Hash32]   # EIP-4895
    blobGasUsed*:     Opt[uint64]    # EIP-4844
    excessBlobGas*:   Opt[uint64]    # EIP-4844
    parentBeaconBlockRoot*: Opt[Hash32] # EIP-4788
    requestsRoot*:    Opt[Hash32]  # EIP-7685


  RequestType* = enum
    DepositRequestType        # EIP-6110
    WithdrawalRequestType     # EIP-7002
    ConsolidationRequestType  # EIP-7251

  Request* = object
    case requestType*: RequestType
    of DepositRequestType:
      deposit*: DepositRequest
    of WithdrawalRequestType:
      withdrawal*: WithdrawalRequest
    of ConsolidationRequestType:
      consolidation*: ConsolidationRequest

  BlockBody* = object
    transactions*:  seq[Transaction]
    uncles*:        seq[BlockHeader]
    withdrawals*:   Opt[seq[Withdrawal]]   # EIP-4895
    requests*:      Opt[seq[Request]]      # EIP-7865

  Log* = object
    address*:       Address
    topics*:        seq[Topic]
    data*:          Blob

  # easily convertible between
  # ReceiptType and TxType
  ReceiptType* = TxType
    # LegacyReceipt  = TxLegacy
    # Eip2930Receipt = TxEip2930
    # Eip1559Receipt = TxEip1559
    # Eip4844Receipt = TxEip4844
    # Eip7702Receipt = TxEip7702

  Receipt* = object
    receiptType*      : ReceiptType
    isHash*           : bool          # hash or status
    status*           : bool          # EIP-658
    hash*             : Hash32
    cumulativeGasUsed*: GasInt
    logsBloom*        : BloomFilter
    logs*             : seq[Log]

  EthBlock* = object
    header*     : BlockHeader
    transactions*: seq[Transaction]
    uncles*     : seq[BlockHeader]
    withdrawals*: Opt[seq[Withdrawal]]   # EIP-4895
    requests*:    Opt[seq[Request]]      # EIP-7865

  BlobsBundle* = object
    commitments*: seq[KzgCommitment]
    proofs*: seq[KzgProof]
    blobs*: seq[NetworkBlob]

  BlockHashOrNumber* = object
    case isHash*: bool
    of true:
      hash*: Hash32
    else:
      number*: BlockNumber

const
  LegacyReceipt*  = TxLegacy
  Eip2930Receipt* = TxEip2930
  Eip1559Receipt* = TxEip1559
  Eip4844Receipt* = TxEip4844
  Eip7702Receipt* = TxEip7702

  EMPTY_ROOT_HASH* = hash32"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
  EMPTY_UNCLE_HASH* = hash32"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
  EMPTY_CODE_HASH* = hash32"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

template txs*(blk: EthBlock): seq[Transaction] =
  # Legacy name emulation
  blk.transactions

# starting from EIP-4399, `mixHash`/`mixDigest` field will be alled `prevRandao`
template prevRandao*(h: BlockHeader): Hash32 =
  h.mixHash

template `prevRandao=`*(h: BlockHeader, hash: Hash32) =
  h.mixHash = hash

func toBlockNonce*(n: uint64): BlockNonce =
  BlockNonce(n.toBytesBE())

func toUint*(n: BlockNonce): uint64 =
  uint64.fromBytesBE(n.data)

func newAccount*(nonce: AccountNonce = 0, balance: UInt256 = 0.u256): Account =
  result.nonce = nonce
  result.balance = balance
  result.storageRoot = EMPTY_ROOT_HASH
  result.codeHash = EMPTY_CODE_HASH

func hasStatus*(rec: Receipt): bool {.inline.} =
  rec.isHash == false

func hasStateRoot*(rec: Receipt): bool {.inline.} =
  rec.isHash == true

func stateRoot*(rec: Receipt): Hash32 {.inline.} =
  doAssert(rec.hasStateRoot)
  rec.hash

template contractCreation*(tx: Transaction): bool =
  tx.to.isNone

func destination*(tx: Transaction): Address =
  # use getRecipient if you also want to get
  # the contract address
  tx.to.valueOr(default(Address))

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
template deref*(o: Opt): auto = o.get

func `==`*(a, b: NetworkId): bool =
  a.uint == b.uint

func `$`*(x: NetworkId): string =
  `$`(uint(x))

# TODO https://github.com/nim-lang/Nim/issues/23354 - parameters should be sink
func init*(T: type EthBlock, header: BlockHeader, body: BlockBody): T =
  T(
    header: header,
    transactions: body.transactions,
    uncles: body.uncles,
    withdrawals: body.withdrawals,
  )

func `==`*(a, b: Request): bool =
  if a.requestType != b.requestType:
    return false

  case a.requestType
  of DepositRequestType:
    a.deposit == b.deposit
  of WithdrawalRequestType:
    a.withdrawal == b.withdrawal
  of ConsolidationRequestType:
    a.consolidation == b.consolidation
