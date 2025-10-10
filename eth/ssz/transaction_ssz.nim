import
  ssz_serialization, stint,
  ../common/[addresses, base, hashes],
  ./signatures,
  ./adapter
  
export adapter

type SignedTx*[P] = object
  payload*: P
  signature*: Secp256k1ExecutionSignature

type
  TransactionType* = uint8
  GasAmount* = uint64
  FeePerGas* = UInt256
  ProgressiveByteList* = seq[byte]

const
  TxLegacy*: TransactionType = 00'u8
  TxAccessList*: TransactionType = 01'u8
  TxDynamicFee*: TransactionType = 02'u8
  TxBlob*: TransactionType = 03'u8
  TxSetCode*: TransactionType = 04'u8
  AuthMagic7702*: TransactionType = 05'u8

type
  BasicFeesPerGas* = object
    regular*: FeePerGas

  BlobFeesPerGas* = object
    regular*: FeePerGas
    blob*: FeePerGas

type AccessTuple* = object
  address*: Address
  storage_keys*: seq[Hash32]

type
  RlpLegacyReplayableBasicTransactionPayload* {.
    sszActiveFields: [1, 0, 1, 1, 1, 1, 1, 1]
  .} = object
    txType*: TransactionType
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    to*: Address
    value*: UInt256
    input*: ProgressiveByteList

  RlpLegacyReplayableCreateTransactionPayload* {.
    sszActiveFields: [1, 0, 1, 1, 1, 0, 1, 1]
  .} = object
    txType*: TransactionType
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList

type
  RlpLegacyBasicTransactionPayload* {.sszActiveFields: [1, 1, 1, 1, 1, 1, 1, 1].} = object
    txType*: TransactionType
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    to*: Address
    value*: UInt256
    input*: ProgressiveByteList

  RlpLegacyCreateTransactionPayload* {.sszActiveFields: [1, 1, 1, 1, 1, 0, 1, 1].} = object
    txType*: TransactionType
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList

type RlpAccessListBasicTransactionPayload* {.
  sszActiveFields: [1, 1, 1, 1, 1, 1, 1, 1, 1]
.} = object
  txType*: TransactionType
  chain_id*: ChainId
  nonce*: uint64
  max_fees_per_gas*: BasicFeesPerGas
  gas*: GasAmount
  to*: Address
  value*: UInt256
  input*: ProgressiveByteList
  access_list*: seq[AccessTuple]

type RlpAccessListCreateTransactionPayload* {.
  sszActiveFields: [1, 1, 1, 1, 1, 0, 1, 1, 1]
.} = object
  txType*: TransactionType
  chain_id*: ChainId
  nonce*: uint64
  max_fees_per_gas*: BasicFeesPerGas
  gas*: GasAmount
  value*: UInt256
  input*: ProgressiveByteList
  access_list*: seq[AccessTuple]

type
  RlpBasicTransactionPayload* {.sszActiveFields: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1].} = object
    txType*: TransactionType
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    to*: Address
    value*: UInt256
    input*: ProgressiveByteList
    access_list*: seq[AccessTuple]
    max_priority_fees_per_gas*: BasicFeesPerGas

  RlpCreateTransactionPayload* {.sszActiveFields: [1, 1, 1, 1, 1, 0, 1, 1, 1, 1].} = object
    txType*: TransactionType
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList
    access_list*: seq[AccessTuple]
    max_priority_fees_per_gas*: BasicFeesPerGas

type RlpBlobTransactionPayload* {.sszActiveFields: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1].} = object
  txType*: TransactionType
  chain_id*: ChainId
  nonce*: uint64
  max_fees_per_gas*: BlobFeesPerGas
  gas*: GasAmount
  to*: Address
  value*: UInt256
  input*: ProgressiveByteList
  access_list*: seq[AccessTuple]
  max_priority_fees_per_gas*: BasicFeesPerGas
  blob_versioned_hashes*: seq[VersionedHash]

type
  RlpReplayableBasicAuthorizationPayload* {.
    sszActiveFields: [1, 0, 1, 1]
  .} = object
    magic*: TransactionType   # 0x05 (Auth)
    address*: Address
    nonce*: uint64

  RlpBasicAuthorizationPayload* {.
    sszActiveFields: [1, 1, 1, 1]
  .} = object
    magic*: TransactionType   # 0x05 (Auth)
    chain_id*: ChainId
    address*: Address
    nonce*: uint64

  AuthorizationKind*  = enum
    authReplayableBasic
    authBasic

  AuthorizationPayload* = object
    case kind*: AuthorizationKind
    of authReplayableBasic:
      replayable*: RlpReplayableBasicAuthorizationPayload
    of authBasic:
      basic*: RlpBasicAuthorizationPayload

  Authorization* = object
    payload*: AuthorizationPayload
    signature*: Secp256k1ExecutionSignature

type RlpSetCodeTransactionPayload* {.
  sszActiveFields: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
.} = object
  txType*: TransactionType
  chain_id*: ChainId
  nonce*: uint64
  max_fees_per_gas*: BasicFeesPerGas
  gas*: GasAmount
  to*: Address
  value*: UInt256
  input*: ProgressiveByteList
  access_list*: seq[AccessTuple]
  max_priority_fees_per_gas*: BasicFeesPerGas
  authorization_list*: seq[Authorization]

type
  RlpLegacyReplayableBasicTransaction* =
    SignedTx[RlpLegacyReplayableBasicTransactionPayload]
  RlpLegacyReplayableCreateTransaction* =
    SignedTx[RlpLegacyReplayableCreateTransactionPayload]
  RlpLegacyBasicTransaction* = SignedTx[RlpLegacyBasicTransactionPayload]
  RlpLegacyCreateTransaction* = SignedTx[RlpLegacyCreateTransactionPayload]
  RlpAccessListBasicTransaction* = SignedTx[RlpAccessListBasicTransactionPayload]
  RlpAccessListCreateTransaction* = SignedTx[RlpAccessListCreateTransactionPayload]
  RlpBasicTransaction* = SignedTx[RlpBasicTransactionPayload]
  RlpCreateTransaction* = SignedTx[RlpCreateTransactionPayload]
  RlpBlobTransaction* = SignedTx[RlpBlobTransactionPayload]
  RlpSetCodeTransaction* = SignedTx[RlpSetCodeTransactionPayload]

  # # This doesnt do the ssz encode/decode stuff so we keep it here for now to swap in later
  # AnyRlpTransaction* =
  #   RlpLegacyReplayableBasicTransaction | RlpLegacyReplayableCreateTransaction |
  #   RlpLegacyBasicTransaction | RlpLegacyCreateTransaction |
  #   RlpAccessListBasicTransaction | RlpAccessListCreateTransaction | RlpBasicTransaction |
  #   RlpCreateTransaction | RlpBlobTransaction | RlpSetCodeTransaction

type
  RLPTransactionKind*  = enum
    txLegacyReplayableBasic=0
    txLegacyReplayableCreate=1
    txLegacyBasic=2
    txLegacyCreate=3
    txAccessListBasic=4
    txAccessListCreate=5
    txBasic=6
    txCreate=7
    txBlob=8
    txSetCode=9

  RlpTransactionObject*  = object
    case kind*: RLPTransactionKind
    of txLegacyReplayableBasic:
      legacyReplayableBasic*: RlpLegacyReplayableBasicTransaction
    of txLegacyReplayableCreate:
      legacyReplayableCreate*: RlpLegacyReplayableCreateTransaction
    of txLegacyBasic:
      legacyBasic*: RlpLegacyBasicTransaction
    of txLegacyCreate:
      legacyCreate*: RlpLegacyCreateTransaction
    of txAccessListBasic:
      accessListBasic*: RlpAccessListBasicTransaction
    of txAccessListCreate:
      accessListCreate*: RlpAccessListCreateTransaction
    of txBasic:
      basic*: RlpBasicTransaction
    of txCreate:
      create*: RlpCreateTransaction
    of txBlob:
      blob*: RlpBlobTransaction
    of txSetCode:
      setCode*: RlpSetCodeTransaction

type
  TransactionKind* {.pure.} = enum
    TxNone=0
    RlpTransaction=1

  Transaction* = object
    case kind*: TransactionKind
    of TxNone:
      discard
    of RlpTransaction:
      rlp*: RlpTransactionObject

# Not importing from common/transaction as it would cause problem with the trensaction deffined in common/transactions
type
  AuthTuple* = tuple
    chain_id: ChainId
    address:  Address
    nonce:    uint64
    y_parity: uint8
    r:        UInt256
    s:        UInt256
