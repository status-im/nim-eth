import ssz_serialization
import stint
import ".."/common/[addresses, base, hashes]
import "."/utils

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
  RlpLegacyReplayableBasicTransactionPayload* = object
    txType*: TransactionType
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    to*: Address
    value*: UInt256
    input*: ProgressiveByteList

  RlpLegacyReplayableCreateTransactionPayload* = object
    txType*: TransactionType
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList

type
  RlpLegacyBasicTransactionPayload* = object
    txType*: TransactionType
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    to*: Address
    value*: UInt256
    input*: ProgressiveByteList

  RlpLegacyCreateTransactionPayload* = object
    txType*: TransactionType
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList

type RlpAccessListBasicTransactionPayload* = object
  txType*: TransactionType
  chain_id*: ChainId
  nonce*: uint64
  max_fees_per_gas*: BasicFeesPerGas
  gas*: GasAmount
  to*: Address
  value*: UInt256
  input*: ProgressiveByteList
  access_list*: seq[AccessTuple]

type RlpAccessListCreateTransactionPayload* = object
  txType*: TransactionType
  chain_id*: ChainId
  nonce*: uint64
  max_fees_per_gas*: BasicFeesPerGas
  gas*: GasAmount
  value*: UInt256
  input*: ProgressiveByteList
  access_list*: seq[AccessTuple]

type
  RlpBasicTransactionPayload* = object
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

  RlpCreateTransactionPayload* = object
    txType*: TransactionType
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList
    access_list*: seq[AccessTuple]
    max_priority_fees_per_gas*: BasicFeesPerGas

type RlpBlobTransactionPayload* = object
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
  RlpReplayableBasicAuthorizationPayload* = object
    magic*: TransactionType
    address*: Address
    nonce*: uint64

  RlpBasicAuthorizationPayload* = object
    magic*: TransactionType
    chain_id*: ChainId
    address*: Address
    nonce*: uint64

type
  AuthKind = enum ReplayableBasic, Basic

  RlpAuthorization* = object
    case kind*: AuthKind
    of ReplayableBasic: replayable*: RlpReplayableBasicAuthorizationPayload
    of Basic:      basic*: RlpBasicAuthorizationPayload

type RlpSetCodeTransactionPayload* = object
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
  authorization_list*: seq[RlpAuthorization]

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

type
  AnyRlpTransaction* =
    RlpLegacyReplayableBasicTransaction | RlpLegacyReplayableCreateTransaction |
    RlpLegacyBasicTransaction | RlpLegacyCreateTransaction |
    RlpAccessListBasicTransaction | RlpAccessListCreateTransaction | RlpBasicTransaction |
    RlpCreateTransaction | RlpBlobTransaction | RlpSetCodeTransaction

  Transaction* = AnyRlpTransaction
