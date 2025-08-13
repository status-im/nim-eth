import ssz_serialization
import stint         
import ".."/common/[addresses, base, hashes]  
import "."/utils

type
  TransactionType* = uint8
  GasAmount*       = uint64
  FeePerGas*       = UInt256        
  ProgressiveByteList* = seq[byte]     

const
  TxLegacy*       : TransactionType = 00'u8   
  TxAccessList*   : TransactionType = 01'u8  
  TxDynamicFee*   : TransactionType = 02'u8   
  TxBlob*         : TransactionType = 03'u8   
  TxSetCode*      : TransactionType = 04'u8  
  AuthMagic7702*  : TransactionType = 05'u8 

type
  BasicFeesPerGas* = object
    regular*: FeePerGas

  BlobFeesPerGas* = object
    regular*: FeePerGas
    blob*:    FeePerGas

type
  AccessTuple* = object
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

  RlpLegacyReplayableBasicTransaction* = object
    payload*: RlpLegacyReplayableBasicTransactionPayload
    signature*: Secp256k1ExecutionSignature

  RlpLegacyReplayableCreateTransactionPayload* = object
    txType*: TransactionType            
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList

  RlpLegacyReplayableCreateTransaction* = object
    payload*: RlpLegacyReplayableCreateTransactionPayload
    signature*: Secp256k1ExecutionSignature


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

  RlpLegacyBasicTransaction* = object
    payload*: RlpLegacyBasicTransactionPayload
    signature*: Secp256k1ExecutionSignature

  RlpLegacyCreateTransactionPayload* = object
    txType*: TransactionType            
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList

  RlpLegacyCreateTransaction* = object
    payload*: RlpLegacyCreateTransactionPayload
    signature*: Secp256k1ExecutionSignature

type
  RlpAccessListBasicTransactionPayload* = object
    txType*: TransactionType            
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    to*: Address
    value*: UInt256
    input*: ProgressiveByteList
    access_list*: seq[AccessTuple]



  RlpAccessListCreateTransactionPayload* = object
    txType*: TransactionType            
    chain_id*: ChainId
    nonce*: uint64
    max_fees_per_gas*: BasicFeesPerGas
    gas*: GasAmount
    value*: UInt256
    input*: ProgressiveByteList
    access_list*: seq[AccessTuple]

  RlpAccessListCreateTransaction* = object
    payload*: RlpAccessListCreateTransactionPayload
    signature*: Secp256k1ExecutionSignature


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

  RlpBasicTransaction* = object
    payload*: RlpBasicTransactionPayload
    signature*: Secp256k1ExecutionSignature

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

  RlpCreateTransaction* = object
    payload*: RlpCreateTransactionPayload
    signature*: Secp256k1ExecutionSignature

type
  RlpBlobTransactionPayload* = object
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

  RlpBlobTransaction* = object
    payload*: RlpBlobTransactionPayload
    signature*: Secp256k1ExecutionSignature


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
  RlpAuthorizationKind* {.pure.} = enum
    ratReplayable = 0'u8
    ratBasic      = 1'u8

  RlpAuthorization* = object
    case kind*: RlpAuthorizationKind
    of replayable: replayableAuth*: RlpReplayableBasicAuthorizationPayload
    of basic:      basicAuth*:      RlpBasicAuthorizationPayload

type
  RlpSetCodeTransactionPayload* = object
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

  RlpSetCodeTransaction* = object
    payload*: RlpSetCodeTransactionPayload
    signature*: Secp256k1ExecutionSignature


type
# the compilet would do these on thier own but still to be safe
  RlpTransactionKind* {.pure.} = enum
    legacyReplayableBasic = 0
    legacyReplayableCreate = 1
    legacyBasic            = 2
    legacyCreate           = 3
    accessListBasic        = 4
    accessListCreate       = 5
    basic1559              = 6
    create1559             = 7
    blob4844               = 8
    setCode7702            = 9

  RlpTransaction* = object
    case kind*: RlpTransactionKind
    of legacyReplayableBasic:  legacyReplayableBasicTx*: RlpLegacyReplayableBasicTransaction
    of legacyReplayableCreate: legacyReplayableCreateTx*: RlpLegacyReplayableCreateTransaction
    of legacyBasic:            legacyBasicTx*: RlpLegacyBasicTransaction
    of legacyCreate:           legacyCreateTx*: RlpLegacyCreateTransaction
    of accessListBasic:        accessListBasicTx*: RlpAccessListBasicTransaction
    of accessListCreate:       accessListCreateTx*: RlpAccessListCreateTransaction
    of basic1559:              basic1559Tx*: RlpBasicTransaction
    of create1559:             create1559Tx*: RlpCreateTransaction
    of blob4844:               blobTx*: RlpBlobTransaction
    of setCode7702:            setCodeTx*: RlpSetCodeTransaction

type
  TransactionKind* {.pure.} = enum txRlp = 0
  Transaction* = object
    case kind*: TransactionKind
    of txRlp: rlp*: RlpTransaction
