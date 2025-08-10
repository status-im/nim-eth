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
  RlpAuthorizationTag* = enum
    ratReplayable = 0'u8
    ratBasic      = 1'u8

  RlpAuthorizationUnion* = object
    tag*: RlpAuthorizationTag
    payloadBytes*: seq[byte]

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
    authorization_list*: seq[RlpAuthorizationUnion]

  RlpSetCodeTransaction* = object
    payload*: RlpSetCodeTransactionPayload
    signature*: Secp256k1ExecutionSignature


type
  RlpTransactionTag* = enum
    rttLegacyReplayableBasic
    rttLegacyReplayableCreate
    rttLegacyBasic
    rttLegacyCreate
    rttAccessListBasic
    rttAccessListCreate
    rttBasic1559
    rttCreate1559
    rttBlob
    rttSetCode

  RlpTransactionUnion* = object
    tag*: RlpTransactionTag
    payloadBytes*: seq[byte]