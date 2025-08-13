import ssz_serialization
import stint
import ".."/common/[addresses, base, hashes]
import "."/codec

const
  MAX_TOPICS_PER_LOG* = 4

type
  Log* = object
    address*: Address                             
    topics*: List[Hash32, MAX_TOPICS_PER_LOG]
    data*: seq[byte]

type
  GasAmount* = uint64

  BasicReceipt* = object
    `from`*: Address
    gas_used*: GasAmount
    contract_address*: Address        
    logs*: seq[Log]                 
    status*: bool

  CreateReceipt* = object
    `from`*: Address
    gas_used*: GasAmount
    contract_address*: Address
    logs*: seq[Log]
    status*: bool

  SetCodeReceipt* = object
    `from`*: Address
    gas_used*: GasAmount
    contract_address*: Address
    logs*: seq[Log]
    status*: bool
    authorities*: seq[Address]     

  ReceiptKind* {.pure.} = enum
    rkBasic = 0
    rkCreate = 1
    rkSetCode = 2

  Receipt* = object
    case kind*: ReceiptKind
    of rkBasic:   basic*:  BasicReceipt
    of rkCreate:  create*: CreateReceipt
    of rkSetCode: setcode*: SetCodeReceipt



proc zeroAddress*: Address =
  zeroAddress

proc makeBasicReceipt*(
  fromAddr: Address,
  gasUsed: GasAmount,
  logs: seq[Log],
  status: bool
): Receipt =
  Receipt(
    kind: rkBasic,
    basic: BasicReceipt(
      `from`: fromAddr,
      gas_used: gasUsed,
      contract_address: zeroAddress(),
      logs: logs,
      status: status
    )
  )

proc makeCreateReceipt*(
  fromAddr: Address,
  gasUsed: GasAmount,
  contractAddr: Address,
  logs: seq[Log],
  status: bool
): Receipt =
  Receipt(
    kind: rkCreate,
    create: CreateReceipt(
      `from`: fromAddr,
      gas_used: gasUsed,
      contract_address: contractAddr,
      logs: logs,
      status: status
    )
  )

proc makeSetCodeReceipt*(
  fromAddr: Address,
  gasUsed: GasAmount,
  authorities: seq[Address],
  logs: seq[Log],
  status: bool
): Receipt =
  Receipt(
    kind: rkSetCode,
    setcode: SetCodeReceipt(
      `from`: fromAddr,
      gas_used: gasUsed,
      contract_address: zeroAddress(),
      logs: logs,
      status: status,
      authorities: authorities
    )
  )


# proc receiptsRoot*(receipts: seq[Receipt]): Hash32 =
#   result = hash_tree_root(receipts)
