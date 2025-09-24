import
  ssz_serialization,
  ./adapter,
  ../common/[addresses, hashes]

const MAX_TOPICS_PER_LOG* = 4

type
  GasAmount* = uint64

  Log* = object
    address*: Address
    topics*: List[Hash32, MAX_TOPICS_PER_LOG]
    data*: seq[byte]

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

  #Run time ->ssz + collections
  ReceiptKind* {.pure.} = enum
    rBasic = 0
    rCreate = 1
    rSetCode = 2

  Receipt*  = object
    case kind*: ReceiptKind
    of rBasic: basic*: BasicReceipt
    of rCreate: create*: CreateReceipt
    of rSetCode: setcode*: SetCodeReceipt

converter toReceipt*(r: BasicReceipt): Receipt =
  Receipt(kind: rBasic, basic: r)

converter toReceipt*(r: CreateReceipt): Receipt =
  Receipt(kind: rCreate, create: r)

converter toReceipt*(r: SetCodeReceipt): Receipt =
  Receipt(kind: rSetCode, setcode: r)
