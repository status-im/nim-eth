import ssz_serialization, ".."/common/[addresses, base, hashes] # "."/codec

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

  Receipt* = BasicReceipt | CreateReceipt | SetCodeReceipt
