import 
  ssz_serialization, 
  ".."/common/[addresses, base, hashes]
  # "."/codec

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
  
  # Compile time type
  Receipt* = BasicReceipt | CreateReceipt | SetCodeReceipt
  
  #Run time ->ssz + collections
  ReceiptKind* = enum rBasic, rCreate, rSetCode
  
  ReceiptTagged* = object
    case kind*: ReceiptKind
    of rBasic:   basic*:  BasicReceipt
    of rCreate:  create*: CreateReceipt
    of rSetCode: setcode*: SetCodeReceipt

# ---- wrap/unwrap between the union arms and the tagged wrapper ----
func asTagged*[T: Receipt](x: T): ReceiptTagged =
  when T is BasicReceipt:
    ReceiptTagged(kind: rBasic, basic: x)
  elif T is CreateReceipt:
    ReceiptTagged(kind: rCreate, create: x)
  else:
    ReceiptTagged(kind: rSetCode, setcode: x)

func fromTagged*[T: Receipt](r: ReceiptTagged): T =
  when T is BasicReceipt:
    doAssert r.kind == rBasic;   r.basic
  elif T is CreateReceipt:
    doAssert r.kind == rCreate;  r.create
  else:
    doAssert r.kind == rSetCode; r.setcode

proc encodeReceipt*[T: Receipt](x: T): seq[byte] =
  SSZ.encode(asTagged(x))

proc decodeReceipt*[T: Receipt](bytes: openArray[byte]): T =
  let tagged = SSZ.decode(@bytes, ReceiptTagged)
  fromTagged[T](tagged)

proc addAny*[T: Receipt](dst: var seq[ReceiptTagged], x: T) =
  dst.add asTagged(x)

