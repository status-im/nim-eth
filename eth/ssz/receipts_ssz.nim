import
  sequtils,
  ssz_serialization,
  ./adapter,
  ../common/[addresses, hashes],
  ../common/receipts as rlp_receipts

const MAX_TOPICS_PER_LOG* = 4

type
  GasAmount* = uint64

  Log* = object
    address*: Address
    topics*: List[Bytes32, MAX_TOPICS_PER_LOG]
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

  ReceiptKind* = enum
    rBasic = 0
    rCreate = 1
    rSetCode = 2

  Receipt* = object
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

proc toSszReceipt*(
    rec: rlp_receipts.StoredReceipt,
    sender: Address,
    gasUsed: uint64,
    contractAddress: Address,
    authorities: seq[Address],
): Receipt =
  # Convert logs from rlp_receipts.Log to ssz_receipts.Log
  # the problem is its seq[log] in common/receipts but ssz_receipts.Log
  # has a fixed size array for topics,which decides how the ssz serialization will happen
  var sszLogs: seq[Log] = @[]
  for log in rec.logs:
    let topicsList = List[Bytes32, MAX_TOPICS_PER_LOG].init(
      log.topics[0 ..< min(log.topics.len, MAX_TOPICS_PER_LOG)].mapIt(Bytes32(it))
    )
    sszLogs.add(Log(address: log.address, topics: topicsList, data: log.data))
  if authorities.len > 0:
    let sszRec = SetCodeReceipt(
      `from`: sender,
      gas_used: gasUsed,
      contract_address: contractAddress,
      logs: sszLogs,
      status: rec.status,
      authorities: authorities,
    )
    return sszRec.toReceipt()
  elif contractAddress != default(Address):
    let sszRec = CreateReceipt(
      `from`: sender,
      gas_used: gasUsed,
      contract_address: contractAddress,
      logs: sszLogs,
      status: rec.status,
    )
    return sszRec.toReceipt()
  else:
    let sszRec = BasicReceipt(
      `from`: sender,
      gas_used: gasUsed,
      contract_address: default(Address),
      logs: sszLogs,
      status: rec.status,
    )
    return sszRec.toReceipt()
