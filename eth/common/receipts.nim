import "."/[addresses, base, hashes, transactions]

export addresses, base, hash, transactions

type
  Topic* = Bytes32
  # topic can be Hash32 or zero padded bytes array

  Log* = object
    address*:       Address
    topics*:        seq[Topic]
    data*:          seq[byte]

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
    logsBloom*        : Bloom
    logs*             : seq[Log]

const
  LegacyReceipt*  = TxLegacy
  Eip2930Receipt* = TxEip2930
  Eip1559Receipt* = TxEip1559
  Eip4844Receipt* = TxEip4844
  Eip7702Receipt* = TxEip7702

func hasStatus*(rec: Receipt): bool {.inline.} =
  rec.isHash == false

func hasStateRoot*(rec: Receipt): bool {.inline.} =
  rec.isHash == true

func stateRoot*(rec: Receipt): Hash32 {.inline.} =
  doAssert(rec.hasStateRoot)
  rec.hash
