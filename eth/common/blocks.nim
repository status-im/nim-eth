import "."/[addresses, base, headers, transactions]

export addresses, base, headers, transactions

type
  Withdrawal* = object  # EIP-4895
    index*         : uint64
    validatorIndex*: uint64
    address*       : Address
    amount*        : uint64

  DepositRequest* = object  # EIP-6110
    pubkey*               : Bytes48
    withdrawalCredentials*: Bytes32
    amount*               : uint64
    signature*            : Bytes96
    index*                : uint64

  WithdrawalRequest* = object  # EIP-7002
    sourceAddress*  : Address
    validatorPubkey*: Bytes48
    amount*         : uint64

  ConsolidationRequest* = object  # EIP-7251
    sourceAddress*: Address
    sourcePubkey* : Bytes48
    targetPubkey* : Bytes48


  RequestType* = enum
    DepositRequestType        # EIP-6110
    WithdrawalRequestType     # EIP-7002
    ConsolidationRequestType  # EIP-7251

  Request* = object
    case requestType*: RequestType
    of DepositRequestType:
      deposit*: DepositRequest
    of WithdrawalRequestType:
      withdrawal*: WithdrawalRequest
    of ConsolidationRequestType:
      consolidation*: ConsolidationRequest

  BlockBody* = object
    transactions*:  seq[Transaction]
    uncles*:        seq[Header]
    withdrawals*:   Opt[seq[Withdrawal]]   # EIP-4895
    requests*:      Opt[seq[Request]]      # EIP-7865

  Block* = object
    header*     : Header
    transactions*: seq[Transaction]
    uncles*     : seq[Header]
    withdrawals*: Opt[seq[Withdrawal]]   # EIP-4895
    requests*:    Opt[seq[Request]]      # EIP-7865

const
  EMPTY_UNCLE_HASH* = hash32"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

# TODO https://github.com/nim-lang/Nim/issues/23354 - parameters should be sink
func init*(T: type Block, header: Header, body: BlockBody): T =
  T(
    header: header,
    transactions: body.transactions,
    uncles: body.uncles,
    withdrawals: body.withdrawals,
  )

template txs*(blk: Block): seq[Transaction] =
  # Legacy name emulation
  blk.transactions

func `==`*(a, b: Request): bool =
  if a.requestType != b.requestType:
    return false

  case a.requestType
  of DepositRequestType:
    a.deposit == b.deposit
  of WithdrawalRequestType:
    a.withdrawal == b.withdrawal
  of ConsolidationRequestType:
    a.consolidation == b.consolidation
