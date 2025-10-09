import
  ssz_serialization,
  ./adapter,
   ../common/[addresses, hashes],
   ./transaction_ssz

const
  # Post-merge constants
  EMPTY_OMMERS_HASH* = hash32"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

type
  Withdrawal* {.sszActiveFields: [1, 1, 1, 1].} = object
      index*: uint64
      validatorIndex*: uint64
      address*: Address
      amount*: uint64

type
  GasAmounts* {.sszActiveFields: [1, 1].} = object
    regular*: uint64
    blob*: uint64

type
  BlobFeesPerGas* {.sszActiveFields: [1, 1].} = object
    regular*: uint64
    blob*: uint64

# EIP-7807: Execution Block Header
type
  Header* {.sszActiveFields: [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
  ].} = object
    parent_hash*: Root
    miner*: Address
    state_root*: Bytes32
    transactions_root*: Root
    receipts_root*: Root
    number*: uint64
    gas_limits*: GasAmounts
    gas_used*: GasAmounts
    timestamp*: uint64
    extra_data*: seq[uint8]
    mix_hash*: Bytes32
    base_fees_per_gas*: BlobFeesPerGas
    withdrawals_root*: Root                         # EIP-6465 hash_tree_root
    excess_gas*: GasAmounts
    parent_beacon_block_root*: Root
    requests_hash*: Bytes32                         # EIP-6110 hash_tree_root
    # Note: Field 16 (system_logs_root) not yet in use

  BlockBody* = object
    transactions*:  seq[Transaction]
    uncles*:        seq[Header]
    withdrawals*:   Opt[seq[Withdrawal]]   # EIP-4895

  Block* = object
    header*     : Header
    transactions*: seq[Transaction]
    uncles*     : seq[Header]
    withdrawals*: Opt[seq[Withdrawal]]   # EIP-4895

const
  EMPTY_UNCLE_HASH* = hash32"1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"

func init*(T: type Block, header: Header, body: BlockBody): T =
  T(
    header: header,
    transactions: body.transactions,
    uncles: body.uncles,
    withdrawals: body.withdrawals,
  )

template txs*(blk: Block): seq[Transaction] =
  blk.transactions

