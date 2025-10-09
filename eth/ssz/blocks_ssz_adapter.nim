import
  ssz_serialization,
  ssz_serialization/merkleization,
  ../common/[addresses, base, hashes, times,transactions,blocks,headers ],
  ./blocks_ssz,
  ./transaction_ssz,
  ./sszcodec

type
 Withdrawal_SSZ* = blocks_ssz.Withdrawal
 Header_SSZ* = blocks_ssz.Header
 BlockBody_SSZ* = blocks_ssz.BlockBody
 Block_SSZ* = blocks_ssz.Block
 Withdrawal_RLP* = blocks.Withdrawal
 Header_RLP* = headers.Header
 BlockBody_RLP* = blocks.BlockBody
 Block_RLP* = blocks.Block

proc toSszWithdrawal*(w: Withdrawal_RLP): Withdrawal_SSZ =
  Withdrawal_SSZ(
    index: w.index,
    validatorIndex: w.validatorIndex,
    address: w.address,
    amount: w.amount
  )

proc toSszHeader*(h: Header_RLP): Header_SSZ =
  var extraData: seq[uint8]
  for b in h.extraData:
    extraData.add(b)


  let blobBaseFee = if h.excessBlobGas.isSome and h.excessBlobGas.get > 0:
    # TODO: Proper calculation: fake_exponential(MIN_BASE_FEE_PER_BLOB_GAS, excess, denominator)
    1'u64
  else:
    0'u64

  Header_SSZ(
    parent_hash: h.parentHash,
    miner: h.coinbase,  # coinbase → miner (Engine API naming)
    state_root: h.stateRoot.Bytes32,
    transactions_root: h.transactionsRoot,
    receipts_root: h.receiptsRoot,
    number: h.number.uint64,
    gas_limits: blocks_ssz.GasAmounts(
      regular: h.gasLimit,
      blob: 0'u64
    ),
    gas_used: blocks_ssz.GasAmounts(
      regular: h.gasUsed,
      blob: if h.blobGasUsed.isSome: h.blobGasUsed.get else: 0'u64
    ),
    timestamp: h.timestamp.uint64,
    extra_data: extraData,
    mix_hash: h.mixHash,
    base_fees_per_gas: blocks_ssz.BlobFeesPerGas(
      regular: if h.baseFeePerGas.isSome: h.baseFeePerGas.get.truncate(uint64) else: 0'u64,
      blob: blobBaseFee
    ),
    withdrawals_root: if h.withdrawalsRoot.isSome:
      h.withdrawalsRoot.get
    else:
      default(Root),
    excess_gas: blocks_ssz.GasAmounts(
      regular: 0,  # Regular gas has no excess concept
      blob: if h.excessBlobGas.isSome: h.excessBlobGas.get else: 0'u64
    ),
    parent_beacon_block_root: if h.parentBeaconBlockRoot.isSome:
      h.parentBeaconBlockRoot.get
    else:
      default(Root),
    requests_hash: if h.requestsHash.isSome:
      h.requestsHash.get.Bytes32
    else:
      default(Bytes32)
  )

proc toSszBlockBody*(body: BlockBody_RLP): BlockBody_SSZ =
  var sszBody = BlockBody_SSZ()

  for tx in body.transactions:
    sszBody.transactions.add(toSszTx(tx))

  for uncle in body.uncles:
    sszBody.uncles.add(toSszHeader(uncle))

  if body.withdrawals.isSome:
    var withdrawalsList: seq[Withdrawal_SSZ]
    for w in body.withdrawals.get:
      withdrawalsList.add(toSszWithdrawal(w))
    sszBody.withdrawals = Opt.some(withdrawalsList)
  else:
    sszBody.withdrawals = Opt.none(seq[Withdrawal_SSZ])

  sszBody

proc toSszBlock*(blk: Block_RLP): Block_SSZ =
  var sszBlock = Block_SSZ()
  sszBlock.header = toSszHeader(blk.header)
  for tx in blk.transactions:
    sszBlock.transactions.add(toSszTx(tx))
  for uncle in blk.uncles:
    sszBlock.uncles.add(toSszHeader(uncle))
  if blk.withdrawals.isSome:
    var withdrawalsList: seq[Withdrawal_SSZ]
    for w in blk.withdrawals.get:
      withdrawalsList.add(toSszWithdrawal(w))
    sszBlock.withdrawals = Opt.some(withdrawalsList)
  else:
    sszBlock.withdrawals = Opt.none(seq[Withdrawal_SSZ])
  sszBlock

proc fromSszWithdrawal*(w: Withdrawal_SSZ): Withdrawal_RLP =
  Withdrawal_RLP(
    index: w.index,
    validatorIndex: w.validatorIndex,
    address: w.address,
    amount: w.amount
  )


proc fromSszHeader*(h: Header_SSZ): Header_RLP =

  var extraData: seq[byte]
  for b in h.extra_data:
    extraData.add(b)

  Header_RLP(
    parentHash: h.parent_hash,
    ommersHash: blocks_ssz.EMPTY_OMMERS_HASH,  # Constant post-merge
    coinbase: h.miner,  # miner → coinbase
    stateRoot: h.state_root.Hash32,
    transactionsRoot: h.transactions_root,
    receiptsRoot: h.receipts_root,
    logsBloom: default(Bloom),  # Not in minimal SSZ header
    difficulty: 0.u256,  # 0 post-merge
    number: h.number.BlockNumber,
    gasLimit: h.gas_limits.regular.GasInt,
    gasUsed: h.gas_used.regular.GasInt,
    timestamp: h.timestamp.EthTime,
    extraData: extraData,
    mixHash: h.mix_hash,
    nonce: default(Bytes8),  # 0 post-merge
    baseFeePerGas: if h.base_fees_per_gas.regular != 0:
      Opt.some(h.base_fees_per_gas.regular.u256)
    else:
      Opt.none(UInt256),
    withdrawalsRoot: if h.withdrawals_root != default(Root):
      Opt.some(h.withdrawals_root)
    else:
      Opt.none(Hash32),
    blobGasUsed: if h.gas_used.blob != 0:
      Opt.some(h.gas_used.blob)
    else:
      Opt.none(uint64),
    excessBlobGas: if h.excess_gas.blob != 0:
      Opt.some(h.excess_gas.blob)
    else:
      Opt.none(uint64),
    parentBeaconBlockRoot: if h.parent_beacon_block_root != default(Root):
      Opt.some(h.parent_beacon_block_root)
    else:
      Opt.none(Hash32),
    requestsHash: if h.requests_hash != default(Bytes32):
      Opt.some(h.requests_hash.Hash32)
    else:
      Opt.none(Hash32)
  )

proc fromSszBlockBody*(body: BlockBody_SSZ): BlockBody_RLP =
  var rlpBody = BlockBody_RLP()
  for tx in body.transactions:
    rlpBody.transactions.add(toOldTx(tx))
  for uncle in body.uncles:
    rlpBody.uncles.add(fromSszHeader(uncle))
  if body.withdrawals.isSome:
    var wds: seq[Withdrawal_RLP]
    for w in body.withdrawals.get:
      wds.add(fromSszWithdrawal(w))
    rlpBody.withdrawals = Opt.some(wds)
  else:
    rlpBody.withdrawals = Opt.none(seq[Withdrawal_RLP])

  rlpBody

proc fromSszBlock*(blk: Block_SSZ): Block_RLP =

  var rlpBlock = Block_RLP()
  rlpBlock.header = fromSszHeader(blk.header)
  for tx in blk.transactions:
    rlpBlock.transactions.add(toOldTx(tx))
  for uncle in blk.uncles:
    rlpBlock.uncles.add(fromSszHeader(uncle))
  if blk.withdrawals.isSome:
    var wds: seq[Withdrawal_RLP]
    for w in blk.withdrawals.get:
      wds.add(fromSszWithdrawal(w))
    rlpBlock.withdrawals = Opt.some(wds)
  else:
    rlpBlock.withdrawals = Opt.none(seq[Withdrawal_RLP])

  rlpBlock


proc computeTransactionsRootFromRlp*(txs: seq[transactions.Transaction]): Root =
  var sszTxs: seq[transaction_ssz.Transaction]
  for tx in txs:
    sszTxs.add(toSszTx(tx))
  Hash32(sszTxs.hash_tree_root().data)

proc computeWithdrawalsRootFromRlp*(withdrawals: Opt[seq[Withdrawal_RLP]]): Root =
  if withdrawals.isNone:
    return default(Root)

  var sszWds: seq[Withdrawal_SSZ]
  for w in withdrawals.get:
    sszWds.add(toSszWithdrawal(w))
  Hash32(sszWds.hash_tree_root().data)

proc computeBlockHashSsz*(blk: Block_RLP): Hash32 =
  ## EIP-7807: Compute SSZ-based block hash from RLP block
  let sszHeader = toSszHeader(blk.header)
  Hash32(sszHeader.hash_tree_root().data)

proc computeBlockHashSsz*(header: Header_RLP): Hash32 =
  ## EIP-7807: Compute SSZ-based block hash from RLP header
  let sszHeader = toSszHeader(header)
  Hash32(sszHeader.hash_tree_root().data)
