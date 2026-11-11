# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## RLP decoding benchmark. Deliberately *not* part of `all_tests` - it measures
## rather than asserts, and timings are too machine-dependent to gate CI on.
##
## Build and run:
##
##   nim c -r -d:release tests/rlp/bench_rlp_decode.nim [filter]
##
## `filter`, if given, only runs the cases whose name contains it.
##
## Pin to a core for stable numbers, e.g. `taskset -c 2`. On hybrid CPUs, make
## sure that it is a performance core. Each row is the median of several runs;
## differences of a few percent between builds are within the noise.
##
## Every case goes through the public API that callers use - mostly
## `rlp.decode` - so the input copy made by `rlpFromBytes` is part of the cost.
##
## Columns, in order:
##
##   bytes   size of the RLP input
##   ns/op   nanoseconds per decode of the whole input
##   MB/s    input bytes decoded per second

import
  std/[algorithm, monotimes, os, strformat, strutils, times],
  stew/io2,
  ../../eth/common/[eth_types_rlp, transactions_rlp, receipts_rlp]

type
  Case = object
    name: string
    input: seq[byte]
    run: proc(input: seq[byte]): uint64 {.nimcall, raises: [RlpError].}
      ## Decodes `input` once, returns a value that depends on the result so
      ## that the decode cannot be optimised away

const
  Samples = 7
  MinSampleTime = initDuration(milliseconds = 20)

var sink: uint64

func digest[T](v: T): uint64 =
  when T is SomeUnsignedInt:
    uint64(v)
  else:
    uint64(cast[ptr byte](unsafeAddr v)[])

# Deterministic, non-zero filler so that no field gets a short encoding by
# accident (and so that integers are canonical).
func filler(n: int, seed: int): seq[byte] =
  result = newSeq[byte](n)
  var x = uint32(seed) * 2654435761'u32 + 1
  for i in 0 ..< n:
    x = x * 1103515245'u32 + 12345'u32
    result[i] = byte(x shr 24) or 1

func hash(seed: int): Hash32 =
  Hash32.copyFrom(filler(32, seed))

func address(seed: int): Address =
  Address.copyFrom(filler(20, seed))

func u256(n: int, seed: int): UInt256 =
  UInt256.fromBytesBE(filler(n, seed))

func bloom(seed: int): Bloom =
  Bloom.copyFrom(filler(256, seed))

func pragueHeader(): Header =
  Header(
    parentHash: hash(1),
    ommersHash: EMPTY_UNCLE_HASH,
    coinbase: address(2),
    stateRoot: hash(3),
    transactionsRoot: hash(4),
    receiptsRoot: hash(5),
    logsBloom: bloom(6),
    difficulty: 0.u256,
    number: 22_000_000'u64,
    gasLimit: 36_000_000'u64,
    gasUsed: 17_123_456'u64,
    timestamp: EthTime(1_745_000_000),
    extraData: @(toOpenArrayByte("beaverbuild.org", 0, 14)),
    mixHash: Bytes32.copyFrom(filler(32, 7)),
    nonce: default(Bytes8),
    baseFeePerGas: Opt.some(1_234_567_890.u256),
    withdrawalsRoot: Opt.some(hash(8)),
    blobGasUsed: Opt.some(393_216'u64),
    excessBlobGas: Opt.some(12_345_678'u64),
    parentBeaconBlockRoot: Opt.some(hash(9)),
    requestsHash: Opt.some(hash(10)),
  )

func accessList(seed: int): AccessList =
  for i in 0 ..< 2:
    result.add AccessPair(
      address: address(seed + i),
      storageKeys: @[Bytes32.copyFrom(filler(32, seed + i + 100)),
                     Bytes32.copyFrom(filler(32, seed + i + 200))],
    )

func legacyTx(seed: int): Transaction =
  # EIP-155 ERC-20 transfer
  Transaction(
    txType: TxLegacy,
    chainId: 1.u256,
    nonce: 1234'u64,
    gasPrice: 20_000_000_000'u64,
    gasLimit: 65_000'u64,
    to: Opt.some(address(seed)),
    value: 0.u256,
    payload: filler(68, seed),
    V: 37'u64,
    R: u256(32, seed + 1),
    S: u256(32, seed + 2),
  )

func eip1559Tx(seed: int): Transaction =
  Transaction(
    txType: TxEip1559,
    chainId: 1.u256,
    nonce: 1234'u64,
    maxPriorityFeePerGas: 1_000_000_000'u64,
    maxFeePerGas: 30_000_000_000'u64,
    gasLimit: 120_000'u64,
    to: Opt.some(address(seed)),
    value: u256(8, seed),
    payload: filler(68, seed),
    accessList: accessList(seed),
    V: 1'u64,
    R: u256(32, seed + 1),
    S: u256(32, seed + 2),
  )

func eip4844Tx(seed: int): Transaction =
  result = eip1559Tx(seed)
  result.txType = TxEip4844
  result.accessList = @[]
  result.maxFeePerBlobGas = 1_000_000_000.u256
  result.versionedHashes = @[hash(seed + 3), hash(seed + 4)]

func receipt(seed: int): Receipt =
  var logs: seq[Log]
  for i in 0 ..< 2:
    logs.add Log(
      address: address(seed + i),
      topics: @[Bytes32.copyFrom(filler(32, seed + i)),
                Bytes32.copyFrom(filler(32, seed + i + 1)),
                Bytes32.copyFrom(filler(32, seed + i + 2))],
      data: filler(32, seed + i),
    )
  Receipt(
    receiptType: Eip1559Receipt,
    status: true,
    cumulativeGasUsed: 1_234_567'u64,
    logsBloom: bloom(seed),
    logs: logs,
  )

func storedReceipt(r: Receipt): StoredReceipt =
  StoredReceipt(
    receiptType: r.receiptType,
    status: r.status,
    cumulativeGasUsed: r.cumulativeGasUsed,
    logs: r.logs,
  )

func branchNode(): seq[byte] =
  # Hexary trie branch node: 16 children, 12 of them hash references, plus an
  # empty value slot
  var w = initRlpList(17)
  for i in 0 ..< 16:
    if i mod 4 == 3:
      w.append(newSeq[byte]())
    else:
      w.append(hash(i))
  w.append(newSeq[byte]())
  w.finish()

template decodeCase(label: string, value: untyped, T: type): Case =
  ## A case that decodes `encode(value)` as `T`, after checking that this
  ## round-trips: a benchmark of a wrong decoder is worse than no benchmark.
  let input = rlp.encode(value)
  doAssert rlp.encode(rlp.decode(input, T)) == input, label
  Case(
    name: label,
    input: input,
    run: proc(input: seq[byte]): uint64 {.nimcall, raises: [RlpError].} =
      digest(rlp.decode(input, T)),
  )

proc readBlocks(input: seq[byte]): uint64 {.raises: [RlpError].} =
  var rlp = rlpFromBytes(input)
  while rlp.hasData:
    result += rlp.read(EthBlock).header.number

proc walkBranch(input: seq[byte]): uint64 {.raises: [RlpError].} =
  # The access pattern of `hexary.getKeysAux` and friends
  let node = rlpFromBytes(input)
  doAssert node.listLen == 17
  for i in 0 ..< 16:
    let branch = node.listElem(i)
    if not branch.isEmpty:
      result += uint64(branch.toBytes()[0])

proc iterateList(input: seq[byte]): uint64 {.raises: [RlpError].} =
  var rlp = rlpFromBytes(input)
  for elem in rlp:
    result += uint64(elem.blobLen)

proc cases(): seq[Case] =
  let
    header = pragueHeader()
    txs = block:
      var txs: seq[Transaction]
      for i in 0 ..< 200:
        txs.add(if i mod 10 == 0: legacyTx(i) else: eip1559Tx(i))
      txs
    receipts = block:
      var receipts: seq[Receipt]
      for i in 0 ..< 200:
        receipts.add receipt(i)
      receipts
    storedReceipts = block:
      var stored: seq[StoredReceipt]
      for r in receipts:
        stored.add storedReceipt(r)
      stored
    hashes = block:
      var hashes: seq[Hash32]
      for i in 0 ..< 1000:
        hashes.add hash(i)
      hashes

  result.add decodeCase("uint64", 0x0123456789abcdef'u64, uint64)
  result.add decodeCase("UInt256 (8 bytes)", u256(8, 1), UInt256)
  result.add decodeCase("UInt256 (32 bytes)", u256(32, 1), UInt256)
  result.add decodeCase("Hash32", hash(1), Hash32)
  result.add decodeCase("seq[byte] (100 bytes)", filler(100, 1), seq[byte])
  result.add decodeCase("Account", Account(
    nonce: 12'u64,
    balance: u256(9, 1),
    storageRoot: hash(1),
    codeHash: hash(2)), Account)
  result.add decodeCase("Header (Prague)", header, Header)
  result.add decodeCase("Transaction (legacy)", legacyTx(1), Transaction)
  result.add decodeCase("Transaction (EIP-1559)", eip1559Tx(1), Transaction)
  result.add decodeCase("Transaction (EIP-4844)", eip4844Tx(1), Transaction)
  result.add decodeCase("Receipt (EIP-1559)", receipt(1), Receipt)
  result.add decodeCase("seq[Transaction] x200", txs, seq[Transaction])
  result.add decodeCase("seq[Receipt] x200", receipts, seq[Receipt])
  result.add decodeCase("seq[StoredReceipt] x200", storedReceipts,
                        seq[StoredReceipt])
  result.add decodeCase("seq[Hash32] x1000", hashes, seq[Hash32])

  # Real chain data: blocks 1..1024 of a test chain - 11264 transactions, all
  # of them legacy, and no uncles
  let blocksFile = currentSourcePath.parentDir / ".." / "common" / "rlps" /
                   "blocks_1024_td_135112316.rlp"
  let blocks = io2.readAllBytes(blocksFile).valueOr:
    raiseAssert "cannot read " & blocksFile & ": " & ioErrorMsg(error)
  result.add Case(name: "EthBlock x1024 (chain file)", input: blocks,
                  run: readBlocks)

  # Generic `Rlp` traversal, as used by the trie and p2p code
  result.add Case(name: "branch node walk (listElem)", input: branchNode(),
                  run: walkBranch)
  result.add Case(name: "iterate list x1000 (items)", input: rlp.encode(hashes),
                  run: iterateList)

proc timeRun(c: Case, iters: int): Duration {.raises: [RlpError].} =
  let t0 = getMonoTime()
  for _ in 0 ..< iters:
    sink = sink xor c.run(c.input)
  getMonoTime() - t0

proc measure(c: Case): float {.raises: [RlpError].} =
  ## Median nanoseconds per run, over `Samples` samples of at least
  ## `MinSampleTime` each. The calibration doubles as warm-up.
  var iters = 1
  while c.timeRun(iters) < MinSampleTime:
    iters *= 2

  var samples: array[Samples, float]
  for s in samples.mitems:
    s = float(c.timeRun(iters).inNanoseconds) / float(iters)
  samples.sort()
  samples[Samples div 2]

proc main() {.raises: [RlpError, ValueError].} =
  let filter = if paramCount() >= 1: paramStr(1) else: ""

  echo "RLP decoding, median of ", Samples, " samples (lower ns/op is better)"
  echo ""
  echo &"""{"case":<30} {"bytes":>9} {"ns/op":>13} {"MB/s":>9}"""
  echo "-".repeat(64)

  for c in cases():
    if filter.len > 0 and filter notin c.name:
      continue
    let
      ns = c.measure()
      mbps = float(c.input.len) / ns * 1000.0
    echo &"{c.name:<30} {c.input.len:>9} {ns:>13.1f} {mbps:>9.1f}"

  echo "-".repeat(64)

  if sink == 0xff'u64:
    echo ""

when isMainModule:
  main()
