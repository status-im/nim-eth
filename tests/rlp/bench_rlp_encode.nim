# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## RLP encoding benchmark. Deliberately *not* part of `all_tests` - it measures
## rather than asserts, and timings are too machine-dependent to gate CI on.
##
## Build and run:
##
##   nim c -r -d:release tests/rlp/bench_rlp_encode.nim [filter]
##
## `filter`, if given, only runs the cases whose name contains it.
##
## Pin to a core for stable numbers, e.g. `taskset -c 2`. On hybrid CPUs, make
## sure that it is a performance core. Each row is the median of several runs;
## differences of a few percent between builds are within the noise.
##
## Cases are grouped by the entry point that nimbus-eth1 uses:
##
##   encode    `rlp.encode` - length tracker pass + two-pass writer
##   hash      `computeRlpHash` - length tracker pass + hash writer
##   keccak    `keccak256(rlp.encode(v))`, the alternative to `hash`
##   length    `getEncodedLength` - length tracker pass only
##   default   `initRlpWriter`/`initRlpList` + `finish` - the single-pass
##             writer that shifts list payloads to fit their prefix
##   arraybuf  `RlpArrayBufWriter`, the stack-allocated single-pass writer,
##             used the way aristo encodes trie nodes
##   signing   `rlpHashForSigning`, the hash used for sender recovery
##   trie      `orderedTrieRoot`, as used for the transactions and receipts
##             roots of a block
##
## Columns, in order:
##
##   bytes   size of the RLP output
##   ns/op   nanoseconds per encode of the whole value
##   MB/s    output bytes produced per second

import
  std/[algorithm, monotimes, os, strformat, strutils, times],
  stew/io2,
  ../../eth/common/[eth_types_rlp, transactions_rlp, receipts_rlp],
  ../../eth/trie/ordered_trie

type
  Case = object
    name: string
    bytes: int
    run: proc(): uint64 {.closure, raises: [].}
      ## Encodes once, returns a value that depends on the result so that the
      ## encode cannot be optimised away

const
  Samples = 7
  MinSampleTime = initDuration(milliseconds = 20)

var sink: uint64

func digest(v: openArray[byte]): uint64 =
  uint64(v.len) + uint64(v[v.len div 2])

func digest(v: Hash32): uint64 =
  uint64(v.data[0])

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

func account(): Account =
  Account(
    nonce: 12'u64,
    balance: u256(9, 1),
    storageRoot: hash(1),
    codeHash: hash(2))

const emptyBlob: seq[byte] = @[]

template appendBranch(w: untyped) =
  # Hexary trie branch node: 16 children, 12 of them hash references, plus an
  # empty value slot
  w.startList(17)
  for i in 0 ..< 16:
    if i mod 4 == 3:
      w.append(emptyBlob)
    else:
      w.append(hashes[i])
  w.append(emptyBlob)

template encodeCase(label: string, value: untyped): Case =
  let v = value
  Case(
    name: "encode " & label,
    bytes: rlp.encode(v).len,
    run: proc(): uint64 {.closure, raises: [].} =
      digest(rlp.encode(v)),
  )

template hashCase(label: string, value: untyped): Case =
  let v = value
  doAssert computeRlpHash(v) == keccak256(rlp.encode(v)), label
  Case(
    name: "hash " & label,
    bytes: rlp.encode(v).len,
    run: proc(): uint64 {.closure, raises: [].} =
      digest(computeRlpHash(v)),
  )

template keccakCase(label: string, value: untyped): Case =
  let v = value
  Case(
    name: "keccak " & label,
    bytes: rlp.encode(v).len,
    run: proc(): uint64 {.closure, raises: [].} =
      digest(keccak256(rlp.encode(v))),
  )

template lengthCase(label: string, value: untyped): Case =
  let v = value
  doAssert getEncodedLength(v) == rlp.encode(v).len, label
  Case(
    name: "length " & label,
    bytes: rlp.encode(v).len,
    run: proc(): uint64 {.closure, raises: [].} =
      uint64(getEncodedLength(v)),
  )

template defaultCase(label: string, value: untyped): Case =
  let v = value
  doAssert (block:
    var w = initRlpWriter()
    w.append(v)
    w.finish) == rlp.encode(v), label
  Case(
    name: "default " & label,
    bytes: rlp.encode(v).len,
    run: proc(): uint64 {.closure, raises: [].} =
      var w = initRlpWriter()
      w.append(v)
      digest(w.finish),
  )

template signingCase(label: string, value: untyped): Case =
  let v = value
  Case(
    name: "signing " & label,
    bytes: encodeForSigning(v, v.isEip155).len,
    run: proc(): uint64 {.closure, raises: [].} =
      digest(rlpHashForSigning(v, v.isEip155)),
  )

proc cases(): seq[Case] {.raises: [RlpError].} =
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

  # Real chain data: blocks 1..1024 of a test chain - 11264 transactions, all
  # of them legacy, and no uncles
  let
    blocksFile = currentSourcePath.parentDir / ".." / "common" / "rlps" /
                 "blocks_1024_td_135112316.rlp"
    blocksRlp = io2.readAllBytes(blocksFile).valueOr:
      raiseAssert "cannot read " & blocksFile & ": " & ioErrorMsg(error)
    blocks = block:
      var
        r = rlpFromBytes(blocksRlp)
        blocks: seq[EthBlock]
      while r.hasData:
        blocks.add r.read(EthBlock)
      blocks
    chainTxs = block:
      var txs: seq[Transaction]
      for b in blocks:
        txs.add b.transactions
      txs

  # rlp.encode
  result.add encodeCase("uint64", 0x0123456789abcdef'u64)
  result.add encodeCase("UInt256 (32 bytes)", u256(32, 1))
  result.add encodeCase("Hash32", hash(1))
  result.add encodeCase("seq[byte] (100 bytes)", filler(100, 1))
  result.add encodeCase("Account", account())
  result.add encodeCase("Header (Prague)", header)
  result.add encodeCase("Transaction (legacy)", legacyTx(1))
  result.add encodeCase("Transaction (EIP-1559)", eip1559Tx(1))
  result.add encodeCase("Transaction (EIP-4844)", eip4844Tx(1))
  result.add encodeCase("Receipt (EIP-1559)", receipt(1))
  result.add encodeCase("StoredReceipt", storedReceipt(receipt(1)))
  result.add encodeCase("seq[Transaction] x200", txs)
  result.add encodeCase("seq[Receipt] x200", receipts)
  result.add encodeCase("seq[StoredReceipt] x200", storedReceipts)
  result.add encodeCase("seq[Hash32] x1000", hashes)
  result.add Case(
    name: "encode EthBlock x1024 (chain)",
    bytes: blocksRlp.len,
    run: proc(): uint64 {.closure, raises: [].} =
      for b in blocks:
        result += digest(rlp.encode(b)),
  )
  doAssert (block:
    var all: seq[byte]
    for b in blocks:
      all.add rlp.encode(b)
    all) == blocksRlp

  # computeRlpHash, and the encode-then-hash alternative
  result.add hashCase("Account", account())
  result.add keccakCase("Account", account())
  result.add hashCase("Header (Prague)", header)
  result.add keccakCase("Header (Prague)", header)
  result.add hashCase("Transaction (legacy)", legacyTx(1))
  result.add keccakCase("Transaction (legacy)", legacyTx(1))
  result.add hashCase("Transaction (EIP-1559)", eip1559Tx(1))
  result.add keccakCase("Transaction (EIP-1559)", eip1559Tx(1))
  result.add hashCase("Receipt (EIP-1559)", receipt(1))
  result.add keccakCase("Receipt (EIP-1559)", receipt(1))
  result.add Case(
    name: "hash chain txs x11264",
    bytes: (block:
      var n = 0
      for tx in chainTxs:
        n += rlp.encode(tx).len
      n),
    run: proc(): uint64 {.closure, raises: [].} =
      for tx in chainTxs:
        result += digest(computeRlpHash(tx)),
  )

  # getEncodedLength
  result.add lengthCase("Header (Prague)", header)
  result.add lengthCase("Transaction (EIP-1559)", eip1559Tx(1))
  result.add lengthCase("seq[Transaction] x200", txs)

  # Single-pass writers
  result.add defaultCase("Account", account())
  result.add defaultCase("Header (Prague)", header)
  result.add defaultCase("seq[Transaction] x200", txs)
  let branchLen = block:
    var w = initRlpWriter()
    w.appendBranch
    w.finish.len
  result.add Case(
    name: "default branch node",
    bytes: branchLen,
    run: proc(): uint64 {.closure, raises: [].} =
      var w = initRlpWriter()
      w.appendBranch
      digest(w.finish),
  )
  result.add Case(
    name: "arraybuf branch node",
    bytes: branchLen,
    run: proc(): uint64 {.closure, raises: [].} =
      # as aristo's `rlpEncodeBranch`
      var w = RlpArrayBufWriter[533, 1]()
      w.appendBranch
      digest(w.finish(asOpenArray = true)),
  )
  let
    leafPath = filler(30, 1)
    acc = account()
  result.add Case(
    name: "arraybuf account leaf node",
    bytes: (block:
      var w = initRlpList(2)
      w.append(leafPath)
      w.append(rlp.encode(account()))
      w.finish.len),
    run: proc(): uint64 {.closure, raises: [].} =
      # as aristo's `rlpEncodeAccLeaf`: the account is encoded into its own
      # buffer, then appended as a blob
      var accW = RlpArrayBufWriter[111, 1]()
      accW.append(acc)
      var w = RlpArrayBufWriter[149, 1]()
      w.startList(2)
      w.append(leafPath)
      w.append(accW.finish(asOpenArray = true))
      digest(w.finish(asOpenArray = true)),
  )

  # Sender recovery hashes every transaction once
  result.add signingCase("Transaction (legacy)", legacyTx(1))
  result.add signingCase("Transaction (EIP-1559)", eip1559Tx(1))
  result.add Case(
    name: "signing chain txs x11264",
    bytes: (block:
      var n = 0
      for tx in chainTxs:
        n += encodeForSigning(tx, tx.isEip155).len
      n),
    run: proc(): uint64 {.closure, raises: [].} =
      for tx in chainTxs:
        result += digest(rlpHashForSigning(tx, tx.isEip155)),
  )

  # Block validation recomputes the transactions and receipts roots
  result.add Case(
    name: "trie txs x200",
    bytes: rlp.encode(txs).len,
    run: proc(): uint64 {.closure, raises: [].} =
      digest(orderedTrieRoot(txs)),
  )
  result.add Case(
    name: "trie receipts x200",
    bytes: rlp.encode(receipts).len,
    run: proc(): uint64 {.closure, raises: [].} =
      digest(orderedTrieRoot(receipts)),
  )

  # Block size check on import
  result.add Case(
    name: "length EthBlock x1024 (chain)",
    bytes: blocksRlp.len,
    run: proc(): uint64 {.closure, raises: [].} =
      for b in blocks:
        result += uint64(getEncodedLength(b)),
  )

proc timeRun(c: Case, iters: int): Duration =
  let t0 = getMonoTime()
  for _ in 0 ..< iters:
    sink = sink xor c.run()
  getMonoTime() - t0

proc measure(c: Case): float =
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

  echo "RLP encoding, median of ", Samples, " samples (lower ns/op is better)"
  echo ""
  echo &"""{"case":<38} {"bytes":>9} {"ns/op":>13} {"MB/s":>9}"""
  echo "-".repeat(72)

  for c in cases():
    if filter.len > 0 and filter notin c.name:
      continue
    let
      ns = c.measure()
      mbps = float(c.bytes) / ns * 1000.0
    echo &"{c.name:<38} {c.bytes:>9} {ns:>13.1f} {mbps:>9.1f}"

  echo "-".repeat(72)

  if sink == 0xff'u64:
    echo ""

when isMainModule:
  main()
