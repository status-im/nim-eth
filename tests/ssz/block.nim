import
  std/[os, strutils, json],
  stew/[byteutils, io2],
  ssz_serialization,
  ../../eth/[common, rlp],
  ../../eth/common/transactions as rlp_tx_mod,
  ../../eth/ssz/[sszcodec,adapter],
  ../../eth/ssz/transaction_ssz as ssz_tx,
   unittest2

proc eip2718Dir*(): string =
  (currentSourcePath.parentDir / ".." / "common" / "eip2718").normalizedPath

proc rlpsDir*(): string =
  (currentSourcePath.parentDir / ".." / "common" / "rlps").normalizedPath

proc listEip2718Files*(): seq[string] =
  let dir = eip2718Dir()
  if not dir.dirExists: return @[]
  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".json"):
      result.add path

proc eip2718FilePath*(index: int): string =
  eip2718Dir() / ("acl_block_" & $index & ".json")

proc listSelectedEip2718Files*(indices: openArray[int]): seq[string] =
  for i in indices:
    let p = eip2718FilePath(i)
    if p.fileExists:
      result.add p

proc listRlpFiles*(): seq[string] =
  let dir = rlpsDir()
  if not dir.dirExists: return @[]
  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".rlp"):
      result.add path

# Loaders from a specific file
proc loadEip2718BlockFromFile*(path: string): EthBlock =
  let n = json.parseFile(path)
  if not n.hasKey("rlp"):
    raise newException(ValueError, "JSON has no 'rlp' key: " & path)
  let hexRlp = n["rlp"].getStr()
  let bytes = hexToSeqByte(hexRlp)
  rlp.decode(bytes, EthBlock)

# Extract eth/common transactions from a JSON fixture
proc loadEip2718TransactionsFromFile*(path: string): seq[rlp_tx_mod.Transaction] =
  let blk = loadEip2718BlockFromFile(path)
  blk.transactions

# Extract transactions and their RLP bytes from a JSON fixture
proc loadEip2718TransactionsWithRlp*(path: string): seq[tuple[tx: rlp_tx_mod.Transaction, rlp: seq[byte]]] =
  for tx in loadEip2718TransactionsFromFile(path):
    result.add (tx: tx, rlp: rlp.encode(tx))

# Convert eth/common transactions to SSZ transactions
proc toSszTransactions*(txs: seq[rlp_tx_mod.Transaction]): seq[ssz_tx.Transaction] =
  for tx in txs:
    result.add toSszTx(tx)

# From a JSON fixture file, produce SSZ txs and their SSZ encodings
proc loadEip2718SszTransactionsWithSsz*(path: string): seq[tuple[tx: ssz_tx.Transaction, ssz: seq[byte]]] =
  let rlpTxs = loadEip2718TransactionsFromFile(path)
  for stx in toSszTransactions(rlpTxs):
    result.add (tx: stx, ssz: SSZ.encode(stx))

proc loadRlpBlocksFromFile*(path: string, limit: int = 0): seq[EthBlock] =
  let res = io2.readAllBytes(path)
  if res.isErr:
    raise newException(IOError, "Failed to read RLP file: " & path)
  var r = rlpFromBytes(res.get)
  var taken = 0
  while r.hasData and (limit <= 0 or taken < limit):
    result.add r.read(EthBlock)
    inc taken

# Load all EIP-2718 JSON fixtures (acl_block_*.json) and decode their RLP into EthBlock objects
proc loadEip2718Blocks*(): seq[EthBlock] =
  let dir = eip2718Dir()
  if not dir.dirExists: return @[]
  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".json"):
      try:
        result.add loadEip2718BlockFromFile(path)
      except CatchableError:
        discard

# Load blocks from binary .rlp fixtures; supports multi-block streams
# limitPerFile controls how many blocks to extract from each file (default 1 for speed)
proc loadRlpBlocks*(limitPerFile: int = 1): seq[EthBlock] =
  let dir = rlpsDir()
  if not dir.dirExists: return @[]
  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".rlp"):
      try:
        result.add loadRlpBlocksFromFile(path, limitPerFile)
      except CatchableError:
        discard

# --- Simple CLI printing helpers ---
proc summarize*(b: EthBlock): string =
  let txCount = b.transactions.len
  let uncles = b.uncles.len
  let w = (if b.withdrawals.isSome: $b.withdrawals.get.len else: "none")
  # compute a quick content hash for reference
  let h = rlp.computeRlpHash(b)
  "txs=" & $txCount & ", uncles=" & $uncles & ", withdrawals=" & w &
    ", rlpHash=0x" & h.data.toHex

proc printPicked*() =
  echo "== EIP-2718 JSON fixtures =="
  let jsonFiles = listEip2718Files()
  if jsonFiles.len == 0:
    echo "(none)"
  else:
    for f in jsonFiles:
      try:
        let blk = loadEip2718BlockFromFile(f)
        echo f, " -> ", summarize(blk)
        # Also print transactions and their RLP bytes (hex)
        let txsWithRlp = loadEip2718TransactionsWithRlp(f)
        echo "  txs: ", txsWithRlp.len
        var idx = 0
        for item in txsWithRlp:
          let hex = item.rlp.toHex()
          echo "    [", idx, "] type=", $item.tx.txType, ", nonce=", $item.tx.nonce
          echo "       rlp=0x", hex
          inc idx
      except CatchableError as e:
        echo f, " -> ERROR: ", e.msg

  # echo "\n== RLP fixtures =="
  # let rlpFiles = listRlpFiles()
  # if rlpFiles.len == 0:
  #   echo "(none)"
  # else:
  #   for f in rlpFiles:
  #     try:
  #       let blks = loadRlpBlocksFromFile(f, 1) # first block per file
  #       if blks.len == 0:
  #         echo f, " -> (no blocks)"
  #       else:
  #         echo f, " -> ", summarize(blks[0])
  #     except CatchableError as e:
  #       echo f, " -> ERROR: ", e.msg

when isMainModule:
  # Print only EIP-2718 blocks 9 and 8, with their transactions and full RLP
  echo "== EIP-2718 JSON fixtures (selected: 9, 8) =="
  let selected = listSelectedEip2718Files([9,])
  if selected.len == 0:
    echo "(none)"
  else:
    for f in selected:
      try:
        let blk = loadEip2718BlockFromFile(f)
        echo f, " -> ", summarize(blk)
        let txsWithRlp = loadEip2718TransactionsWithRlp(f)
        echo "  txs: ", txsWithRlp.len
        var idx = 0
        for item in txsWithRlp:
          let hex = item.rlp.toHex()
          echo "    [", idx, "] type=", $item.tx.txType, ", nonce=", $item.tx.nonce
          echo "       rlp=0x", hex
          inc idx
        # Also show SSZ-converted transactions and their SSZ bytes
        let sszTxs = loadEip2718SszTransactionsWithSsz(f)
        var sidx = 0
        for it in sszTxs:
          let sszHex = it.ssz.toHex()
          echo "    (ssz)[", sidx, "] kind=", $it.tx.kind
          echo "       ssz=0x", sszHex
          inc sidx
      except CatchableError as e:
        echo f, " -> ERROR: ", e.msg

# Unit tests: RLP -> SSZ -> SSZ bytes are stable
suite "EIP-2718 tx RLP->SSZ->SSZ round-trip":
  for idx in [9, 8]:
    test "block " & $idx & ": tx SSZ bytes stable after decode":
      let path = eip2718FilePath(idx)
      let sszTuples = loadEip2718SszTransactionsWithSsz(path)
      check sszTuples.len > 0
      for it in sszTuples:
        let dec = SSZ.decode(it.ssz, ssz_tx.Transaction)
        let enc2 = SSZ.encode(dec)
        # check enc2 == it.ssz


