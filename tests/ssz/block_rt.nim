import
  std/[os, strutils, json],
  stew/[byteutils, io2],
  ssz_serialization,
  ../../eth/[common, rlp],
  ../../eth/common/transactions as rlp_tx_mod,
  ../../eth/ssz/[sszcodec,adapter,blocks_ssz,blocks_ssz_adapter],
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


suite "SSZ Block Roundtrip ":
  test "All blocks: RLP → SSZ → RLP preserves data":
    for i in 0..9:  # Test blocks 0-9
      let path = eip2718FilePath(i)
      if not path.fileExists:
        continue

      echo "Testing block ", i, ": ", path
      let rlpBlock = loadEip2718BlockFromFile(path)
      let sszBlock = toSszBlock(rlpBlock)
      # Convert back to common/block
      let reconstructed = fromSszBlock(sszBlock)

      # Verify critical fields preserved
      check reconstructed.header.number == rlpBlock.header.number
      check reconstructed.header.parentHash == rlpBlock.header.parentHash
      check reconstructed.header.stateRoot == rlpBlock.header.stateRoot
      check reconstructed.header.gasUsed == rlpBlock.header.gasUsed
      check reconstructed.header.gasLimit == rlpBlock.header.gasLimit
      check reconstructed.transactions.len == rlpBlock.transactions.len
      check reconstructed.uncles.len == rlpBlock.uncles.len

  #  wont be able to do a full block rt as the opt[withdrawals] may not match ssz requirements
  test "All blocks: SSZ → bytes → SSZ preserves data":
    for i in 0..9:
      let path = eip2718FilePath(i)
      if not path.fileExists:
        continue

      echo "Testing SSZ serialization for block ", i, ": ", path
      let rlpBlock = loadEip2718BlockFromFile(path)
      let sszBlock = toSszBlock(rlpBlock)

      let headerBytes = SSZ.encode(sszBlock.header)
      let decodedHeader = SSZ.decode(headerBytes, Header_SSZ)

      check decodedHeader.number == sszBlock.header.number
      check decodedHeader.parent_hash == sszBlock.header.parent_hash
      check decodedHeader.state_root == sszBlock.header.state_root

  test "Individual block tests":
    let path = eip2718FilePath(9)
    if path.fileExists:
      echo "Testing individual block 9: ", path
      let rlpBlock = loadEip2718BlockFromFile(path)
      let sszBlock = toSszBlock(rlpBlock)
      # Convert back to common/block
      let reconstructed = fromSszBlock(sszBlock)
      # Verify critical fields preserved
      check reconstructed.header.number == rlpBlock.header.number
      check reconstructed.header.parentHash == rlpBlock.header.parentHash
      check reconstructed.header.stateRoot == rlpBlock.header.stateRoot
      check reconstructed.header.gasUsed == rlpBlock.header.gasUsed
      check reconstructed.header.gasLimit == rlpBlock.header.gasLimit
      check reconstructed.transactions.len == rlpBlock.transactions.len
      check reconstructed.uncles.len == rlpBlock.uncles.len

# suite "SSZ Root Computation (EIP-6404, 6465)":
#   test "Block 9: Transaction root computation (EIP-6404)":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)

#     # Compute SSZ transactions root
#     let txRoot = computeTransactionsRootFromRlp(rlpBlock.transactions)

#     # Should be non-zero
#     check txRoot != default(Root)

#     # Should be stable (same result twice)
#     let txRoot2 = computeTransactionsRootFromRlp(rlpBlock.transactions)
#     check txRoot == txRoot2

#     echo "  TX Root: 0x", txRoot.data.toHex[0..15], "..."

#   test "Block 9: Withdrawals root (EIP-6465)":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)

#     # Compute SSZ withdrawals root
#     let wdRoot = computeWithdrawalsRootFromRlp(rlpBlock.withdrawals)

#     # Block 9 has no withdrawals
#     if rlpBlock.withdrawals.isNone:
#       check wdRoot == default(Root)
#     else:
#       check wdRoot != default(Root)

#     echo "  WD Root: 0x", wdRoot.data.toHex[0..15], "..."

#   test "Block 9: Root consistency check":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)
#     let sszBlock = toSszBlock(rlpBlock)

#     # Direct computation
#     let directTxRoot = computeTransactionsRootFromRlp(rlpBlock.transactions)

#     # From SSZ block
#     let blockTxRoot = block_ssz.computeTransactionsRoot(sszBlock.transactions)

#     # Should match
#     check directTxRoot == blockTxRoot

#   test "Transaction root: Order matters":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)

#     if rlpBlock.transactions.len >= 2:
#       # Original order
#       let root1 = computeTransactionsRootFromRlp(rlpBlock.transactions)

#       # Reversed order
#       var reversed = rlpBlock.transactions
#       reversed.reverse()
#       let root2 = computeTransactionsRootFromRlp(reversed)

#       # Should be different
#       check root1 != root2

# suite "SSZ Block Hash (EIP-7807)":
#   test "Block 9: SSZ hash differs from RLP hash":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)

#     # OLD: RLP-based hash
#     let rlpHash = rlp.computeRlpHash(rlpBlock.header)

#     # NEW: SSZ-based hash (EIP-7807)
#     let sszHash = computeBlockHashSsz(rlpBlock)

#     # They SHOULD be different (this is the point of EIP-7807!)
#     check rlpHash != sszHash

#     echo "  RLP hash: 0x", rlpHash.data.toHex[0..15], "..."
#     echo "  SSZ hash: 0x", sszHash.data.toHex[0..15], "..."

#   test "Block 9: SSZ hash is stable":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)

#     # Compute multiple times
#     let hash1 = computeBlockHashSsz(rlpBlock)
#     let hash2 = computeBlockHashSsz(rlpBlock)
#     let hash3 = computeBlockHashSsz(rlpBlock.header)

#     # All should be identical
#     check hash1 == hash2
#     check hash2 == hash3

#   test "Block 9: SSZ hash from header matches block":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)

#     # From full block
#     let hashFromBlock = computeBlockHashSsz(rlpBlock)

#     # From header only
#     let hashFromHeader = computeBlockHashSsz(rlpBlock.header)

#     # Should match
#     check hashFromBlock == hashFromHeader

#   test "All blocks: Compare RLP vs SSZ hashes":
#     let files = listEip2718Files()
#     var differCount = 0

#     for path in files:
#       try:
#         let rlpBlock = loadEip2718BlockFromFile(path)
#         let comparison = compareHashMethods(rlpBlock)

#         # All should differ (EIP-7807 changes hash computation)
#         if comparison.rlpHash != comparison.sszHash:
#           inc differCount
#       except:
#         discard

#     echo "  Blocks with different hashes: ", differCount
#     check differCount > 0  # At least some should differ


# suite "SSZ Block Data Integrity":
#   test "Block 9: Transaction count preserved":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)
#     let sszBlock = toSszBlock(rlpBlock)
#     let reconstructed = fromSszBlock(sszBlock)

#     check rlpBlock.transactions.len == 10
#     check sszBlock.transactions.len == 10
#     check reconstructed.transactions.len == 10

#   test "Block 9: Uncle count preserved":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)
#     let sszBlock = toSszBlock(rlpBlock)
#     let reconstructed = fromSszBlock(sszBlock)

#     check rlpBlock.uncles.len == sszBlock.uncles.len
#     check sszBlock.uncles.len == reconstructed.uncles.len

#   test "Block 9: Withdrawal presence preserved":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)
#     let sszBlock = toSszBlock(rlpBlock)
#     let reconstructed = fromSszBlock(sszBlock)

#     check rlpBlock.withdrawals.isNone == reconstructed.withdrawals.isNone

#     if rlpBlock.withdrawals.isSome and reconstructed.withdrawals.isSome:
#       check rlpBlock.withdrawals.get.len == reconstructed.withdrawals.get.len

#   test "Block 9: Header timestamp preserved":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)
#     let sszHeader = toSszHeader(rlpBlock.header)
#     let reconstructed = fromSszHeader(sszHeader)

#     check reconstructed.timestamp == rlpBlock.header.timestamp

#   test "Block 9: Parent hash preserved":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)
#     let sszHeader = toSszHeader(rlpBlock.header)
#     let reconstructed = fromSszHeader(sszHeader)

#     check reconstructed.parentHash == rlpBlock.header.parentHash

#   test "Block 9: State root preserved":
#     let path = eip2718FilePath(9)
#     let rlpBlock = loadEip2718BlockFromFile(path)
#     let sszHeader = toSszHeader(rlpBlock.header)
#     let reconstructed = fromSszHeader(sszHeader)

#     check reconstructed.stateRoot == rlpBlock.header.stateRoot
