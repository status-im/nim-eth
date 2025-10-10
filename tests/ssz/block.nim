import
  std/[os, strutils, json],
  stew/[byteutils, io2],
  ssz_serialization,
  ../../eth/[common, rlp],
  ../../eth/ssz/[sszcodec,adapter,blocks_ssz,transaction_ssz],
   unittest2

type
  TxSSZ = transaction_ssz.Transaction
  TxRLP = transactions.Transaction

proc eip2718Dir*(): string =
  (currentSourcePath.parentDir / ".." / "common" / "eip2718").normalizedPath

proc rlpsDir*(): string =
  (currentSourcePath.parentDir / ".." / "common" / "rlps").normalizedPath

proc eip2718FilePath*(index: int): string =
  eip2718Dir() / ("acl_block_" & $index & ".json")

proc loadBlockFromFile*(path: string): EthBlock =
  let n = json.parseFile(path)
  if not n.hasKey("rlp"):
    raise newException(ValueError, "JSON has no 'rlp' key")
  let hexRlp = n["rlp"].getStr()
  let bytes = hexToSeqByte(hexRlp)
  rlp.decode(bytes, EthBlock)

proc listRlpFiles*(): seq[string] =
  let dir = rlpsDir()
  if not dir.dirExists: return @[]
  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".rlp"):
      result.add path

proc loadRlpBlocksFromFile*(path: string, limit: int = 0): seq[EthBlock] =
  let res = io2.readAllBytes(path)
  if res.isErr:
    raise newException(IOError, "Failed to read RLP file: " & path)
  var r = rlpFromBytes(res.get)
  var taken = 0
  while r.hasData and (limit <= 0 or taken < limit):
    result.add r.read(EthBlock)
    inc taken


suite "Transaction List Roundtrip":
  test "Block 9: RLP → SSZ → RLP preserves all transactions":
    let path = eip2718FilePath(9)
    if not path.fileExists:
      skip()

    let blk = loadBlockFromFile(path)
    let originalTxs = blk.transactions
    var sszTxs: seq[TxSSZ]
    for tx in originalTxs:
      sszTxs.add(toSszTx(tx))
    var reconstructed: seq[TxRLP]
    for tx in sszTxs:
      reconstructed.add(toOldTx(tx))
    check reconstructed.len == originalTxs.len

    # Verify each transaction
    for i in 0..<originalTxs.len:
      check reconstructed[i].txType == originalTxs[i].txType
      check reconstructed[i].chainId == originalTxs[i].chainId
      check reconstructed[i].nonce == originalTxs[i].nonce
      check reconstructed[i].gasLimit == originalTxs[i].gasLimit
      check reconstructed[i].to == originalTxs[i].to
      check reconstructed[i].value == originalTxs[i].value
      check reconstructed[i].payload == originalTxs[i].payload

  test "All blocks 0-9: Transaction count preserved":
    for i in 0..9:
      let path = eip2718FilePath(i)
      if not path.fileExists:
        continue

      let blk = loadBlockFromFile(path)
      let originalTxs = blk.transactions

      # RLP → SSZ → RLP
      var sszTxs: seq[TxSSZ]
      for tx in originalTxs:
        sszTxs.add(toSszTx(tx))

      var reconstructed: seq[TxRLP]
      for tx in sszTxs:
        reconstructed.add(toOldTx(tx))

      check reconstructed.len == originalTxs.len

      # Spot check first tx
      if originalTxs.len > 0:
        check reconstructed[0].nonce == originalTxs[0].nonce
        check reconstructed[0].chainId == originalTxs[0].chainId

suite "Transaction Root Computation (EIP-6404)":
  test "Block 9: Root is deterministic":
    let path = eip2718FilePath(9)
    if not path.fileExists:
      skip()

    let blk = loadBlockFromFile(path)

    # Compute multiple times
    let root1 = computeTransactionsRootSsz(blk.transactions)
    let root2 = computeTransactionsRootSsz(blk.transactions)
    let root3 = computeTransactionsRootSsz(blk.transactions)

    # All identical
    check root1 == root2
    check root2 == root3
    check root1 != default(Root)

    echo "\nTX Root: 0x", root1.data.toHex

  test "All blocks 0-9: Compute transaction roots":
    echo ""
    for i in 0..9:
      let path = eip2718FilePath(i)
      if not path.fileExists:
        continue

      let blk = loadBlockFromFile(path)

      # Compute root
      let root1 = computeTransactionsRootSsz(blk.transactions)
      let root2 = computeTransactionsRootSsz(blk.transactions)

      # Verify stable
      check root1 == root2
      check root1 != default(Root)

      echo "Block ", i, " (", blk.transactions.len, " txs): 0x",
           root1.data.toHex[0..15], "..."


suite "SSZ Encoding/Decoding":
  test "Block 9: Individual transaction SSZ roundtrip":
    let path = eip2718FilePath(9)
    if not path.fileExists:
      skip()

    let blk = loadBlockFromFile(path)
    for i, rlpTx in blk.transactions:
      let sszTx = toSszTx(rlpTx)
      let encoded = SSZ.encode(sszTx)
      let decoded = SSZ.decode(encoded, TxSSZ)  # ← FIXED: Use type, not variable
      let reconstructed = toOldTx(decoded)

      # Verify
      check reconstructed.nonce == rlpTx.nonce
      check reconstructed.chainId == rlpTx.chainId
      check reconstructed.gasLimit == rlpTx.gasLimit
      check reconstructed.value == rlpTx.value

  test "Block 9: Transaction list SSZ encoding":
    let path = eip2718FilePath(9)
    if not path.fileExists:
      skip()

    let blk = loadBlockFromFile(path)
    var sszTxs: seq[TxSSZ]
    for tx in blk.transactions:
      sszTxs.add(toSszTx(tx))
    let encoded = SSZ.encode(sszTxs)
    let decoded = SSZ.decode(encoded, seq[TxSSZ])  # ← FIXED: Use type
    check decoded.len == sszTxs.len
