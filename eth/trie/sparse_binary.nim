import
  ranges/[ptr_arith, typedranges, bitranges], eth/rlp/types,
  trie_defs, trie_utils, db, sparse_proofs

export
  types, trie_utils, bitranges,
  sparse_proofs.verifyProof

type
  DB = TrieDatabaseRef

  SparseBinaryTrie* = object
    db: DB
    rootHash: ByteRange

proc `==`(a: ByteRange, b: KeccakHash): bool =
  if a.len != b.data.len: return false
  equalMem(a.baseAddr, b.data[0].unsafeAddr, a.len)

type
  # 256 * 2 div 8
  DoubleHash = array[64, byte]

proc initDoubleHash(a, b: openArray[byte]): DoubleHash =
  assert(a.len == 32, $a.len)
  assert(b.len == 32, $b.len)
  copyMem(result[ 0].addr, a[0].unsafeAddr, 32)
  copyMem(result[32].addr, b[0].unsafeAddr, 32)

proc initDoubleHash(x: ByteRange): DoubleHash =
  initDoubleHash(x.toOpenArray, x.toOpenArray)

proc init*(x: typedesc[SparseBinaryTrie], db: DB): SparseBinaryTrie =
  result.db = db
  # Initialize an empty tree with one branch
  var value = initDoubleHash(emptyNodeHashes[0])
  result.rootHash = keccakHash(value)
  result.db.put(result.rootHash.toOpenArray, value)

  for i in 0..<treeHeight - 1:
    value = initDoubleHash(emptyNodeHashes[i+1])
    result.db.put(emptyNodeHashes[i].toOpenArray, value)

  result.db.put(emptyLeafNodeHash.data, zeroBytesRange.toOpenArray)

proc initSparseBinaryTrie*(db: DB): SparseBinaryTrie =
  init(SparseBinaryTrie, db)

proc init*(x: typedesc[SparseBinaryTrie], db: DB,
           rootHash: BytesContainer | KeccakHash): SparseBinaryTrie =
  checkValidHashZ(rootHash)
  result.db = db
  result.rootHash = rootHash

proc initSparseBinaryTrie*(db: DB, rootHash: BytesContainer | KeccakHash): SparseBinaryTrie =
  init(SparseBinaryTrie, db, rootHash)

proc getDB*(t: SparseBinaryTrie): auto = t.db

proc getRootHash*(self: SparseBinaryTrie): ByteRange {.inline.} =
  self.rootHash

proc getAux(self: SparseBinaryTrie, path: BitRange, rootHash: ByteRange): ByteRange =
  var nodeHash = rootHash
  for targetBit in path:
    let value = self.db.get(nodeHash.toOpenArray).toRange
    if value.len == 0: return zeroBytesRange
    if targetBit: nodeHash = value[32..^1]
    else: nodeHash = value[0..31]

  if nodeHash.toOpenArray == emptyLeafNodeHash.data:
    result = zeroBytesRange
  else:
    result = self.db.get(nodeHash.toOpenArray).toRange

proc get*(self: SparseBinaryTrie, key: BytesContainer): ByteRange =
  ## gets a key from the tree.
  assert(key.len == pathByteLen)
  let path = MutByteRange(key.toRange).bits
  self.getAux(path, self.rootHash)

proc get*(self: SparseBinaryTrie, key, rootHash: distinct BytesContainer): ByteRange =
  ## gets a key from the tree at a specific root.
  assert(key.len == pathByteLen)
  let path = MutByteRange(key.toRange).bits
  self.getAux(path, rootHash.toRange)

proc hashAndSave*(self: SparseBinaryTrie, node: ByteRange): ByteRange =
  result = keccakHash(node)
  self.db.put(result.toOpenArray, node.toOpenArray)

proc hashAndSave*(self: SparseBinaryTrie, a, b: ByteRange): ByteRange =
  let value = initDoubleHash(a.toOpenArray, b.toOpenArray)
  result = keccakHash(value)
  self.db.put(result.toOpenArray, value)

proc setAux(self: var SparseBinaryTrie, value: ByteRange,
    path: BitRange, depth: int, nodeHash: ByteRange): ByteRange =
  if depth == treeHeight:
    result = self.hashAndSave(value)
  else:
    let
      node = self.db.get(nodeHash.toOpenArray).toRange
      leftNode = node[0..31]
      rightNode = node[32..^1]
    if path[depth]:
      result = self.hashAndSave(leftNode, self.setAux(value, path, depth+1, rightNode))
    else:
      result = self.hashAndSave(self.setAux(value, path, depth+1, leftNode), rightNode)

proc set*(self: var SparseBinaryTrie, key, value: distinct BytesContainer) =
  ## sets a new value for a key in the tree, returns the new root,
  ## and sets the new current root of the tree.
  assert(key.len == pathByteLen)
  let path = MutByteRange(key.toRange).bits
  self.rootHash = self.setAux(value.toRange, path, 0, self.rootHash)

proc set*(self: var SparseBinaryTrie, key, value, rootHash: distinct BytesContainer): ByteRange =
  ## sets a new value for a key in the tree at a specific root,
  ## and returns the new root.
  assert(key.len == pathByteLen)
  let path = MutByteRange(key.toRange).bits
  self.setAux(value.toRange, path, 0, rootHash.toRange)

template exists*(self: SparseBinaryTrie, key: BytesContainer): bool =
  self.get(toRange(key)) != zeroBytesRange

proc del*(self: var SparseBinaryTrie, key: BytesContainer) =
  ## Equals to setting the value to zeroBytesRange
  assert(key.len == pathByteLen)
  self.set(key, zeroBytesRange)

# Dictionary API
template `[]`*(self: SparseBinaryTrie, key: BytesContainer): ByteRange =
  self.get(key)

template `[]=`*(self: var SparseBinaryTrie, key, value: distinct BytesContainer) =
  self.set(key, value)

template contains*(self: SparseBinaryTrie, key: BytesContainer): bool =
  self.exists(key)

proc proveAux(self: SparseBinaryTrie, key, rootHash: ByteRange, output: var seq[ByteRange]): bool =
  assert(key.len == pathByteLen)
  var currVal = self.db.get(rootHash.toOpenArray).toRange
  if currVal.len == 0: return false

  let path = MutByteRange(key).bits
  for i, bit in path:
    if bit:
      # right side
      output[i] = currVal[0..31]
      currVal = self.db.get(currVal[32..^1].toOpenArray).toRange
      if currVal.len == 0: return false
    else:
      output[i] = currVal[32..^1]
      currVal = self.db.get(currVal[0..31].toOpenArray).toRange
      if currVal.len == 0: return false

  result = true

# prove generates a Merkle proof for a key.
proc prove*(self: SparseBinaryTrie, key: BytesContainer): seq[ByteRange] =
  result = newSeq[ByteRange](treeHeight)
  if not self.proveAux(key.toRange, self.rootHash, result):
    result = @[]

# prove generates a Merkle proof for a key, at a specific root.
proc prove*(self: SparseBinaryTrie, key, rootHash: distinct BytesContainer): seq[ByteRange] =
  result = newSeq[ByteRange](treeHeight)
  if not self.proveAux(key.toRange, rootHash.toRange, result):
    result = @[]

# proveCompact generates a compacted Merkle proof for a key.
proc proveCompact*(self: SparseBinaryTrie, key: BytesContainer): seq[ByteRange] =
  var temp = self.prove(key)
  temp.compactProof

# proveCompact generates a compacted Merkle proof for a key, at a specific root.
proc proveCompact*(self: SparseBinaryTrie, key, rootHash: distinct BytesContainer): seq[ByteRange] =
  var temp = self.prove(key, rootHash)
  temp.compactProof
