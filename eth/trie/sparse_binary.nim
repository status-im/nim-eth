import
  ./trie_bitseq,
  ./trie_defs, ./trie_utils, ./db, ./sparse_proofs

export
  trie_utils, trie_bitseq,
  sparse_proofs.verifyProof

type
  DB = TrieDatabaseRef

  SparseBinaryTrie* = object
    db: DB
    rootHash: seq[byte]

type
  # 256 * 2 div 8
  DoubleHash = array[64, byte]

proc initDoubleHash(a, b: openArray[byte]): DoubleHash =
  doAssert(a.len == 32, $a.len)
  doAssert(b.len == 32, $b.len)
  result[0..31] = a
  result[32..^1] = b

proc initDoubleHash(x: openArray[byte]): DoubleHash =
  initDoubleHash(x, x)

proc init*(x: typedesc[SparseBinaryTrie], db: DB): SparseBinaryTrie =
  result.db = db
  # Initialize an empty tree with one branch
  var value = initDoubleHash(emptyNodeHashes[0].data)
  result.rootHash = @(keccakHash(value).data)
  result.db.put(result.rootHash, value)

  for i in 0..<treeHeight - 1:
    value = initDoubleHash(emptyNodeHashes[i+1].data)
    result.db.put(emptyNodeHashes[i].data, value)

  result.db.put(emptyLeafNodeHash.data, [])

proc initSparseBinaryTrie*(db: DB): SparseBinaryTrie =
  init(SparseBinaryTrie, db)

proc init*(x: typedesc[SparseBinaryTrie], db: DB,
           rootHash: openArray[byte]): SparseBinaryTrie =
  checkValidHashZ(rootHash)
  result.db = db
  result.rootHash = @rootHash

proc initSparseBinaryTrie*(db: DB, rootHash: openArray[byte]): SparseBinaryTrie =
  init(SparseBinaryTrie, db, rootHash)

proc getDB*(t: SparseBinaryTrie): auto = t.db

proc getRootHash*(self: SparseBinaryTrie): seq[byte] {.inline.} =
  self.rootHash

proc getAux(self: SparseBinaryTrie, path: TrieBitSeq, rootHash: openArray[byte]): seq[byte] =
  var nodeHash = @rootHash
  for targetBit in path:
    let value = self.db.get(nodeHash)
    if value.len == 0: return
    if targetBit: nodeHash = value[32..^1]
    else: nodeHash = value[0..31]

  if nodeHash == emptyLeafNodeHash.data:
    result = @[]
  else:
    result = self.db.get(nodeHash)

proc get*(self: SparseBinaryTrie, key: openArray[byte]): seq[byte] =
  ## gets a key from the tree.
  doAssert(key.len == pathByteLen)
  let path = bits key
  self.getAux(path, self.rootHash)

proc get*(self: SparseBinaryTrie, key, rootHash: openArray[byte]): seq[byte] =
  ## gets a key from the tree at a specific root.
  doAssert(key.len == pathByteLen)
  let path = bits key
  self.getAux(path, rootHash)

proc hashAndSave*(self: SparseBinaryTrie, node: openArray[byte]): seq[byte] =
  result = @(keccakHash(node).data)
  self.db.put(result, node)

proc hashAndSave*(self: SparseBinaryTrie, a, b: openArray[byte]): seq[byte] =
  let value = initDoubleHash(a, b)
  result = @(keccakHash(value).data)
  self.db.put(result, value)

proc setAux(self: var SparseBinaryTrie, value: openArray[byte],
    path: TrieBitSeq, depth: int, nodeHash: openArray[byte]): seq[byte] =
  if depth == treeHeight:
    result = self.hashAndSave(value)
  else:
    let
      node = self.db.get(nodeHash)
      leftNode = node[0..31]
      rightNode = node[32..^1]
    if path[depth]:
      result = self.hashAndSave(leftNode, self.setAux(value, path, depth+1, rightNode))
    else:
      result = self.hashAndSave(self.setAux(value, path, depth+1, leftNode), rightNode)

proc set*(self: var SparseBinaryTrie, key, value: openArray[byte]) =
  ## sets a new value for a key in the tree, returns the new root,
  ## and sets the new current root of the tree.
  doAssert(key.len == pathByteLen)
  let path = bits key
  self.rootHash = self.setAux(value, path, 0, self.rootHash)

proc set*(self: var SparseBinaryTrie, key, value, rootHash: openArray[byte]): seq[byte] =
  ## sets a new value for a key in the tree at a specific root,
  ## and returns the new root.
  doAssert(key.len == pathByteLen)
  let path = bits key
  self.setAux(value, path, 0, rootHash)

template exists*(self: SparseBinaryTrie, key: openArray[byte]): bool =
  self.get(key) != []

proc del*(self: var SparseBinaryTrie, key: openArray[byte]) =
  ## Equals to setting the value to zeroBytesRange
  doAssert(key.len == pathByteLen)
  self.set(key, [])

# Dictionary API
template `[]`*(self: SparseBinaryTrie, key: openArray[byte]): seq[byte] =
  self.get(key)

template `[]=`*(self: var SparseBinaryTrie, key, value: openArray[byte]) =
  self.set(key, value)

template contains*(self: SparseBinaryTrie, key: openArray[byte]): bool =
  self.exists(key)

proc proveAux(self: SparseBinaryTrie, key, rootHash: openArray[byte], output: var seq[seq[byte]]): bool =
  doAssert(key.len == pathByteLen)
  var currVal = self.db.get(rootHash)
  if currVal.len == 0: return false

  let path = bits key
  for i, bit in path:
    if bit:
      # right side
      output[i] = currVal[0..31]
      currVal = self.db.get(currVal[32..^1])
      if currVal.len == 0: return false
    else:
      output[i] = currVal[32..^1]
      currVal = self.db.get(currVal[0..31])
      if currVal.len == 0: return false

  result = true

# prove generates a Merkle proof for a key.
proc prove*(self: SparseBinaryTrie, key: openArray[byte]): seq[seq[byte]] =
  result = newSeq[seq[byte]](treeHeight)
  if not self.proveAux(key, self.rootHash, result):
    result = @[]

# prove generates a Merkle proof for a key, at a specific root.
proc prove*(self: SparseBinaryTrie, key, rootHash: openArray[byte]): seq[seq[byte]] =
  result = newSeq[seq[byte]](treeHeight)
  if not self.proveAux(key, rootHash, result):
    result = @[]

# proveCompact generates a compacted Merkle proof for a key.
proc proveCompact*(self: SparseBinaryTrie, key: openArray[byte]): seq[seq[byte]] =
  var temp = self.prove(key)
  temp.compactProof

# proveCompact generates a compacted Merkle proof for a key, at a specific root.
proc proveCompact*(self: SparseBinaryTrie, key, rootHash: openArray[byte]): seq[seq[byte]] =
  var temp = self.prove(key, rootHash)
  temp.compactProof
