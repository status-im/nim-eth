import
  "."/[trie_defs, binary, binaries, db, trie_utils, trie_bitseq]

type
  DB = TrieDatabaseRef

  # TODO: replace the usages of this with regular asserts
  InvalidKeyError* = object of Defect

template query(db: DB, nodeHash: TrieNodeKey): seq[byte] =
  db.get(nodeHash)

proc checkIfBranchExistImpl(db: DB; nodeHash: TrieNodeKey; keyPrefix: TrieBitSeq): bool =
  if nodeHash == zeroHash:
    return false

  let node = parseNode(db.query(nodeHash))

  case node.kind:
  of LEAF_TYPE:
    if keyPrefix.len != 0: return false
    return true
  of KV_TYPE:
    if keyPrefix.len == 0: return true
    if keyPrefix.len < node.keyPath.len:
      if keyPrefix == node.keyPath[0..<keyPrefix.len]: return true
      return false
    else:
      if keyPrefix[0..<node.keyPath.len] == node.keyPath:
        return checkIfBranchExistImpl(db, node.child, keyPrefix.sliceToEnd(node.keyPath.len))
      return false
  of BRANCH_TYPE:
    if keyPrefix.len == 0: return true
    if keyPrefix[0] == false:
      return checkIfBranchExistImpl(db, node.leftChild, keyPrefix.sliceToEnd(1))
    else:
      return checkIfBranchExistImpl(db, node.rightChild, keyPrefix.sliceToEnd(1))

proc checkIfBranchExist*(db: DB; rootHash: TrieNodeKey, keyPrefix: openArray[byte]): bool =
  ## Given a key prefix, return whether this prefix is
  ## the prefix of an existing key in the trie.
  checkValidHashZ(rootHash)
  var keyPrefixBits = bits keyPrefix
  checkIfBranchExistImpl(db, rootHash, keyPrefixBits)

proc getBranchImpl(db: DB; nodeHash: TrieNodeKey, keyPath: TrieBitSeq, output: var seq[seq[byte]]) =
  if nodeHash == zeroHash: return

  let nodeVal = db.query(nodeHash)
  let node = parseNode(nodeVal)

  case node.kind
  of LEAF_TYPE:
    if keyPath.len == 0:
      output.add nodeVal
    else:
      raise newException(InvalidKeyError, "Key too long")

  of KV_TYPE:
    if keyPath.len == 0:
      raise newException(InvalidKeyError, "Key too short")

    output.add nodeVal
    let sliceLen = min(keyPath.len, node.keyPath.len)
    if keyPath[0..<sliceLen] == node.keyPath:
      getBranchImpl(db, node.child, keyPath.sliceToEnd(sliceLen), output)

  of BRANCH_TYPE:
    if keyPath.len == 0:
      raise newException(InvalidKeyError, "Key too short")

    output.add nodeVal
    if keyPath[0] == false:
      getBranchImpl(db, node.leftChild, keyPath.sliceToEnd(1), output)
    else:
      getBranchImpl(db, node.rightChild, keyPath.sliceToEnd(1), output)

proc getBranch*(db: DB; rootHash: seq[byte]; key: openArray[byte]): seq[seq[byte]] =
  ##     Get a long-format Merkle branch
  checkValidHashZ(rootHash)
  result = @[]
  var keyBits = bits key
  getBranchImpl(db, rootHash, keyBits, result)

proc isValidBranch*(branch: seq[seq[byte]], rootHash: seq[byte], key, value: openArray[byte]): bool =
  checkValidHashZ(rootHash)
  # branch must not be empty
  doAssert(branch.len != 0)

  var db = newMemoryDB()
  for node in branch:
    doAssert(node.len != 0)
    let nodeHash = keccakHash(node)
    db.put(nodeHash.data, node)

  var trie = initBinaryTrie(db, rootHash)
  result = trie.get(key) == value

proc getTrieNodesImpl(db: DB; nodeHash: TrieNodeKey, output: var seq[seq[byte]]): bool =
  ## Get full trie of a given root node

  if nodeHash.isZeroHash(): return false

  var nodeVal: seq[byte]
  if nodeHash in db:
    nodeVal = db.query(nodeHash)
  else:
    return false

  let node = parseNode(nodeVal)

  case node.kind
  of KV_TYPE:
    output.add nodeVal
    result = getTrieNodesImpl(db, node.child, output)
  of BRANCH_TYPE:
    output.add nodeVal
    result = getTrieNodesImpl(db, node.leftChild, output)
    result = getTrieNodesImpl(db, node.rightChild, output)
  of LEAF_TYPE:
    output.add nodeVal

proc getTrieNodes*(db: DB; nodeHash: TrieNodeKey): seq[seq[byte]] =
  checkValidHashZ(nodeHash)
  result = @[]
  discard getTrieNodesImpl(db, nodeHash, result)

proc getWitnessImpl*(db: DB; nodeHash: TrieNodeKey; keyPath: TrieBitSeq; output: var seq[seq[byte]]) =
  if keyPath.len == 0:
    if not getTrieNodesImpl(db, nodeHash, output): return

  if nodeHash.isZeroHash(): return

  var nodeVal: seq[byte]
  if nodeHash in db:
    nodeVal = db.query(nodeHash)
  else:
    return

  let node = parseNode(nodeVal)

  case node.kind
  of LEAF_TYPE:
    if keyPath.len != 0:
      raise newException(InvalidKeyError, "Key too long")
  of KV_TYPE:
    output.add nodeVal
    if keyPath.len < node.keyPath.len and node.keyPath[0..<keyPath.len] == keypath:
      if not getTrieNodesImpl(db, node.child, output): return
    elif keyPath[0..<node.keyPath.len] == node.keyPath:
      getWitnessImpl(db, node.child, keyPath.sliceToEnd(node.keyPath.len), output)
  of BRANCH_TYPE:
    output.add nodeVal
    if keyPath[0] == false:
      getWitnessImpl(db, node.leftChild, keyPath.sliceToEnd(1), output)
    else:
      getWitnessImpl(db, node.rightChild, keyPath.sliceToEnd(1), output)

proc getWitness*(db: DB; nodeHash: TrieNodeKey; key: openArray[byte]): seq[seq[byte]] =
  ##  Get all witness given a keyPath prefix.
  ##  Include
  ##
  ##  1. witness along the keyPath and
  ##  2. witness in the subtrie of the last node in keyPath
  checkValidHashZ(nodeHash)
  result = @[]
  var keyBits = bits key
  getWitnessImpl(db, nodeHash, keyBits, result)
