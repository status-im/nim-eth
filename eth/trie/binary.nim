import
  "."/[trie_bitseq, trie_defs, db, binaries, trie_utils]

export
  trie_utils

type
  DB = TrieDatabaseRef

  BinaryTrie* = object
    db: DB
    rootHash: TrieNodeKey

  NodeOverrideError* = object of CatchableError

const
  zeroHash* = default(seq[byte])

proc init*(x: typedesc[BinaryTrie], db: DB,
           rootHash: openArray[byte]): BinaryTrie =
  checkValidHashZ(rootHash)
  result.db = db
  result.rootHash = @(rootHash)

proc getDB*(t: BinaryTrie): auto = t.db

proc initBinaryTrie*(db: DB, rootHash: openArray[byte]): BinaryTrie =
  init(BinaryTrie, db, rootHash)

proc initBinaryTrie*(db: DB): BinaryTrie =
  init(BinaryTrie, db, zeroHash)

proc getRootHash*(self: BinaryTrie): TrieNodeKey {.inline.} =
  self.rootHash

template fetchNode(self: BinaryTrie, nodeHash: TrieNodeKey): TrieNode =
  doAssert(nodeHash.len == 32)
  parseNode self.db.get(nodeHash)

proc getAux(self: BinaryTrie, nodeHash: TrieNodeKey, keyPath: TrieBitSeq): seq[byte] =
  # Empty trie
  if isZeroHash(nodeHash):
    return

  let node = self.fetchNode(nodeHash)

  # Key-value node descend
  if node.kind == LEAF_TYPE:
    if keyPath.len != 0: return
    return node.value
  elif node.kind == KV_TYPE:
    # keyPath too short
    if keyPath.len == 0: return
    let sliceLen = min(node.keyPath.len, keyPath.len)
    if keyPath[0..<sliceLen] == node.keyPath:
      return self.getAux(node.child, keyPath.sliceToEnd(node.keyPath.len))
    else:
      return
  # Branch node descend
  elif node.kind == BRANCH_TYPE:
    # keyPath too short
    if keyPath.len == 0: return
    if keyPath[0]: # first bit == 1
      return self.getAux(node.rightChild, keyPath.sliceToEnd(1))
    else:
      return self.getAux(node.leftChild, keyPath.sliceToEnd(1))

proc get*(self: BinaryTrie, key: openArray[byte]): seq[byte] {.inline.} =
  var keyBits = key.bits
  return self.getAux(self.rootHash, keyBits)

proc hashAndSave*(self: BinaryTrie, node: openArray[byte]): TrieNodeKey =
  result = @(keccakHash(node).data)
  self.db.put(result, node)

template saveKV(self: BinaryTrie, keyPath: TrieBitSeq | bool, child: openArray[byte]): untyped =
  self.hashAndSave(encodeKVNode(keyPath, child))

template saveLeaf(self: BinaryTrie, value: openArray[byte]): untyped =
  self.hashAndSave(encodeLeafNode(value))

template saveBranch(self: BinaryTrie, L, R: openArray[byte]): untyped =
  self.hashAndSave(encodeBranchNode(L, R))

proc setBranchNode(self: BinaryTrie, keyPath: TrieBitSeq, node: TrieNode,
  value: openArray[byte], deleteSubtrie = false): TrieNodeKey
proc setKVNode(self: BinaryTrie, keyPath: TrieBitSeq, nodeHash: TrieNodeKey,
  node: TrieNode, value: openArray[byte], deleteSubtrie = false): TrieNodeKey

const
  overrideErrorMsg =
    "Fail to set the value because the prefix of it's key is the same as existing key"

proc setAux(self: BinaryTrie, nodeHash: TrieNodeKey, keyPath: TrieBitSeq,
  value: openArray[byte], deleteSubtrie = false): TrieNodeKey =
  ## If deleteSubtrie is set to True, what it will do is that it take in a keyPath
  ## and traverse til the end of keyPath, then delete the whole subtrie of that node.
  ## Note: keyPath should be in binary array format, i.e., encoded by encode_to_bin()

  template checkBadKeyPath(): untyped =
    # keyPath too short
    if keyPath.len == 0:
      if deleteSubtrie: return zeroHash
      else: raise newException(NodeOverrideError, overrideErrorMsg)

  template ifGoodValue(body: untyped): untyped =
    if value.len != 0: body
    else: return zeroHash

  # Empty trie
  if isZeroHash(nodeHash):
    ifGoodValue:
      return self.saveKV(keyPath, self.saveLeaf(value))

  let node = self.fetchNode(nodeHash)

  case node.kind
  of LEAF_TYPE:   # Node is a leaf node
    # keyPath must match, there should be no remaining keyPath
    if keyPath.len != 0:
      raise newException(NodeOverrideError, overrideErrorMsg)
    if deleteSubtrie: return zeroHash

    ifGoodValue:
      return self.saveLeaf(value)
  of KV_TYPE:     # node is a key-value node
    checkBadKeyPath()
    return self.setKVNode(keyPath, nodeHash, node, value, deleteSubtrie)
  of BRANCH_TYPE: # node is a branch node
    checkBadKeyPath()
    return self.setBranchNode(keyPath, node, value, deleteSubtrie)

proc set*(self: var BinaryTrie, key, value: openArray[byte]) {.inline.} =
  ## Sets the value at the given keyPath from the given node
  ## Key will be encoded into binary array format first.

  var keyBits = key.bits
  self.rootHash = self.setAux(self.rootHash, keyBits, value)

proc setBranchNode(self: BinaryTrie, keyPath: TrieBitSeq, node: TrieNode,
  value: openArray[byte], deleteSubtrie = false): TrieNodeKey =
  # Which child node to update? Depends on first bit in keyPath
  var newLeftChild, newRightChild: TrieNodeKey

  if keyPath[0]: # first bit == 1
    newRightChild = self.setAux(node.rightChild, keyPath[1..^1], value, deleteSubtrie)
    newLeftChild  = node.leftChild
  else:
    newLeftChild  = self.setAux(node.leftChild, keyPath[1..^1], value, deleteSubtrie)
    newRightChild = node.rightChild

  let blankLeft = isZeroHash(newLeftChild)

  # Compress branch node into kv node
  if blankLeft or isZeroHash(newRightChild):
    let childNode = if blankLeft: newRightChild else: newLeftChild
    var subNode = self.fetchNode(childNode)

    # Compress (k1, (k2, NODE)) -> (k1 + k2, NODE)
    if subNode.kind == KV_TYPE:
      # exploit subNode.keyPath unused prefix bit
      # to avoid bitVector concat
      subNode.keyPath.pushFront(blankLeft)
      result = self.saveKV(subNode.keyPath, subNode.child)
    # kv node pointing to a branch node
    elif subNode.kind in {BRANCH_TYPE, LEAF_TYPE}:
      result = self.saveKV(blankLeft, childNode)
  else:
    result = self.saveBranch(newLeftChild, newRightChild)

proc setKVNode(self: BinaryTrie, keyPath: TrieBitSeq, nodeHash: TrieNodeKey,
  node: TrieNode, value: openArray[byte], deleteSubtrie = false): TrieNodeKey =
  # keyPath prefixes match
  if deleteSubtrie:
    if keyPath.len < node.keyPath.len and keyPath == node.keyPath[0..<keyPath.len]:
      return zeroHash

  let sliceLen = min(node.keyPath.len, keyPath.len)

  if keyPath[0..<sliceLen] == node.keyPath:
    # Recurse into child
    let subNodeHash = self.setAux(node.child,
      keyPath.sliceToEnd(node.keyPath.len), value, deleteSubtrie)

    # If child is empty
    if isZeroHash(subNodeHash):
      return zeroHash
    let subNode = self.fetchNode(subNodeHash)

    # If the child is a key-value node, compress together the keyPaths
    # into one node
    if subNode.kind == KV_TYPE:
      return self.saveKV(node.keyPath & subNode.keyPath, subNode.child)
    else:
      return self.saveKV(node.keyPath, subNodeHash)
  # keyPath prefixes don't match. Here we will be converting a key-value node
  # of the form (k, CHILD) into a structure of one of the following forms:
  # 1.    (k[:-1], (NEWCHILD, CHILD))
  # 2.    (k[:-1], ((k2, NEWCHILD), CHILD))
  # 3.    (k1, ((k2, CHILD), NEWCHILD))
  # 4.    (k1, ((k2, CHILD), (k2', NEWCHILD))
  # 5.    (CHILD, NEWCHILD)
  # 6.    ((k[1:], CHILD), (k', NEWCHILD))
  # 7.    ((k[1:], CHILD), NEWCHILD)
  # 8.    (CHILD, (k[1:], NEWCHILD))
  else:
    let
      commonPrefixLen = getCommonPrefixLength(node.keyPath, keyPath[0..<sliceLen])
      cplenPlusOne    = commonPrefixLen + 1
    # New key-value pair can not contain empty value
    # Or one can not delete non-exist subtrie
    if value.len == 0 or deleteSubtrie: return nodeHash

    var valNode, oldNode, newSub: TrieNodeKey
    # valnode: the child node that has the new value we are adding
    # Case 1: keyPath prefixes almost match, so we are in case (1), (2), (5), (6)
    if keyPath.len == cplenPlusOne:
      valNode = self.saveLeaf(value)
    # Case 2: keyPath prefixes mismatch in the middle, so we need to break
    # the keyPath in half. We are in case (3), (4), (7), (8)
    else:
      if keyPath.len <= commonPrefixLen:
        raise newException(NodeOverrideError, overrideErrorMsg)
      valNode = self.saveKV(keyPath[cplenPlusOne..^1], self.saveLeaf(value))

    # oldnode: the child node the has the old child value
    # Case 1: (1), (3), (5), (6)
    if node.keyPath.len == cplenPlusOne:
      oldNode = node.child
    # (2), (4), (6), (8)
    else:
      oldNode = self.saveKV(node.keyPath[cplenPlusOne..^1], node.child)

    # Create the new branch node (because the key paths diverge, there has to
    # be some "first bit" at which they diverge, so there must be a branch
    # node somewhere)
    if keyPath[commonPrefixLen]: # first bit == 1
      newSub = self.saveBranch(oldNode, valNode)
    else:
      newSub = self.saveBranch(valNode, oldNode)

    # Case 1: keyPath prefixes match in the first bit, so we still need
    # a kv node at the top
    # (1) (2) (3) (4)
    if commonPrefixLen != 0:
      return self.saveKV(node.keyPath[0..<commonPrefixLen], newSub)
    # Case 2: keyPath prefixes diverge in the first bit, so we replace the
    # kv node with a branch node
    # (5) (6) (7) (8)
    else:
      return newSub

template exists*(self: BinaryTrie, key: openArray[byte]): bool =
  self.get(key) != []

proc delete*(self: var BinaryTrie, key: openArray[byte]) {.inline.} =
  ## Equals to setting the value to zeroBytesRange
  var keyBits = key.bits
  self.rootHash = self.setAux(self.rootHash, keyBits, [])

proc deleteSubtrie*(self: var BinaryTrie, key: openArray[byte]) {.inline.} =
  ## Given a key prefix, delete the whole subtrie that starts with the key prefix.
  ## Key will be encoded into binary array format first.
  ## It will call `setAux` with `deleteSubtrie` set to true.

  var keyBits = key.bits
  self.rootHash = self.setAux(self.rootHash, keyBits, [], true)

# Convenience
proc rootNode*(self: BinaryTrie): seq[byte] {.inline.} =
  self.db.get(self.rootHash)

proc rootNode*(self: var BinaryTrie, node: openArray[byte]) {.inline.} =
  self.rootHash = self.hashAndSave(node)

# Dictionary API
template `[]`*(self: BinaryTrie, key: seq[byte]): seq[byte] =
  self.get(key)

template `[]=`*(self: var BinaryTrie, key, value: seq[byte]) =
  self.set(key, value)

template contains*(self: BinaryTrie, key: seq[byte]): bool =
  self.exists(key)
