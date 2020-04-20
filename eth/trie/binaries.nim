import
  sequtils,
  stew/ranges/ptr_arith, trie_defs,
  ./trie_bitseq

type
  TrieNodeKind* = enum
    KV_TYPE = 0
    BRANCH_TYPE = 1
    LEAF_TYPE = 2

  TrieNodeKey* = seq[byte]

  TrieNode* = object
    case kind*: TrieNodeKind
    of KV_TYPE:
      keyPath*: TrieBitSeq
      child*: TrieNodeKey
    of BRANCH_TYPE:
      leftChild*: TrieNodeKey
      rightChild*: TrieNodeKey
    of LEAF_TYPE:
      value*: seq[byte]

  InvalidNode* = object of CorruptedTrieDatabase
  ValidationError* = object of CorruptedTrieDatabase

# ----------------------------------------------
template sliceToEnd*(r: TrieBitSeq, index: int): TrieBitSeq =
  if r.len <= index: TrieBitSeq() else: r[index .. ^1]

proc decodeToBinKeypath*(path: seq[byte]): TrieBitSeq =
  ## Decodes bytes into a sequence of 0s and 1s
  ## Used in decoding key path of a KV-NODE
  var path = path.bits
  if path[0]:
    path = path[4..^1]

  doAssert path[0] == false
  doAssert path[1] == false
  var bits = path[2].int shl 1
  bits = bits or path[3].int

  if path.len > 4:
    path[4+((4 - bits) mod 4)..^1]
  else:
    TrieBitSeq()

proc parseNode*(node: openArray[byte]): TrieNode =
  # Input: a serialized node

  if node.len == 0:
    raise newException(InvalidNode, "Blank node is not a valid node type in Binary Trie")

  if node[0].ord < low(TrieNodeKind).ord or node[0].ord > high(TrieNodeKind).ord:
    raise newException(InvalidNode, "Invalid node type")

  let nodeType = node[0].TrieNodeKind
  case nodeType
  of BRANCH_TYPE:
    if node.len != 65:
      raise newException(InvalidNode, "Invalid branch node, both child node should be 32 bytes long each")
    # Output: node type, left child, right child
    result = TrieNode(kind: BRANCH_TYPE, leftChild: node[1..<33], rightChild: node[33..^1])
    doAssert(result.leftChild.len == 32)
    doAssert(result.rightChild.len == 32)
    return result
  of KV_TYPE:
    if node.len <= 33:
      raise newException(InvalidNode, "Invalid kv node, short of key path or child node hash")
    # Output: node type, keypath, child
    return TrieNode(kind: KV_TYPE, keyPath: decodeToBinKeypath(node[1..^33]), child: node[^32..^1])
  of LEAF_TYPE:
    if node.len == 1:
      raise newException(InvalidNode, "Invalid leaf node, can not contain empty value")
    # Output: node type, value
    return TrieNode(kind: LEAF_TYPE, value: node[1..^1])

proc encodeKVNode*(keyPath: TrieBitSeq, childHash: TrieNodeKey): seq[byte] =
  ## Serializes a key/value node
  if keyPath.len == 0:
    raise newException(ValidationError, "Key path can not be empty")

  if childHash.len != 32:
    raise newException(ValidationError, "Invalid hash len")

  # Encodes a sequence of 0s and 1s into tightly packed bytes
  # Used in encoding key path of a KV-NODE
  # KV-NODE = KV-TYPE-PREFIX + encoded keypath + 32 bytes hash
  let
    len = keyPath.len
    padding = ((not len) + 1) and 3 # modulo 4 padding
    paddedBinLen = len + padding
    prefix = len mod 4

  result = newSeq[byte](((len + padding) div 8) + 34)
  result[0] = KV_TYPE.byte
  if paddedBinLen mod 8 == 4:
    var nbits = 4 - padding
    result[1] = byte(prefix shl 4) or byte.fromBits(keyPath, 0, nbits)
    for i in 0..<(len div 8):
      result[i+2] = byte.fromBits(keyPath, nbits, 8)
      inc(nbits, 8)
  else:
    var nbits = 8 - padding
    result[1] = byte(0b1000_0000) or byte(prefix)
    result[2] = byte.fromBits(keyPath, 0, nbits)
    for i in 0..<((len-1) div 8):
      result[i+3] = byte.fromBits(keyPath, nbits, 8)
      inc(nbits, 8)
  copyMem(result[^32].addr, childHash.baseAddr, 32)

proc encodeKVNode*(keyPath: bool, childHash: TrieNodeKey): seq[byte] =
  result = newSeq[byte](34)
  result[0] = KV_TYPE.byte
  result[1] = byte(16) or byte(keyPath)
  copyMem(result[^32].addr, childHash.baseAddr, 32)

proc encodeBranchNode*(leftChildHash, rightChildHash: TrieNodeKey): seq[byte] =
  ## Serializes a branch node
  const
    BRANCH_TYPE_PREFIX = @[BRANCH_TYPE.byte]

  if leftChildHash.len != 32 or rightChildHash.len != 32:
    raise newException(ValidationError, "encodeBranchNode: Invalid hash len")

  result = BRANCH_TYPE_PREFIX.concat(leftChildHash, rightChildHash)

proc encodeLeafNode*(value: openArray[byte]): seq[byte] =
  ## Serializes a leaf node
  const
    LEAF_TYPE_PREFIX = @[LEAF_TYPE.byte]

  if value.len == 0:
    raise newException(ValidationError, "Value of leaf node can not be empty")

  result = LEAF_TYPE_PREFIX.concat(@value)

proc getCommonPrefixLength*(a, b: TrieBitSeq): int =
  let len = min(a.len, b.len)
  for i in 0..<len:
    if a[i] != b[i]: return i
  result = len
