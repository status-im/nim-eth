import
  stew/ranges/[typedranges, bitranges],
  trie_defs, trie_utils

const
  treeHeight* = 160
  pathByteLen* = treeHeight div 8
  emptyLeafNodeHash* = blankStringHash

proc makeInitialEmptyTreeHash(H: static[int]): array[H, ByteRange] =
  result[^1] = @(emptyLeafNodeHash.data).toRange
  for i in countdown(H-1, 1):
    result[i - 1] = keccakHash(result[i], result[i])

# cannot yet turn this into compile time constant
let emptyNodeHashes* = makeInitialEmptyTreeHash(treeHeight)

# VerifyProof verifies a Merkle proof.
proc verifyProofAux*(proof: seq[ByteRange], root, key, value: ByteRange): bool =
  doAssert(root.len == 32)
  doAssert(key.len == pathByteLen)
  var
    path = MutByteRange(key).bits
    curHash = keccakHash(value)

  if proof.len != treeHeight: return false

  for i in countdown(treeHeight - 1, 0):
    var node = proof[i]
    if node.len != 32: return false
    if path[i]: # right
      # reuse curHash without more alloc
      curHash.keccakHash(node, curHash)
    else:
      curHash.keccakHash(curHash, node)

  result = curHash == root

template verifyProof*(proof: seq[ByteRange], root, key, value: distinct BytesContainer): bool =
  verifyProofAux(proof, root.toRange, key.toRange, value.toRange)

proc count(b: BitRange, val: bool): int =
  for c in b:
    if c == val: inc result

# CompactProof compacts a proof, to reduce its size.
proc compactProof*(proof: seq[ByteRange]): seq[ByteRange] =
  if proof.len != treeHeight: return

  var
    data = newRange[byte](pathByteLen)
    bits = MutByteRange(data).bits

  result = @[]
  result.add data
  for i in 0 ..< treeHeight:
    var node = proof[i]
    if node == emptyNodeHashes[i]:
      bits[i] = true
    else:
      result.add node

# decompactProof decompacts a proof, so that it can be used for VerifyProof.
proc decompactProof*(proof: seq[ByteRange]): seq[ByteRange] =
  if proof.len == 0: return
  if proof[0].len != pathByteLen: return
  var bits = MutByteRange(proof[0]).bits
  if proof.len != bits.count(false) + 1: return
  result = newSeq[ByteRange](treeHeight)

  var pos = 1 # skip bits
  for i in 0 ..< treeHeight:
    if bits[i]:
      result[i] = emptyNodeHashes[i]
    else:
      result[i] = proof[pos]
      inc pos

# verifyCompactProof verifies a compacted Merkle proof.
proc verifyCompactProofAux*(proof: seq[ByteRange], root, key, value: ByteRange): bool =
  var decompactedProof = decompactProof(proof)
  if decompactedProof.len == 0: return false
  verifyProofAux(decompactedProof, root, key, value)

template verifyCompactProof*(proof: seq[ByteRange], root, key, value: distinct BytesContainer): bool =
  verifyCompactProofAux(proof, root.toRange, key.toRange, value.toRange)
