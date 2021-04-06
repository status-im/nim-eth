import
  "."/[trie_bitseq, trie_defs, trie_utils]

const
  treeHeight* = 160
  pathByteLen* = treeHeight div 8
  emptyLeafNodeHash* = blankStringHash

proc makeInitialEmptyTreeHash(H: static[int]): array[H, KeccakHash] =
  result[^1] = emptyLeafNodeHash
  for i in countdown(H-1, 1):
    result[i - 1] = keccakHash(result[i].data, result[i].data)

# cannot yet turn this into compile time constant
let emptyNodeHashes* = makeInitialEmptyTreeHash(treeHeight)

# VerifyProof verifies a Merkle proof.
proc verifyProofAux*(proof: seq[seq[byte]], root, key, value: openArray[byte]): bool =
  doAssert(root.len == 32)
  doAssert(key.len == pathByteLen)
  var
    path = bits key
    curHash = keccakHash(value)

  if proof.len != treeHeight: return false

  for i in countdown(treeHeight - 1, 0):
    var node = proof[i]
    if node.len != 32: return false
    if path[i]: # right
      # reuse curHash without more alloc
      curHash.data.keccakHash(node, curHash.data)
    else:
      curHash.data.keccakHash(curHash.data, node)

  result = curHash.data == root

template verifyProof*(proof: seq[seq[byte]], root, key, value: openArray[byte]): bool =
  verifyProofAux(proof, root, key, value)

proc count(b: TrieBitSeq, val: bool): int =
  for c in b:
    if c == val: inc result

# CompactProof compacts a proof, to reduce its size.
proc compactProof*(proof: seq[seq[byte]]): seq[seq[byte]] =
  if proof.len != treeHeight: return

  var
    data = newSeq[byte](pathByteLen)
    bits = bits data

  result = @[]
  result.add @[]
  for i in 0 ..< treeHeight:
    var node = proof[i]
    if node == emptyNodeHashes[i].data:
      bits[i] = true
    else:
      result.add node
  result[0] = bits.toBytes

# decompactProof decompacts a proof, so that it can be used for VerifyProof.
proc decompactProof*(proof: seq[seq[byte]]): seq[seq[byte]] =
  if proof.len == 0: return
  if proof[0].len != pathByteLen: return
  let bits = bits proof[0]
  if proof.len != bits.count(false) + 1: return
  result = newSeq[seq[byte]](treeHeight)

  var pos = 1 # skip bits
  for i in 0 ..< treeHeight:
    if bits[i]:
      result[i] = @(emptyNodeHashes[i].data)
    else:
      result[i] = proof[pos]
      inc pos

# verifyCompactProof verifies a compacted Merkle proof.
proc verifyCompactProofAux*(proof: seq[seq[byte]], root, key, value: openArray[byte]): bool =
  var decompactedProof = decompactProof(proof)
  if decompactedProof.len == 0: return false
  verifyProofAux(decompactedProof, root, key, value)

template verifyCompactProof*(proof: seq[seq[byte]], root, key, value: openArray[byte]): bool =
  verifyCompactProofAux(proof, root, key, value)
