{.push raises: [Defect].}

import
  math, sequtils, ssz_serialization, options, algorithm,
  nimcrypto/hash,
  ../common/eth_types, ./types, ./merkleization

const maxTreeDepth: uint64 = 32
const empty: seq[Digest] = @[]

type
  MerkleNodeType = enum
    LeafType,
    NodeType,
    ZeroType

  MerkleNode = ref object
    case kind: MerkleNodeType
    of LeafType:
      digest: Digest
    of NodeType:
      innerDigest: Digest
      left: MerkleNode
      right: MerkleNode
    of ZeroType:
      depth: uint64

func zeroNodes(): seq[MerkleNode] =
  var nodes = newSeq[MerkleNode]()
  for i in 0..maxTreeDepth:
    nodes.add(MerkleNode(kind: ZeroType, depth: i))
  return nodes

let zNodes = zeroNodes()

# This look like something that should be in standard lib.
func splitAt[T](s: openArray[T], idx: uint64): (seq[T], seq[T]) =
  var lSeq = newSeq[T]()
  var rSeq = newSeq[T]()
  for i, e in s:
    if (uint64(i) < idx):
      lSeq.add(e)
    else:
      rSeq.add(e)
  (lSeq, rSeq)

func splitLeaves(l: openArray[Digest], cap: uint64): (seq[Digest], seq[Digest]) =
  if (uint64(len(l)) <= cap):
    (l.toSeq(), empty)
  else:
    splitAt(l, cap)

proc getSubTrees(node: MerkleNode): Option[(MerkleNode, MerkleNode)] =
  case node.kind
  of LeafType:
    return none[(MerkleNode, MerkleNode)]()
  of NodeType:
    return some((node.left, node.right))
  of ZeroType:
    if node.depth == 0:
      return none[(MerkleNode, MerkleNode)]()
    else:
      return some((zNodes[node.depth - 1], zNodes[node.depth - 1]))

func hash*(node: MerkleNode): Digest =
  case node.kind
  of LeafType:
    node.digest
  of NodeType:
    node.innerDigest
  of ZeroType:
    zeroHashes[node.depth]

func getCapacityAtDepth(depth: uint64): uint64 = 
  uint64 math.pow(2'f64, float64 depth)

func createTree*(leaves: openArray[Digest], depth: uint64): MerkleNode = 
  if len(leaves) == 0:
    return MerkleNode(kind: ZeroType, depth: depth)
  elif depth == 0:
    return MerkleNode(kind: LeafType, digest: leaves[0])
  else:
    let nexLevelDepth = depth - 1
    let subCap = getCapacityAtDepth(nexLevelDepth)
    let (left, right) = splitLeaves(leaves, subCap)
    let leftTree = createTree(left, nexLevelDepth)
    let rightTree = createTree(right, nexLevelDepth)
    let finalHash = mergeBranches(leftTree.hash(), rightTree.hash())
    return MerkleNode(kind: NodeType, innerDigest: finalHash, left: leftTree, right: rightTree) 

proc genProof*(tree: MerkleNode, idx: uint64, treeDepth: uint64): seq[Digest] =
  var proof = newSeq[Digest]()
  var currNode = tree
  var currDepth = treeDepth
  while currDepth > 0:
    let ithBit = (idx shr (currDepth - 1)) and 1
    # should be safe to call unsafeGet() as leaves are on lowest level, and depth is
    # always larger than 0
    let (left, right) = getSubTrees(currNode).unsafeGet()
    if ithBit == 1:
      proof.add(left.hash())
      currNode = right
    else:
      proof.add(right.hash())
      currNode = left
    currDepth = currDepth - 1

  proof.reverse()
  proof

# TODO add method to add leaf to the exisiting tree
