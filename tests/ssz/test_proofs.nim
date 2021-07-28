{.used.}

import 
  sequtils, unittest, math,
  nimcrypto/[hash, sha2],
  stew/endians2,
  ../eth/ssz/merkleization,
  ../eth/ssz/ssz_serialization,
  ../eth/ssz/merkle_tree

template toSszType(x: auto): auto =
    x

proc h(a: openArray[byte]): Digest =
  var h: sha256
  h.init()
  h.update(a)
  h.finish()

type TestObject = object
  digest: array[32, byte]
  num: uint64

proc genObject(num: uint64): TestObject =
  let numAsHash = h(num.toBytesLE())
  TestObject(digest: numAsHash.data, num: num)

proc genNObjects(n: int): seq[TestObject] =
  var objs = newSeq[TestObject]()
  for i in 1..n:
    let obj = genObject(uint64 i)
    objs.add(obj)
  objs

proc getGenIndex(idx: int, depth: uint64): uint64 =
  uint64 (math.pow(2'f64, float64 depth) + float64 idx)

# Normal hash_tree_root add list length to final hash calculation. Proofs by default
# are generated without it. If necessary length of the list can be added manually
# at the end of the proof but here we are just hashing list with no mixin.
proc getListRootNoMixin(list: List): Digest =
  var merk = createMerkleizer(list.maxLen)
  for e in list:
    let hash = hash_tree_root(e)
    merk.addChunk(hash.data)
  merk.getFinalHash()

type TestCase = object
  numOfElements: int
  limit: int

const TestCases = (
  TestCase(numOfElements: 0, limit: 2),
  TestCase(numOfElements: 1, limit: 2),
  TestCase(numOfElements: 2, limit: 2),

  TestCase(numOfElements: 0, limit: 4),
  TestCase(numOfElements: 1, limit: 4),
  TestCase(numOfElements: 2, limit: 4),
  TestCase(numOfElements: 3, limit: 4),
  TestCase(numOfElements: 4, limit: 4),

  TestCase(numOfElements: 0, limit: 8),
  TestCase(numOfElements: 1, limit: 8),
  TestCase(numOfElements: 2, limit: 8),
  TestCase(numOfElements: 3, limit: 8),
  TestCase(numOfElements: 4, limit: 8),
  TestCase(numOfElements: 5, limit: 8),
  TestCase(numOfElements: 6, limit: 8),
  TestCase(numOfElements: 7, limit: 8),
  TestCase(numOfElements: 8, limit: 8),

  TestCase(numOfElements: 0, limit: 16),
  TestCase(numOfElements: 1, limit: 16),
  TestCase(numOfElements: 2, limit: 16),
  TestCase(numOfElements: 3, limit: 16),
  TestCase(numOfElements: 4, limit: 16),
  TestCase(numOfElements: 5, limit: 16),
  TestCase(numOfElements: 6, limit: 16),
  TestCase(numOfElements: 7, limit: 16),
  TestCase(numOfElements: 16, limit: 16),

  TestCase(numOfElements: 32, limit: 32),

  TestCase(numOfElements: 64, limit: 64)
)

suite "Merkle Proof generation":
  test "generation of proof for various tree sizes":
    for testCase in TestCases.fields:
      let testObjects = genNObjects(testCase.numOfElements)
      let treeDepth = uint64 binaryTreeHeight(testCase.limit) - 1

      # Create List and and genereate root by using merkelizer
      let list = List.init(testObjects, testCase.limit)
      let listRoot = getListRootNoMixin(list)
      
      # Create sparse merkle tree from list elements and generate root
      let listDigests = map(testObjects, proc(x: TestObject): Digest = hash_tree_root(x))
      let tree = createTree(listDigests, treeDepth)
      let treeHash = tree.hash()

      # Assert that by using both methods we get same hash
      check listRoot == treeHash
      
      for i, e in list:
        # generate proof by using merkelizer
        let merkleizerProof = generateAndGetProofWithIdx(list, i)
        # generate proof by sparse merkle tree
        let sparseTreeProof = genProof(tree, uint64 i, treeDepth)

        let leafHash = hash_tree_root(e)
        let genIndex = getGenIndex(i, treeDepth)

        # both proof are valid. If both are valid that means that both proof are
        # effectivly the same
        let isValidProof = isValidProof(leafHash , merkleizerProof, genIndex, listRoot)
        let isValidProof1 = isValidProof(leafHash , sparseTreeProof, genIndex, listRoot)

        check isValidProof
        check isValidProof1


