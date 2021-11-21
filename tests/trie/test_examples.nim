{.used.}

import
  unittest2,
  stew/byteutils, nimcrypto/[keccak, hash],
  ../../eth/trie/[db, binary, binaries, trie_utils, branches]

suite "examples":

  var db = newMemoryDB()
  var trie = initBinaryTrie(db)

  test "basic set/get":
    trie.set("key1".toBytes(), "value1".toBytes())
    trie.set("key2".toBytes(), "value2".toBytes())
    check trie.get("key1".toBytes) == "value1".toBytes
    check trie.get("key2".toBytes) == "value2".toBytes

  test "check branch exists":
    check checkIfBranchExist(db, trie.getRootHash(), "key".toBytes) == true
    check checkIfBranchExist(db, trie.getRootHash(), "key1".toBytes) == true
    check checkIfBranchExist(db, trie.getRootHash(), "ken".toBytes) == false
    check checkIfBranchExist(db, trie.getRootHash(), "key123".toBytes) == false

  test "branches utils":
    var branchA = getBranch(db, trie.getRootHash(), "key1".toBytes)
    # ==> [A, B, C1, D1]
    check branchA.len == 4

    var branchB = getBranch(db, trie.getRootHash(), "key2".toBytes)
    # ==> [A, B, C2, D2]
    check branchB.len == 4

    check isValidBranch(branchA, trie.getRootHash(), "key1".toBytes, "value1".toBytes) == true
    check isValidBranch(branchA, trie.getRootHash(), "key5".toBytes, "".toBytes) == true

    expect InvalidNode:
      check isValidBranch(branchB, trie.getRootHash(), "key1".toBytes, "value1".toBytes)

    var x = getBranch(db, trie.getRootHash(), "key".toBytes)
    # ==> [A]
    check x.len == 1

    expect InvalidKeyError:
      x = getBranch(db, trie.getRootHash(), "key123".toBytes) # InvalidKeyError

    x = getBranch(db, trie.getRootHash(), "key5".toBytes) # there is still branch for non-exist key
    # ==> [A]
    check x.len == 1

  test "getWitness":
    var branch = getWitness(db, trie.getRootHash(), "key1".toBytes)
    # equivalent to `getBranch(db, trie.getRootHash(), "key1")`
    # ==> [A, B, C1, D1]
    check branch.len == 4

    branch = getWitness(db, trie.getRootHash(), "key".toBytes)
    # this will include additional nodes of "key2"
    # ==> [A, B, C1, D1, C2, D2]
    check branch.len == 6

    branch = getWitness(db, trie.getRootHash(), "".toBytes)
    # this will return the whole trie
    # ==> [A, B, C1, D1, C2, D2]
    check branch.len == 6

  let beforeDeleteLen = db.totalRecordsInMemoryDB
  test "verify intermediate entries existence":
    var branchs = getWitness(db, trie.getRootHash, [])
    # set operation create new intermediate entries
    check branchs.len < beforeDeleteLen

    var node = branchs[1]
    let nodeHash = keccak256.digest(node)
    var nodes = getTrieNodes(db, @(nodeHash.data))
    check nodes.len == branchs.len - 1

  test "delete sub trie":
    # delete all subtrie with key prefixes "key"
    trie.deleteSubtrie("key".toBytes)
    check trie.get("key1".toBytes) == []
    check trie.get("key2".toBytes) == []

  test "prove the lie":
    # `delete` and `deleteSubtrie` not actually delete the nodes
    check db.totalRecordsInMemoryDB == beforeDeleteLen
    var branchs = getWitness(db, trie.getRootHash, [])
    check branchs.len == 0

  test "dictionary syntax API":
    # dictionary syntax API
    trie["moon".toBytes] = "sun".toBytes
    check "moon".toBytes in trie
    check trie["moon".toBytes] == "sun".toBytes
