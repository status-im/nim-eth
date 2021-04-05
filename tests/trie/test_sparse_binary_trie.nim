{.used.}

import
  std/[unittest, random],
  stew/byteutils,
  ../../eth/trie/[db, sparse_binary, sparse_proofs],
  ./testutils

suite "sparse binary trie":
  randomize()
  var kv_pairs = randKVPair(20)
  var numbers = randList(int, randGen(1, 99), randGen(50, 100))
  var db = newMemoryDB()
  var trie = initSparseBinaryTrie(db)

  test "basic set":
    for c in kv_pairs:
      check trie.exists(c.key) == false
      trie.set(c.key, c.value)

  let prevRoot = trie.getRootHash()
  test "basic get":
    for c in kv_pairs:
      let x = trie.get(c.key)
      let y = c.value
      check x == y
      trie.del(c.key)

    for c in kv_pairs:
      check trie.exists(c.key) == false

    check trie.getRootHash() == keccakHash(emptyNodeHashes[0].data, emptyNodeHashes[0].data).data

  test "single update set":
    random.shuffle(kv_pairs)
    for c in kv_pairs:
      trie.set(c.key, c.value)

    # Check trie root remains the same even in different insert order
    check trie.getRootHash() == prevRoot

  let prior_to_update_root = trie.getRootHash()
  test "single update get":
    for i in numbers:
      # If new value is the same as current value, skip the update
      if toBytes($i) == trie.get(kv_pairs[i].key):
        continue
      # Update
      trie.set(kv_pairs[i].key, toBytes($i))
      check trie.get(kv_pairs[i].key) == toBytes($i)
      check trie.getRootHash() != prior_to_update_root

      # Un-update
      trie.set(kv_pairs[i].key, kv_pairs[i].value)
      check trie.getRootHash == prior_to_update_root

  test "batch update with different update order":
    # First batch update
    for i in numbers:
      trie.set(kv_pairs[i].key, toBytes($i))

    let batch_updated_root = trie.getRootHash()

    # Un-update
    random.shuffle(numbers)
    for i in numbers:
      trie.set(kv_pairs[i].key, kv_pairs[i].value)

    check trie.getRootHash() == prior_to_update_root

    # Second batch update
    random.shuffle(numbers)
    for i in numbers:
        trie.set(kv_pairs[i].key, toBytes($i))

    check trie.getRootHash() == batch_updated_root

  test "dictionary API":
    trie[kv_pairs[0].key] = kv_pairs[0].value
    let x = trie[kv_pairs[0].key]
    let y = kv_pairs[0].value
    check x == y
    check kv_pairs[0].key in trie

  test "get/set for specific root":
    db = newMemoryDB()
    trie = initSparseBinaryTrie(db)
    let
      testKey    = kv_pairs[0].key
      testValue  = kv_pairs[0].value
      testKey2   = kv_pairs[1].key
      testValue2 = kv_pairs[1].value

    trie.set(testKey, testValue)
    var root = trie.getRootHash()
    var value = trie.get(testKey, root)
    check value == testValue

    root = trie.set(testKey2, testValue2, root)
    value = trie.get(testKey2, root)
    check value == testValue2

    value = trie.get(testKey, root)
    check value == testValue

  proc makeBadProof(size: int, width = 32): seq[seq[byte]] =
    let badProofStr = randList(seq[byte], randGen(width, width), randGen(size, size))
    result = newSeq[seq[byte]](size)
    for i in 0 ..< result.len:
      result[i] = badProofStr[i]

  test "proofs":
    const
      MaxBadProof = 32 * 8

    let
      testKey   = kv_pairs[0].key
      badKey    = kv_pairs[1].key
      testValue = "testValue".toBytes
      testValue2 = "testValue2".toBytes
      badValue  = "badValue".toBytes
      badProof  = makeBadProof(MaxBadProof)

    trie[testKey] = testValue
    var proof = trie.prove(testKey)
    check proof.len == treeHeight
    check verifyProof(proof, trie.getRootHash(), testKey, testValue) == true
    check verifyProof(proof, trie.getRootHash(), testKey, badValue) == false
    check verifyProof(proof, trie.getRootHash(), badKey, testValue) == false
    check verifyProof(badProof, trie.getRootHash(), testKey, testValue) == false

    let
      testKey2  = kv_pairs[2].key
      testKey3  = kv_pairs[3].key
      defaultValue = default(seq[byte])

    trie.set(testKey2, testValue)
    proof = trie.prove(testKey)
    check verifyProof(proof, trie.getRootHash(), testKey, testValue) == true
    check verifyProof(proof, trie.getRootHash(), testKey, badValue) == false
    check verifyProof(proof, trie.getRootHash(), testKey2, testValue) == false
    check verifyProof(badProof, trie.getRootHash(), testKey, testValue) == false

    proof = trie.prove(testKey2)
    check verifyProof(proof, trie.getRootHash(), testKey2, testValue) == true
    check verifyProof(proof, trie.getRootHash(), testKey2, badValue) == false
    check verifyProof(proof, trie.getRootHash(), testKey3, testValue) == false
    check verifyProof(badProof, trie.getRootHash(), testKey, testValue) == false

    var compactProof = compactProof(proof)
    var decompactedProof = decompactProof(compactProof)

    check decompactedProof.len == proof.len
    for i, c in proof:
      check decompactedProof[i] == c

    let
      badProof2 = makeBadProof(MaxBadProof + 1)
      badProof3 = makeBadProof(MaxBadProof - 1)
      badProof4 = makeBadProof(MaxBadProof, 31)
      badProof5 = makeBadProof(MaxBadProof, 33)
      badProof6 = makeBadProof(MaxBadProof, 1)

    check verifyProof(badProof2, trie.getRootHash(), testKey3, defaultValue) == false
    check verifyProof(badProof3, trie.getRootHash(), testKey3, defaultValue) == false
    check verifyProof(badProof4, trie.getRootHash(), testKey3, defaultValue) == false
    check verifyProof(badProof5, trie.getRootHash(), testKey3, defaultValue) == false
    check verifyProof(badProof6, trie.getRootHash(), testKey3, defaultValue) == false

    check compactProof(badProof2).len == 0
    check compactProof(badProof3).len == 0
    check decompactProof(badProof3).len == 0
    var zeroProof: seq[seq[byte]]
    check decompactProof(zeroProof).len == 0

    proof = trie.proveCompact(testKey2)
    check verifyCompactProof(proof, trie.getRootHash(), testKey2, testValue) == true
    check verifyCompactProof(proof, trie.getRootHash(), testKey2, badValue) == false
    check verifyCompactProof(proof, trie.getRootHash(), testKey3, testValue) == false
    check verifyCompactProof(badProof, trie.getRootHash(), testKey, testValue) == false

    var root = trie.getRootHash()
    trie.set(testKey2, testValue2)

    proof = trie.proveCompact(testKey2, root)
    check verifyCompactProof(proof, root, testKey2, testValue) == true
    check verifyCompactProof(proof, root, testKey2, badValue) == false
    check verifyCompactProof(proof, root, testKey3, testValue) == false
    check verifyCompactProof(badProof, root, testKey, testValue) == false

    proof = trie.prove(testKey2, root)
    check verifyProof(proof, root, testKey2, testValue) == true
    check verifyProof(proof, root, testKey2, badValue) == false
    check verifyProof(proof, root, testKey3, testValue) == false
    check verifyProof(badProof, root, testKey, testValue) == false

    proof = trie.prove(testKey3)
    check proof.len == 0
    check verifyProof(proof, trie.getRootHash(), testKey3, defaultValue) == false
    check verifyProof(proof, trie.getRootHash(), testKey3, badValue) == false
    check verifyProof(proof, trie.getRootHash(), testKey2, defaultValue) == false
    check verifyProof(badProof, trie.getRootHash(), testKey, testValue) == false

  test "examples":
    let
      key1 = "01234567890123456789".toBytes
      key2 = "abcdefghijklmnopqrst".toBytes

    trie.set(key1, "value1".toBytes)
    trie.set(key2, "value2".toBytes)
    check trie.get(key1) == "value1".toBytes
    check trie.get(key2) == "value2".toBytes

    trie.del(key1)
    check trie.get(key1) == []

    trie.del(key2)
    check trie[key2] == []

    let
      value1 = "hello world".toBytes
      badValue = "bad value".toBytes

    trie[key1] = value1
    var proof = trie.prove(key1)

    check verifyProof(proof, trie.getRootHash(), key1, value1) == true
    check verifyProof(proof, trie.getRootHash(), key1, badValue) == false
    check verifyProof(proof, trie.getRootHash(), key2, value1) == false
