{.used.}

import
  std/random,
  unittest2,
  stew/byteutils,
  ../../eth/trie/[db, binary],
  ./testutils

suite "binary trie":

  test "different order insert":
    randomize()
    var kv_pairs = randKVPair()
    var result = zeroHash
    for _ in 0..<1: # repeat 3 times
      var db = newMemoryDB()
      var trie = initBinaryTrie(db)
      random.shuffle(kv_pairs)

      for i, c in kv_pairs:
        trie.set(c.key, c.value)
        let x = trie.get(c.key)
        let y = c.value
        check y == x

      check result == zeroHash or trie.getRootHash() == result
      result = trie.getRootHash()

      # insert already exist key/value
      trie.set(kv_pairs[0].key, kv_pairs[0].value)
      check trie.getRootHash() == result

      # Delete all key/value
      random.shuffle(kv_pairs)
      for i, c in kv_pairs:
        trie.delete(c.key)
      check trie.getRootHash() == zeroHash

  const delSubtrieData = [
    (("\x12\x34\x56\x78", "78"), ("\x12\x34\x56\x79", "79"), "\x12\x34\x56", true, false),
    (("\x12\x34\x56\x78", "78"), ("\x12\x34\x56\xff", "ff"), "\x12\x34\x56", true, false),
    (("\x12\x34\x56\x78", "78"), ("\x12\x34\x56\x79", "79"), "\x12\x34\x57", false, false),
    (("\x12\x34\x56\x78", "78"), ("\x12\x34\x56\x79", "79"), "\x12\x34\x56\x78\x9a", false, true)
    ]

  test "delete subtrie":
    for data in delSubtrieData:
      var db = newMemoryDB()
      var trie = initBinaryTrie(db)

      let kv1 = data[0]
      let kv2 = data[1]
      let key_to_be_deleted = data[2]
      let will_delete = data[3]
      let will_raise_error = data[4]

      # First test case, delete subtrie of a kv node
      trie.set(kv1[0].toBytes, kv1[1].toBytes)
      trie.set(kv2[0].toBytes, kv2[1].toBytes)
      check trie.get(kv1[0].toBytes) == kv1[1].toBytes
      check trie.get(kv2[0].toBytes) == kv2[1].toBytes

      if will_delete:
        trie.deleteSubtrie(key_to_be_deleted.toBytes)
        check trie.get(kv1[0].toBytes) == []
        check trie.get(kv2[0].toBytes) == []
        check trie.getRootHash() == zeroHash
      else:
        if will_raise_error:
          try:
            trie.deleteSubtrie(key_to_be_deleted.toBytes)
          except NodeOverrideError:
            discard
        else:
          let root_hash_before_delete = trie.getRootHash()
          trie.deleteSubtrie(key_to_be_deleted.toBytes)
          check trie.get(kv1[0].toBytes) == toBytes(kv1[1])
          check trie.get(kv2[0].toBytes) == toBytes(kv2[1])
          check trie.getRootHash() == root_hash_before_delete

  const invalidKeyData = [
    ("\x12\x34\x56", false),
    ("\x12\x34\x56\x77", false),
    ("\x12\x34\x56\x78\x9a", true),
    ("\x12\x34\x56\x79\xab", true),
    ("\xab\xcd\xef", false)
    ]

  test "invalid key":
   for data in invalidKeyData:
      var db = newMemoryDB()
      var trie = initBinaryTrie(db)

      trie.set("\x12\x34\x56\x78".toBytes, "78".toBytes)
      trie.set("\x12\x34\x56\x79".toBytes, "79".toBytes)

      let invalidKey = data[0]
      let if_error = data[1]

      check trie.get(invalidKey.toBytes) == []

      if if_error:
        try:
          trie.delete(invalidKey.toBytes)
        except NodeOverrideError:
          discard
      else:
        let previous_root_hash = trie.getRootHash()
        trie.delete(invalidKey.toBytes)
        check previous_root_hash == trie.getRootHash()

  test "update value":
    let keys = randList(string, randGen(32, 32), randGen(100, 100))
    let vals = randList(int, randGen(0, 99), randGen(50, 50))
    var db = newMemoryDB()
    var trie = initBinaryTrie(db)
    for key in keys:
      trie.set(key.toBytes, "old".toBytes)

    var current_root = trie.getRootHash()
    for i in vals:
      trie.set(keys[i].toBytes, "old".toBytes)
      check current_root == trie.getRootHash()
      trie.set(keys[i].toBytes, "new".toBytes)
      check current_root != trie.getRootHash()
      check trie.get(keys[i].toBytes) == toBytes("new")
      current_root = trie.getRootHash()
