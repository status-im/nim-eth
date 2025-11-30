import
  secp256k1,
  stew/byteutils,
  "."/hashes,
  std/[net, sequtils],
  unittest2,
  ../trie/[hexary, db, hexary_proof_verification]

discard SkSecretKey.fromHex("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

suite "MPT trie proof verification":
  test "Validate proof for existing value":
    block:
      var db = newMemoryDB()
      var trie = initHexaryTrie(db)

      const bytes = @[0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
      trie.put(bytes, bytes)

      for _ in [0]:
        let
          proof = @[@[248'u8, 67, 161, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]] # trie.getBranch(bytes)
          root = Hash32([0x04'u8, 0xf4, 0xd4, 0x00, 0x43, 0x78, 0xc7, 0x62, 0xb2, 0xd8, 0xe0, 0x8f, 0x4b, 0x7c, 0xd6, 0xf2, 0xce, 0x43, 0x98, 0xb5, 0x7f, 0x3c, 0x62, 0xf4, 0x49, 0x0f, 0xc7, 0x3b, 0x7a, 0x0b, 0x2f, 0x4c]) # trie.rootHash()
          res = verifyMptProof(proof, root, bytes, bytes)

        doAssert res.isValid()
        check: res.value == bytes

    block:
      var db = newMemoryDB()
      var trie = initHexaryTrie(db)

      const bytes = @[0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
      trie.put(bytes, bytes)

      let
        nonExistingKey = toSeq([0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        proof = trie.getBranch(nonExistingKey)
        # proof = @[@[248'u8, 67, 161, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]] # trie.getBranch(nonExistingKey)
        root = Hash32([0x04'u8, 0xf4, 0xd4, 0x00, 0x43, 0x78, 0xc7, 0x62, 0xb2, 0xd8, 0xe0, 0x8f, 0x4b, 0x7c, 0xd6, 0xf2, 0xce, 0x43, 0x98, 0xb5, 0x7f, 0x3c, 0x62, 0xf4, 0x49, 0x0f, 0xc7, 0x3b, 0x7a, 0x0b, 0x2f, 0x4c]) # trie.rootHash()
        res = verifyMptProof(proof, root, nonExistingKey, nonExistingKey)

      doAssert res.isMissing()
