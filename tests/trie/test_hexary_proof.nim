# proof verification
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

{.push raises: [].}

import
  std/sequtils,
  unittest2,
  stint,
  stew/byteutils,
  ../../eth/trie/[hexary, db, trie_defs, hexary_proof_verification]

proc getKeyBytes(i: int): seq[byte] =
  @(u256(i).toBytesBE())

suite "MPT trie proof verification":
  test "Validate proof for existing value":
    let numValues = 1000
    var db = newMemoryDB()
    var trie = initHexaryTrie(db)

    for i in 1..numValues:
      let bytes = getKeyBytes(i)

      trie.put(bytes, bytes)

    for i in 1..numValues:
      let
        kv = getKeyBytes(i)
        proof = trie.getBranch(kv)
        root = trie.rootHash()
        res = verifyMptProof(proof, root, kv, kv)

      check:
        res.isValid()
        res.value == kv

  test "Validate proof for non-existing value":
    let numValues = 1000
    var db = newMemoryDB()
    var trie = initHexaryTrie(db)

    for i in 1..numValues:
      let bytes = getKeyBytes(i)
      trie.put(bytes, bytes)

    let
      nonExistingKey = toSeq(toBytesBE(u256(numValues + 1)))
      proof = trie.getBranch(nonExistingKey)
      root = trie.rootHash()
      res = verifyMptProof(proof, root, nonExistingKey, nonExistingKey)

    check:
      res.isMissing()

  # The following test cases were copied from the Rust hexary trie implementation.
  # See here: https://github.com/citahub/cita_trie/blob/master/src/tests/mod.rs#L554
  test "Validate proof for empty trie":
    let db = newMemoryDB()
    var trie = initHexaryTrie(db)

    let
      proof = trie.getBranch("not-exist".toBytes)
      res = verifyMptProof(proof, trie.rootHash, "not-exist".toBytes, "not-exist".toBytes)

    check:
      trie.rootHash == keccak256(emptyRlp)
      proof.len() == 1 # Note that the Rust implementation returns an empty list for this scenario
      proof == @[emptyRlp]
      res.kind == InvalidProof

  test "Validate proof for one element trie":
    let db = newMemoryDB()
    var trie = initHexaryTrie(db)

    trie.put("k".toBytes, "v".toBytes)

    let
      rootHash = trie.rootHash
      proof = trie.getBranch("k".toBytes)
      res = verifyMptProof(proof, rootHash, "k".toBytes, "v".toBytes)

    check:
      proof.len() == 1
      res.isValid()

    # removing key does not affect the verify process
    trie.del("k".toBytes)
    check verifyMptProof(proof, rootHash, "k".toBytes, "v".toBytes).isValid()

  test "Validate proof bytes":
    let db = newMemoryDB()
    var trie = initHexaryTrie(db)

    trie.put("doe".toBytes, "reindeer".toBytes)
    trie.put("dog".toBytes, "puppy".toBytes)
    trie.put("dogglesworth".toBytes, "cat".toBytes)

    block:
      let
        rootHash = trie.rootHash
        proof = trie.getBranch("doe".toBytes)
        res = verifyMptProof(proof, rootHash, "doe".toBytes, "reindeer".toBytes)

      check:
        to0xHex(rootHash.data) == "0x8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3"
        proof.len() == 3
        proof[0] == "e5831646f6a0db6ae1fda66890f6693f36560d36b4dca68b4d838f17016b151efe1d4c95c453".hexToSeqByte
        proof[1] == "f83b8080808080ca20887265696e6465657280a037efd11993cb04a54048c25320e9f29c50a432d28afdf01598b2978ce1ca3068808080808080808080".hexToSeqByte
        res.isValid()

    block:
      let
        proof = trie.getBranch("dogg".toBytes)
        res = verifyMptProof(proof, trie.rootHash, "dogg".toBytes, "puppy".toBytes)

      check:
        proof.len() == 4
        proof[0] == "e5831646f6a0db6ae1fda66890f6693f36560d36b4dca68b4d838f17016b151efe1d4c95c453".hexToSeqByte
        proof[1] == "f83b8080808080ca20887265696e6465657280a037efd11993cb04a54048c25320e9f29c50a432d28afdf01598b2978ce1ca3068808080808080808080".hexToSeqByte
        proof[2] == "e4808080808080ce89376c6573776f72746883636174808080808080808080857075707079".hexToSeqByte
        res.isMissing()

    block:
      let
        proof = newSeq[seq[byte]]()
        res = verifyMptProof(proof, trie.rootHash, "doe".toBytes, "reindeer".toBytes)

      check res.kind == InvalidProof

    block:
      let
        proof = @["aaa".toBytes, "ccc".toBytes]
        res = verifyMptProof(proof, trie.rootHash, "doe".toBytes, "reindeer".toBytes)

      check res.kind == InvalidProof


