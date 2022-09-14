# proof verification
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

{.push raises: [Defect].}

import
  unittest2,
  stint,
  std/sequtils,
  nimcrypto/hash,
  ../../eth/trie/[hexary, db, trie_defs, hexary_proof_verification]

proc getKeyBytes(i: int): seq[byte] =
  let hash = keccakHash(u256(i).toBytesBE())
  return toSeq(hash.data)

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
      nonExistingKey = toSeq(keccakHash(toBytesBE(u256(numValues + 1))).data)
      proof = trie.getBranch(nonExistingKey)
      root = trie.rootHash()
      res = verifyMptProof(proof, root, nonExistingKey, nonExistingKey)

    check:
      res.isMissing()
