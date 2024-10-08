import ../../eth/trie/[db, hexary, ordered_trie], ../../eth/rlp, unittest2

{.used.}

suite "OrderedTrie":
  for n in [0, 1, 2, 3, 126, 127, 128, 129, 130, 1000]:
    test "Ordered vs normal trie " & $n:
      let values = block:
        var tmp: seq[uint64]
        for i in 0 .. n:
          tmp.add i.uint64
        tmp

      let b1 = orderedTrieRoot(values)

      let b2 = block:
        var db2 = initHexaryTrie(newMemoryDB())
        for v in values:
          db2.put(rlp.encode(v), rlp.encode(v))

        db2.rootHash()
      check:
        b1 == b2
