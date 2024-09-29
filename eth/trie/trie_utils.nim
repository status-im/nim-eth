import
  ./trie_defs

export trie_defs

template checkValidHashZ*(x: untyped) =
  doAssert(x.len == 32 or x.len == 0)

template isZeroHash*(x: openArray[byte]): bool =
  x.len == 0
