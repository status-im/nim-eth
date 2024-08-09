import
  stew/byteutils,
  ./trie_defs

export trie_defs

template checkValidHashZ*(x: untyped) =
  when x.type isnot KeccakHash:
    doAssert(x.len == 32 or x.len == 0)

template isZeroHash*(x: openArray[byte]): bool =
  x.len == 0

proc hashFromHex*(bits: static[int], input: string): MDigest[bits] =
  MDigest(data: hexToByteArray[bits div 8](input))

template hashFromHex*(s: static[string]): untyped = hashFromHex(s.len * 4, s)
