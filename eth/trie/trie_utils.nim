import
  stew/byteutils,
  nimcrypto/[hash, keccak],
  trie_defs

template checkValidHashZ*(x: untyped) =
  when x.type isnot KeccakHash:
    doAssert(x.len == 32 or x.len == 0)

template isZeroHash*(x: openArray[byte]): bool =
  x.len == 0

proc hashFromHex*(bits: static[int], input: string): MDigest[bits] =
  MDigest(data: hexToByteArray[bits div 8](input))

template hashFromHex*(s: static[string]): untyped = hashFromHex(s.len * 4, s)

proc keccakHash*(input: openArray[byte]): KeccakHash =
  keccak256.digest(input)

proc keccakHash*(dest: var openArray[byte], a, b: openArray[byte]) =
  var ctx: keccak256
  ctx.init()
  if a.len != 0:
    ctx.update(a[0].unsafeAddr, uint(a.len))
  if b.len != 0:
    ctx.update(b[0].unsafeAddr, uint(b.len))
  ctx.finish dest
  ctx.clear()

proc keccakHash*(a, b: openArray[byte]): KeccakHash =
  var s: array[32, byte]
  keccakHash(s, a, b)
  KeccakHash(data: s)
