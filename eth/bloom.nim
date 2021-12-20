import stint, nimcrypto/[keccak, hash]

type UInt2048 = StUint[2048]

iterator chunksForBloom(h: MDigest[256]): array[2, uint8] =
  yield [h.data[0], h.data[1]]
  yield [h.data[2], h.data[3]]
  yield [h.data[4], h.data[5]]

proc chunkToBloomBits(chunk: array[2, uint8]): UInt2048 =
  let h = chunk[0].int
  let l = chunk[1].int
  one(UInt2048) shl ((l + (h shl 8)) and 2047)

iterator bloomBits(h: MDigest[256]): UInt2048 =
  for chunk in chunksForBloom(h):
    yield chunkToBloomBits(chunk)

type BloomFilter* = object
  value*: UInt2048

proc incl*(f: var BloomFilter, h: MDigest[256]) =
  for bits in bloomBits(h):
    f.value = f.value or bits

proc init*(_: type BloomFilter, h: MDigest[256]): BloomFilter =
  result.incl(h)

# TODO: The following 2 procs should be one genric, but it doesn't compile. Nim bug?
proc incl*(f: var BloomFilter, v: string) = f.incl(keccak256.digest(v))
proc incl*(f: var BloomFilter, v: openArray[byte]) = f.incl(keccak256.digest(v))

proc contains*(f: BloomFilter, h: MDigest[256]): bool =
  for bits in bloomBits(h):
    if (f.value and bits).isZero: return false
  return true

template contains*[T](f: BloomFilter, v: openArray[T]): bool =
  f.contains(keccak256.digest(v))
