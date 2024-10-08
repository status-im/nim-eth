import stint, ./common/[addresses, base, hashes]

type UInt2048 = StUint[2048]

iterator chunksForBloom(h: Hash32): array[2, uint8] =
  yield [h.data[0], h.data[1]]
  yield [h.data[2], h.data[3]]
  yield [h.data[4], h.data[5]]

proc chunkToBloomBits(chunk: array[2, uint8]): UInt2048 =
  let h = chunk[0].int
  let l = chunk[1].int
  one(UInt2048) shl ((l + (h shl 8)) and 2047)

iterator bloomBits(h: Hash32): UInt2048 =
  for chunk in chunksForBloom(h):
    yield chunkToBloomBits(chunk)

type BloomFilter* = object
  value*: UInt2048

proc incl*(f: var BloomFilter, h: Hash32) =
  for bits in bloomBits(h):
    f.value = f.value or bits

proc init*(_: type BloomFilter, h: Hash32): BloomFilter =
  result.incl(h)

proc incl*[T: byte|char](f: var BloomFilter, v: openArray[T]) =
  f.incl(keccak256(v))

proc incl*(f: var BloomFilter, v: Address | Bytes32) =
  f.incl(v.data)

proc contains*(f: BloomFilter, h: Hash32): bool =
  for bits in bloomBits(h):
    if (f.value and bits).isZero:
      return false
  return true

template contains*(f: BloomFilter, v: openArray): bool =
  f.contains(keccak256(v))

proc contains*(f: BloomFilter, v: Address | Bytes32): bool =
  f.contains(v.data)
