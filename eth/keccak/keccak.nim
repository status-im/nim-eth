# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import ./keccak_xkcp
export keccak_xkcp.init, keccak_xkcp.update, keccak_xkcp.clear

from nimcrypto/hash import MDigest
export MDigest

const
  keccakCacheEnabled* {.booldefine.} = false
    ## Memoize `keccak256` of short inputs.

  keccakCacheCapacity* {.intdefine.} = 1 shl 14 # 2 MiB
    ## Number of cache buckets when the cache is enabled. Must be a power of two and
    ## at least `fixed_cache.MinEntries`, both checked below.

  MaxCachedInputLen* = 87
    ## Longest input the cache will hold. Each cache bucket is 128 bytes containing
    ## the 32-byte digest, the one-byte length and the eight-byte tag word are fixed
    ## overhead, leaving 87 bytes for the key.

  emptyKeccak256Digest = MDigest[256](data: [
    0xc5'u8, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70])

type Keccak256* = KeccakXkcpCtx

template finish*(h: var Keccak256): MDigest[256] =
  block:
    var digest {.noinit.}: MDigest[256]
    keccak_xkcp.finish(h, digest.data)
    digest

when keccakCacheEnabled:
  import
    std/hashes,
    ./fixed_cache,
    ./rapidhash

  static:
    doAssert (keccakCacheCapacity and (keccakCacheCapacity - 1)) == 0,
      "keccakCacheCapacity must be a power of two"
    doAssert keccakCacheCapacity >= MinEntries,
      "keccakCacheCapacity must be at least fixed_cache.MinEntries"

  type
    KeccakCacheKey = object
      len: uint8
      data: array[MaxCachedInputLen, byte]

  # A lookup is done against the caller's bytes directly - hashing and comparing
  # a borrowed view rather than building a KeccakCacheKey first.
  func hash(data: openArray[byte]): Hash =
    cast[Hash](rapidhashMicro(data))

  func hash(k: KeccakCacheKey): Hash =
    hash(k.data.toOpenArray(0, int(k.len) - 1))

  func `==`(k: KeccakCacheKey, data: openArray[byte]): bool =
    int(k.len) == data.len and
      equalMem(unsafeAddr k.data[0], unsafeAddr data[0], data.len)

  func `==`(a, b: KeccakCacheKey): bool =
    a == b.data.toOpenArray(0, int(b.len) - 1)

  static:
    doAssert sizeof(KeccakCacheKey) + sizeof(MDigest[256]) + sizeof(uint) <= 128

  var keccakCache: FixedCache[KeccakCacheKey, MDigest[256]]

  keccakCache.init(keccakCacheCapacity)

func digestImpl(data: openArray[byte]): MDigest[256] {.noinit, inline.} =
  # Non-generic on purpose. `digest` takes a typedesc, which makes it generic,
  # and a generic body resolves late-bound symbols in the caller's scope
  # where this module's private `==` and `hash` overloads are not visible.
  if data.len == 0:
    return emptyKeccak256Digest

  var digest {.noinit.}: MDigest[256]

  when not keccakCacheEnabled:
    keccak256Xkcp(data, digest.data)
    return digest
  else:
    if data.len > MaxCachedInputLen:
      keccak256Xkcp(data, digest.data)
      return digest

    {.cast(noSideEffect), cast(gcsafe).}:
      let slot = keccakCache.locate(data)
      if keccakCache.getBySlot(slot, data, digest):
        return digest

      keccak256Xkcp(data, digest.data)

      var key: KeccakCacheKey
      key.len = uint8(data.len)
      copyMem(addr key.data[0], unsafeAddr data[0], data.len)
      keccakCache.putBySlot(slot, key, digest)
      return digest

func digest*(_: type Keccak256, data: openArray[byte]): MDigest[256] {.inline.} =
  digestImpl(data)
