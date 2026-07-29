# Nimbus
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

## The default keccak256 for nim-eth.
##
## API-compatible with `keccak_boringssl`, which it replaces; that module is
## kept for reference and is no longer imported. The permutation is the
## XKCP-style one in `keccak_xkcp`, measured ~1.11x faster than the BoringSSL C
## at every input size.
##
## This module must not import `eth/common/hashes`: that module imports this
## one, so the dependency would be circular. Digests are `MDigest[256]` from
## nimcrypto, exactly as `keccak_boringssl` exposed them.

{.push raises: [], gcsafe.}

import ./keccak_xkcp

from nimcrypto/hash import MDigest
export MDigest

const
  keccakCacheEnabled* {.booldefine.} = false
    ## Memoise keccak256 of short inputs. Off by default: a cache is a bet on
    ## hit rate, and below break-even it is slower than not caching, because a
    ## miss pays the lookup, the insert *and* the hash. Enable with
    ## `-d:keccakCacheEnabled=true` once the workload is known to repeat
    ## preimages.

type
  Keccak256* = KeccakXkcpCtx

export keccak_xkcp.init, keccak_xkcp.update, keccak_xkcp.finish

template clear*(h: var Keccak256) =
  init(h)

{.push inline, noinit, gcsafe.}

func init*(_: type Keccak256): Keccak256 =
  result.init()

func finish*(h: var Keccak256): MDigest[256] =
  h.finish(result.data)

func digest*(_: type Keccak256, data: openArray[byte]): MDigest[256] =
  keccak256XkcpNim(data, result.data)

func keccak256_20*(data: openArray[byte]): MDigest[256] =
  keccak256XkcpNim(data, result.data)

func keccak256_32*(data: openArray[byte]): MDigest[256] =
  keccak256XkcpNim(data, result.data)

{.pop.}

func keccak256Uncached*(data: openArray[byte]): MDigest[256] {.noinit.} =
  ## One-shot, always hashing.
  keccak256XkcpNim(data, result.data)

# ------------------------------------------------------------------------------
# Optional memoisation
# ------------------------------------------------------------------------------

when keccakCacheEnabled:
  import
    std/[hashes, os, strutils],
    ./fixed_cache

  const
    srcPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]
    rapidhashHeader = srcPath & "/rapidhash.h"

    MaxCachedInputLen* = 87
      ## Longer inputs are hashed directly. Bounded so key and digest fit one
      ## 128-byte bucket; matches alloy-primitives' `MAX_INPUT_LEN`.
    DefaultKeccakCacheCapacity* = 1 shl 14

  const emptyKeccak256Digest = MDigest[256](data: [
    0xc5'u8, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70])

  func rapidhashMicro(key: pointer, len: csize_t): uint64 {.
    importc: "rapidhashMicro", header: rapidhashHeader.}

  type
    KeccakCacheKey = object
      len: uint8
      data: array[MaxCachedInputLen, byte]

  # A lookup is done against the caller's bytes directly - hashing and comparing
  # a borrowed view rather than building a KeccakCacheKey first. Only an insert
  # needs the owned key. `hash(KeccakCacheKey)` is defined in terms of the
  # openArray one so the two can never disagree: if they did, every lookup would
  # probe a different bucket than the matching insert wrote, and the cache would
  # silently never hit while still returning correct digests.
  func hash(data: openArray[byte]): Hash =
    cast[Hash](rapidhashMicro(unsafeAddr data[0], csize_t(data.len)))

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

  keccakCache.init(DefaultKeccakCacheCapacity)

proc keccak256Cached*(data: openArray[byte]): MDigest[256] {.inline.} =
  ## One-shot keccak256, served from the cache when it is enabled and the input
  ## is short enough. Results are identical to `keccak256Uncached` either way.
  when not keccakCacheEnabled:
    keccak256Uncached(data)
  else:
    if data.len == 0:
      return emptyKeccak256Digest
    if data.len > MaxCachedInputLen:
      return keccak256Uncached(data)

    {.cast(gcsafe).}:
      let slot = keccakCache.locate(data)
      if keccakCache.getBySlot(slot, data, result):
        return result

      result = keccak256Uncached(data)

      var key: KeccakCacheKey
      key.len = uint8(data.len)
      copyMem(addr key.data[0], unsafeAddr data[0], data.len)
      keccakCache.putBySlot(slot, key, result)

{.pop.}
