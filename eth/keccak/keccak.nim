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
    ## Enable memoize `keccak256` of short inputs.

  keccakCacheCapacity* {.intdefine.} = 1 shl 14 # 2 MiB
    ## Number of cache buckets. Must be a power of two.

  MAX_CACHED_INPUT_LEN = 87

  EMPTY_KECCAK256_DIGEST = MDigest[256](data: [
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
    nimcrypto/sysrand,
    ./fixed_cache,
    ./rapidhash

  static:
    doAssert (keccakCacheCapacity and (keccakCacheCapacity - 1)) == 0,
      "keccakCacheCapacity must be a power of two"
    doAssert keccakCacheCapacity >= MIN_ENTRIES,
      "keccakCacheCapacity must be at least fixed_cache.MIN_ENTRIES"

  type
    KeccakCacheKey = object
      len: uint8
      data: array[MAX_CACHED_INPUT_LEN, byte]

  let keccakCacheSeed: uint64 = block:
    var s: array[1, uint64]
    doAssert randomBytes(s) == s.len
    s[0]

  # A lookup is done against the caller's bytes directly - hashing and comparing
  # a borrowed view rather than building a KeccakCacheKey first.
  func hash(data: openArray[byte]): Hash =
    {.cast(noSideEffect).}:
      cast[Hash](rapidhashMicro(data, keccakCacheSeed))

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

  const
    keccakCacheStatsEnabled* {.booldefine.} = true
      ## Track, for every `keccak256` lookup, the preimage's length and how
      ## often it hit or missed the cache - i.e. what is being hashed and what
      ## share of it the cache can serve. Costs one probe of a side table and a
      ## relaxed atomic increment per lookup.

    keccakCacheStatsCapacity* {.intdefine.} = 1 shl 20 # 32 MiB
      ## Distinct preimages tracked. Must be a power of two. Lookups whose
      ## preimage cannot claim a slot are counted as untracked, not silently
      ## dropped.

  when keccakCacheStatsEnabled:
    import std/[algorithm, atomics, strformat, tables]

    static:
      doAssert (keccakCacheStatsCapacity and (keccakCacheStatsCapacity - 1)) == 0,
        "keccakCacheStatsCapacity must be a power of two"

    const STATS_PROBE_LIMIT = 16

    type
      StatEntry = object
        ## One tracked preimage, identified by its seeded rapidhash. `hash` is
        ## zero while the slot is empty; a preimage whose hash is really zero
        ## is stored as 1, which merely merges its stats with that value's.
        hash: Atomic[uint64]
        len: uint32
        hits: Atomic[uint64]
        misses: Atomic[uint64]

      KeccakKeyStat* = object
        ## Snapshot of one tracked preimage.
        len*: int
        hits*: int64
        misses*: int64

    var
      statEntries: ptr UncheckedArray[StatEntry] =
        cast[ptr UncheckedArray[StatEntry]](
          createShared(StatEntry, keccakCacheStatsCapacity))
      statUntracked: Atomic[uint64]

    proc recordStat(hash0: uint64, len: int, hit: bool) =
      ## Lock-free: linear probing, slots claimed with a compare-exchange and
      ## never released. `len` is a plain store made only by the claimant, so
      ## a snapshot racing the claim can transiently see it as zero.
      let h = if hash0 == 0: 1'u64 else: hash0
      var idx = int(h and uint64(keccakCacheStatsCapacity - 1))
      for _ in 0 ..< STATS_PROBE_LIMIT:
        let e = addr statEntries[idx]
        var cur = e.hash.load(moRelaxed)
        if cur == 0:
          if e.hash.compareExchange(cur, h, moRelaxed, moRelaxed):
            e.len = uint32(len)
            cur = h
          # on failure `cur` holds the winning claimant's hash, handled below
        if cur == h:
          if hit:
            discard e.hits.fetchAdd(1, moRelaxed)
          else:
            discard e.misses.fetchAdd(1, moRelaxed)
          return
        idx = (idx + 1) and (keccakCacheStatsCapacity - 1)
      discard statUntracked.fetchAdd(1, moRelaxed)

    proc keccakCacheKeyStats*(): seq[KeccakKeyStat] =
      ## Point-in-time copy of every tracked preimage. Safe to call while
      ## other threads keep hashing; counters may lag by a few increments.
      for i in 0 ..< keccakCacheStatsCapacity:
        let e = addr statEntries[i]
        if e.hash.load(moRelaxed) != 0:
          result.add KeccakKeyStat(
            len: int(e.len),
            hits: int64(e.hits.load(moRelaxed)),
            misses: int64(e.misses.load(moRelaxed)))

    proc keccakCacheUntrackedLookups*(): int64 =
      int64(statUntracked.load(moRelaxed))

    proc resetKeccakCacheStats*() =
      ## Not atomic against concurrent hashing - call while no other thread
      ## is hashing.
      for i in 0 ..< keccakCacheStatsCapacity:
        let e = addr statEntries[i]
        e.hash.store(0, moRelaxed)
        e.len = 0
        e.hits.store(0, moRelaxed)
        e.misses.store(0, moRelaxed)
      statUntracked.store(0, moRelaxed)

    proc keccakCacheStatsReport*(maxLengths = 30): string =
      ## Human-readable summary aggregated by preimage length, sorted by
      ## lookup volume. Lengths above `MAX_CACHED_INPUT_LEN`, marked `*`,
      ## bypass the cache and can only miss.
      type LenAgg = object
        keys, repeated, hits, misses: int64

      func pctStr(part, whole: int64): string =
        if whole == 0: "    n/a"
        else: &"{100.0 * float(part) / float(whole):>6.1f}%"

      var
        byLen: Table[int, LenAgg]
        totKeys, keysHit, totHits, totMisses: int64
      for s in keccakCacheKeyStats():
        var agg = byLen.getOrDefault(s.len)
        inc agg.keys
        if s.hits + s.misses > 1:
          inc agg.repeated
        agg.hits += s.hits
        agg.misses += s.misses
        byLen[s.len] = agg
        inc totKeys
        if s.hits > 0:
          inc keysHit
        totHits += s.hits
        totMisses += s.misses

      var lens: seq[(int, LenAgg)]
      for len, agg in byLen:
        lens.add (len, agg)
      lens.sort proc(a, b: (int, LenAgg)): int =
        cmp(b[1].hits + b[1].misses, a[1].hits + a[1].misses)

      let lookups = totHits + totMisses
      result = "keccak256 cache stats\n"
      result.add &"  tracked preimages : {totKeys} " &
        &"(capacity {keccakCacheStatsCapacity}, " &
        &"untracked lookups {keccakCacheUntrackedLookups()})\n"
      result.add &"  lookups           : {lookups}  hits {totHits} " &
        &"({pctStr(totHits, lookups)})  misses {totMisses}\n"
      result.add &"  preimages hit >=1x: {keysHit} " &
        &"({pctStr(keysHit, totKeys)} of tracked)\n"
      result.add "  by length (* = above MAX_CACHED_INPUT_LEN, never cached):\n"
      result.add &"""  {"len":>7} {"preimages":>10} {"repeated":>9} """ &
        &"""{"lookups":>10} {"hits":>10} {"misses":>10} {"hit%":>7}""" & "\n"

      var shown = 0
      var restKeys, restRepeated, restHits, restMisses, restLens: int64
      for (len, agg) in lens:
        if shown < maxLengths:
          let mark = if len > MAX_CACHED_INPUT_LEN: "*" else: " "
          result.add &"  {len:>6}{mark} {agg.keys:>10} {agg.repeated:>9} " &
            &"{agg.hits + agg.misses:>10} {agg.hits:>10} {agg.misses:>10} " &
            &"{pctStr(agg.hits, agg.hits + agg.misses)}" & "\n"
          inc shown
        else:
          inc restLens
          restKeys += agg.keys
          restRepeated += agg.repeated
          restHits += agg.hits
          restMisses += agg.misses
      if restLens > 0:
        result.add &"  {restLens:>5} more lengths: {restKeys} preimages, " &
          &"{restHits + restMisses} lookups, {restHits} hits\n"

func digestImpl(data: openArray[byte]): MDigest[256] {.noinit, inline.} =
  # Non-generic on purpose. `digest` takes a typedesc, which makes it generic,
  # and a generic body resolves late-bound symbols in the caller's scope
  # where this module's private `==` and `hash` overloads are not visible.
  if data.len == 0:
    return EMPTY_KECCAK256_DIGEST

  var digest {.noinit.}: MDigest[256]

  when not keccakCacheEnabled:
    keccak256Xkcp(data, digest.data)
    return digest
  else:
    if data.len > MAX_CACHED_INPUT_LEN:
      keccak256Xkcp(data, digest.data)
      when keccakCacheStatsEnabled:
        {.cast(noSideEffect), cast(gcsafe).}:
          recordStat(cast[uint64](hash(data)), data.len, hit = false)
      return digest

    {.cast(noSideEffect), cast(gcsafe).}:
      let slot = keccakCache.locate(data)
      when keccakCacheStatsEnabled:
        # `locate` split the full hash into index and tag bits; their union
        # reconstructs it, so the stats key costs no second hash.
        let statHash = uint64(slot.tag or uint(slot.idx))
      if keccakCache.getBySlot(slot, data, digest):
        when keccakCacheStatsEnabled:
          recordStat(statHash, data.len, hit = true)
        return digest

      keccak256Xkcp(data, digest.data)
      when keccakCacheStatsEnabled:
        recordStat(statHash, data.len, hit = false)

      var key: KeccakCacheKey
      key.len = uint8(data.len)
      copyMem(addr key.data[0], unsafeAddr data[0], data.len)
      keccakCache.putBySlot(slot, key, digest)
      return digest

func digest*(_: type Keccak256, data: openArray[byte]): MDigest[256] {.inline.} =
  digestImpl(data)
