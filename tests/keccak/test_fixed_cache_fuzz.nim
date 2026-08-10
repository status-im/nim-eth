# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

## Fuzz tests for `eth/keccak/fixed_cache`.
##
## Single-threaded fuzzing is model-based: random operation streams run against
## both the cache and a `Table` holding the last value written per key. The
## cache's single-threaded contract is exact - a lookup either misses or returns
## precisely the value most recently put under that key - so any hit is checked
## byte-for-byte against the model. Values change on every insert (they carry a
## generation), which catches a stale entry surviving an overwrite, not just a
## wrong key.
##
## Multi-threaded fuzzing cannot use a model - which write "wins" is scheduling -
## so values are self-certifying instead: every 8-byte lane of a value encodes
## the key's fingerprint and the write's generation, redundantly. A lookup then
## checks that all lanes tell the same story. A torn read - bytes from two
## different writes - shows up as disagreeing lanes; a foreign value shows up as
## a fingerprint mismatch. Misses stay legitimate, as ever.
##
## `-d:fcFuzzRounds=N` and `-d:fcFuzzSeed=N` (decimal) scale and reseed the
## single-threaded streams; `-d:fcFuzzThreadOps=N` scales the threaded ones.

import
  std/[atomics, hashes, random, strformat, tables],
  unittest2,
  ../../eth/keccak/fixed_cache,
  ../../eth/keccak/keccak as ethkeccak

const ProdEntries = ethkeccak.keccakCacheCapacity
  ## The fuzzing runs at the keccak cache's production capacity (2^14 by
  ## default).

const
  fcFuzzSeed {.intdefine.} = 20260730
  fcFuzzRounds {.intdefine.} = 300_000
  fcFuzzThreadOps {.intdefine.} = 200_000

type
  Key = object
    len: uint8
    data: array[87, byte]

  Val = array[32, byte]

func hash(data: openArray[byte]): Hash =
  hashes.hash(data)

func hash(k: Key): Hash =
  hash(k.data.toOpenArray(0, int(k.len) - 1))

func `==`(k: Key, data: openArray[byte]): bool =
  int(k.len) == data.len and
    equalMem(unsafeAddr k.data[0], unsafeAddr data[0], data.len)

func `==`(a, b: Key): bool =
  a == b.data.toOpenArray(0, int(b.len) - 1)

func keyFor(n: int, len: int): Key =
  var k: Key
  k.len = uint8(len)
  var v = uint64(n)
  copyMem(addr k.data[0], addr v, 8)
  for i in 8 ..< len:
    k.data[i] = byte(i * 7 + (n and 0xff))
  k

func smallKey(n: int): Key =
  ## 256 distinct keys covering every cacheable length 1..87. Distinctness for
  ## any length comes from the first byte alone, so the compared prefix always
  ## identifies the key.
  keyFor(n and 0xff, 1 + (n mod 87))

func wideKey(n: int): Key =
  ## Unbounded distinct keys; lengths 8..87 so the full 8-byte discriminator is
  ## always inside the compared prefix.
  keyFor(n, 8 + (n mod 80))

proc randomVal(rng: var Rand): Val =
  var v: Val
  for i in 0 ..< v.len:
    v[i] = byte(rng.rand(0 .. 255))
  v

# ------------------------------------------------------------------------------
# Single-threaded, model-based
# ------------------------------------------------------------------------------

proc modelFuzz(capacity, rounds: int, seed: int64,
               keyGen: proc(n: int): Key {.noSideEffect.},
               keySpace: int, useViews: bool): (int, int) =
  ## Runs a random put/get stream against the cache and a last-write model.
  ## Returns (hits, wrongs); every hit was checked against the model.
  var
    cache: FixedCache[Key, Val]
    model = initTable[Key, Val]()
    rng = initRand(seed)
    hits = 0
    wrongs = 0
  cache.init(capacity)
  defer: cache.dispose()

  for round in 0 ..< rounds:
    let
      k = keyGen(rng.rand(0 ..< keySpace))
      op = rng.rand(0 .. 99)
    if op < 55:
      var got: Val
      let hit =
        if useViews:
          cache.getBySlot(
            cache.locate(k.data.toOpenArray(0, int(k.len) - 1)),
            k.data.toOpenArray(0, int(k.len) - 1), got)
        else:
          cache.get(k, got)
      if hit:
        inc hits
        # A hit must be the exact last write; the model cannot be missing the
        # key, because the cache can only hold what was put.
        if k notin model or got != model[k]:
          inc wrongs
    else:
      # Fresh random bytes every time: overwrites change the value, so a stale
      # entry surviving an overwrite is caught, not silently re-confirmed.
      let v = rng.randomVal()
      model[k] = v
      cache.put(k, v)
  (hits, wrongs)

suite "FixedCache fuzz, single-threaded":
  test &"small universe, every length ({fcFuzzRounds} ops)":
    # 256 keys in ProdEntries buckets: few collisions, high hit rate, every
    # cacheable length 1..87 exercised, constant overwriting.
    let (hits, wrongs) = modelFuzz(ProdEntries, fcFuzzRounds, fcFuzzSeed,
      smallKey, 256, useViews = false)
    checkpoint(&"hits={hits} wrongs={wrongs}")
    check wrongs == 0
    check hits > min(fcFuzzRounds div 10, ProdEntries * 10)

  test &"large universe with eviction churn ({fcFuzzRounds} ops)":
    # 16x more keys than buckets: eviction on nearly every insert, so hits must
    # survive their entry being replaced and re-inserted arbitrarily often.
    let (hits, wrongs) = modelFuzz(ProdEntries, fcFuzzRounds, fcFuzzSeed + 1,
      wideKey, 16 * ProdEntries, useViews = false)
    checkpoint(&"hits={hits} wrongs={wrongs}")
    check wrongs == 0
    check hits > 0

  test &"borrowed-view lookups against the model ({fcFuzzRounds} ops)":
    # Same stream shape, but every lookup goes through locate + getBySlot on a
    # raw byte view - the dual hash/`==` path the keccak cache actually uses.
    let (hits, wrongs) = modelFuzz(ProdEntries, fcFuzzRounds, fcFuzzSeed + 2,
      smallKey, 256, useViews = true)
    checkpoint(&"hits={hits} wrongs={wrongs}")
    check wrongs == 0
    check hits > min(fcFuzzRounds div 10, ProdEntries * 10)

  test "second instantiation: FixedCache[uint64, uint64]":
    # A different K/V shape checks the generic layout and tag arithmetic, with
    # keys crafted to collide: n and n + capacity share a bucket and differ
    # only in tag bits.
    var
      cache: FixedCache[uint64, uint64]
      model = initTable[uint64, uint64]()
      rng = initRand(fcFuzzSeed + 3)
      hits = 0
    cache.init(ProdEntries)
    defer: cache.dispose()
    for round in 0 ..< fcFuzzRounds:
      let k = uint64(rng.rand(0 ..< 8 * ProdEntries))
      if rng.rand(0 .. 1) == 0:
        var got: uint64
        if cache.get(k, got):
          inc hits
          check k in model and got == model[k]
      else:
        let v = uint64(round) * 0x9E3779B97F4A7C15'u64 xor k
        model[k] = v
        cache.put(k, v)
    checkpoint(&"hits={hits}")
    check hits > 0

  test "init/dispose cycles stay independent":
    # Nothing may leak from one lifetime into the next: a fresh cache must miss
    # every key the previous one held.
    var rng = initRand(fcFuzzSeed + 4)
    for cycle in 0 ..< 20:
      var cache: FixedCache[Key, Val]
      cache.init(ProdEntries)
      var stored: seq[Key]
      for i in 0 ..< 500:
        let k = wideKey(rng.rand(0 ..< 100_000))
        cache.put(k, rng.randomVal())
        stored.add k
      var got: Val
      var found = 0
      for k in stored:
        if cache.get(k, got):
          inc found
      check found > 0
      cache.dispose()
      # a fresh cache over the same keys is empty
      var fresh: FixedCache[Key, Val]
      fresh.init(ProdEntries)
      for k in stored:
        check not fresh.get(k, got)
      fresh.dispose()

# ------------------------------------------------------------------------------
# Multi-threaded, self-certifying values
# ------------------------------------------------------------------------------

when compileOption("threads"):

  const
    LaneMarker = 0xFEEDFACE'u64

  func fpOf(k: Key): uint64 =
    ## Fingerprint of the compared prefix - two keys equal under the cache's
    ## `==` always fingerprint alike, and distinct keys differ (whp).
    var h: uint64
    copyMem(addr h, unsafeAddr k.data[0], 8)
    h xor (uint64(k.len) shl 56)

  func stampedVal(k: Key, gen: uint32): Val =
    ## Lanes 0/2 carry the key fingerprint, lanes 1/3 the generation under a
    ## fixed marker. Any mixture of bytes from two different writes makes some
    ## pair of lanes disagree, whatever the tearing granularity.
    var lanes: array[4, uint64]
    lanes[0] = fpOf(k)
    lanes[1] = (LaneMarker shl 32) or uint64(gen)
    lanes[2] = lanes[0]
    lanes[3] = lanes[1]
    var v: Val
    copyMem(addr v[0], addr lanes[0], 32)
    v

  func stampOk(k: Key, v: Val): bool =
    ## A value is acceptable iff it is one whole write for this very key.
    var lanes: array[4, uint64]
    copyMem(addr lanes[0], unsafeAddr v[0], 32)
    lanes[0] == lanes[2] and lanes[1] == lanes[3] and
      lanes[0] == fpOf(k) and (lanes[1] shr 32) == LaneMarker

  type
    SharedF = object
      cache: ptr FixedCache[Key, Val]
      keySpace: int
      wrong: Atomic[int]
      hits: Atomic[int]
      misses: Atomic[int]

  proc mixedLoop(s: ptr SharedF) {.thread.} =
    ## Every thread both reads and writes, so the same bucket sees read/read,
    ## read/write and write/write races rather than fixed roles.
    var
      rng = initRand(getThreadId() * 2654435761)
      localHits = 0
      localMisses = 0
      localWrong = 0
    for i in 0 ..< fcFuzzThreadOps:
      let k = keyFor(rng.rand(0 ..< s.keySpace), 32)
      if rng.rand(0 .. 99) < 60:
        var got: Val
        if s.cache[].get(k, got):
          inc localHits
          if not stampOk(k, got):
            inc localWrong
        else:
          inc localMisses
      else:
        s.cache[].put(k, stampedVal(k, uint32(i)))
    discard s.hits.fetchAdd(localHits, moRelaxed)
    discard s.misses.fetchAdd(localMisses, moRelaxed)
    discard s.wrong.fetchAdd(localWrong, moRelaxed)

  proc runMixed(capacity, keySpace, threads: int): (int, int, int) =
    var cache: FixedCache[Key, Val]
    cache.init(capacity)
    defer: cache.dispose()
    var s = SharedF(cache: addr cache, keySpace: keySpace)
    var ts = newSeq[Thread[ptr SharedF]](threads)
    for i in 0 ..< threads:
      createThread(ts[i], mixedLoop, addr s)
    joinThreads(ts)
    (s.hits.load(moRelaxed), s.misses.load(moRelaxed), s.wrong.load(moRelaxed))

  # An adversarial key type: the hash's low bits are all zero, so every key
  # lands in bucket 0 - constant eviction and lock contention on a single
  # line - while the high (tag) bits still distinguish the keys. With reads
  # holding the bucket lock for the copy, no write interleaving is observable
  # at all, so the assertion is an absolute zero.
  #
  # The ids start at 1: id 0 would hash to 0 with an all-zero representation,
  # which is indistinguishable from an *empty* bucket (see the module note in
  # fixed_cache) and produces a legitimate-looking hit with a zeroed value in
  # the startup window before the first insert. That artifact - not a
  # concurrency bug - was the source of an intermittent wrong=1 in an earlier
  # version of this test, reproducible single-threaded.
  const NarrowIndexBits = block:
    ## log2(ProdEntries); shifting the id above the index bits parks every key
    ## in bucket 0 while keeping the tags distinct.
    var n = ProdEntries
    var bits = 0
    while n > 1:
      n = n shr 1
      inc bits
    bits

  static: doAssert 1 shl NarrowIndexBits == ProdEntries

  type
    NarrowKey = object
      id: uint64

  func hash(k: NarrowKey): Hash =
    Hash(k.id shl NarrowIndexBits)

  func `==`(a, b: NarrowKey): bool =
    a.id == b.id

  func narrowVal(k: NarrowKey): Val =
    ## All four lanes identical and derived from the id: torn mixtures of two
    ## writes disagree between lanes, foreign values disagree with the key.
    var lanes: array[4, uint64]
    for i in 0 ..< 4:
      lanes[i] = k.id * 0x9E3779B97F4A7C15'u64 + 1
    var v: Val
    copyMem(addr v[0], addr lanes[0], 32)
    v

  type
    SharedN = object
      cache: ptr FixedCache[NarrowKey, Val]
      wrong: Atomic[int]
      hits: Atomic[int]

  proc narrowLoop(s: ptr SharedN) {.thread.} =
    var
      rng = initRand(getThreadId() * 48271)
      localHits = 0
      localWrong = 0
    for _ in 0 ..< fcFuzzThreadOps:
      let k = NarrowKey(id: uint64(rng.rand(1 .. 16)))
      if rng.rand(0 .. 99) < 50:
        var got: Val
        if s.cache[].get(k, got):
          inc localHits
          if got != narrowVal(k):
            inc localWrong
      else:
        s.cache[].put(k, narrowVal(k))
    discard s.hits.fetchAdd(localHits, moRelaxed)
    discard s.wrong.fetchAdd(localWrong, moRelaxed)

  suite "FixedCache fuzz, multi-threaded":
    test &"mixed ops, hot keys ({fcFuzzThreadOps} ops x 6 threads)":
      # 8 keys: every operation contends on the same few buckets.
      let (hits, misses, wrong) = runMixed(ProdEntries, 8, 6)
      checkpoint(&"hits={hits} misses={misses} wrong={wrong}")
      check wrong == 0
      check hits > 0
      check misses > 0

    test &"mixed ops, eviction churn ({fcFuzzThreadOps} ops x 6 threads)":
      # 4x oversubscription: the same races, but with the resident key of a
      # bucket changing constantly underneath the readers.
      let (hits, misses, wrong) = runMixed(ProdEntries, 4 * ProdEntries, 6)
      checkpoint(&"hits={hits} misses={misses} wrong={wrong}")
      check wrong == 0
      check hits > 0

    test &"adversarial hash: 16 keys forced into one bucket ({fcFuzzThreadOps} ops x 6 threads)":
      var cache: FixedCache[NarrowKey, Val]
      cache.init(ProdEntries)
      defer: cache.dispose()
      var s = SharedN(cache: addr cache)
      var ts: array[6, Thread[ptr SharedN]]
      for i in 0 ..< ts.len:
        createThread(ts[i], narrowLoop, addr s)
      joinThreads(ts)
      let
        hits = s.hits.load(moRelaxed)
        wrong = s.wrong.load(moRelaxed)
      checkpoint(&"hits={hits} wrong={wrong}")
      check wrong == 0
      check hits > 0
else:
  suite "FixedCache fuzz, multi-threaded":
    test "skipped - compiled without --threads:on":
      skip()
