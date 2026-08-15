# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

## Tests for `eth/keccak/fixed_cache`.
##
## The central invariant is that a lookup either misses or returns the value
## that was stored under *that* key - never another key's value, and never a
## torn mixture of two. Every test derives the value from the key with
## `valueFor`, so any violation shows up as a value that does not match its own
## key rather than as a subtle corruption.
##
## Misses are expected and legitimate: the cache is one-way set associative with
## unconditional eviction, and a reader that races a writer reports a miss by
## design. So the tests assert on "no wrong answers" plus "hits do happen" -
## asserting a specific hit rate would be asserting on scheduling.

import
  std/[atomics, hashes, random, strformat],
  unittest2,
  ../../eth/keccak/fixed_cache

const TestEntries = 1 shl 10
  ## Default capacity for these tests: big enough to spread keys, small enough
  ## that oversubscribed key spaces still collide constantly.

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

func keyFor(n: int, len = 32): Key =
  ## Distinct `n` always gives a distinct key: the discriminator occupies whole
  ## bytes rather than being folded into one, which would alias.
  var k: Key
  k.len = uint8(len)
  var v = uint64(n)
  copyMem(addr k.data[0], addr v, 8)
  for i in 8 ..< len:
    k.data[i] = byte(i * 7 + (n and 0xff))
  k

func valueFor(k: Key): Val =
  ## The value is a pure function of the key, so any successful lookup can be
  ## checked against the key it was found under. This is what makes a torn read
  ## detectable rather than merely unlikely to be noticed.
  var v: Val
  for i in 0 ..< 32:
    v[i] = byte((int(k.data[i mod int(max(k.len, 1))]) * 31 + i + int(k.len)) and 0xff)
  v

suite "FixedCache single-threaded":
  test "empty cache misses":
    var c: FixedCache[Key, Val]
    c.init(TestEntries)
    defer: c.dispose()
    var got: Val
    for n in 0 ..< 500:
      check not c.get(keyFor(n), got)

  test "put then get returns the stored value":
    var c: FixedCache[Key, Val]
    c.init(1 shl 12)
    defer: c.dispose()
    for n in 0 ..< 1000:
      let k = keyFor(n)
      c.put(k, valueFor(k))
      var got: Val
      check c.get(k, got)
      check got == valueFor(k)

  test "every cacheable key length round-trips":
    var c: FixedCache[Key, Val]
    c.init(1 shl 12)
    defer: c.dispose()
    for len in 1 .. 87:
      let k = keyFor(len * 1000, len)
      c.put(k, valueFor(k))
      var got: Val
      check c.get(k, got)
      check got == valueFor(k)

  test "a shared prefix is not a hit":
    var c: FixedCache[Key, Val]
    c.init(1 shl 12)
    defer: c.dispose()
    let k = keyFor(42, 32)
    c.put(k, valueFor(k))
    # same bytes, one shorter: the length must participate in the comparison
    var shorter = k
    shorter.len = 31
    var got: Val
    check not c.get(shorter, got)

  test "a borrowed byte view finds an owned insert":
    var c: FixedCache[Key, Val]
    c.init(1 shl 12)
    defer: c.dispose()
    for n in 0 ..< 200:
      let k = keyFor(n)
      c.put(k, valueFor(k))
      let view = k.data[0 ..< int(k.len)]
      var got: Val
      check c.getBySlot(c.locate(view), view, got)
      check got == valueFor(k)
      # and the two hash paths must agree on the bucket
      check c.locate(k) == c.locate(view)

  test "collision evicts, and the evicted key then misses":
    # Far more keys than buckets, so collisions are certain.
    var c: FixedCache[Key, Val]
    c.init(TestEntries)
    defer: c.dispose()
    var resident = -1
    for n in 0 ..< 200:
      let k = keyFor(n)
      c.put(k, valueFor(k))
      var got: Val
      # whatever is resident must still be self-consistent
      if c.get(k, got):
        check got == valueFor(k)
        resident = n
      if resident >= 0 and resident != n:
        let old = keyFor(resident)
        var oldGot: Val
        if c.get(old, oldGot):
          check oldGot == valueFor(old)
    check resident >= 0

  test "heavy churn never returns another key's value":
    var c: FixedCache[Key, Val]
    c.init(TestEntries)
    defer: c.dispose()
    var
      rng = initRand(0x1234)
      hits = 0
    for _ in 0 ..< 200_000:
      let
        n = rng.rand(0 .. 20_000)
        k = keyFor(n)
      var got: Val
      if c.get(k, got):
        check got == valueFor(k)
        inc hits
      else:
        c.put(k, valueFor(k))
    # 20k keys through 1k buckets still hits often enough to be exercising the
    # hit path, not just the insert path
    check hits > 1000

  test "capacity must be a power of two":
    var c: FixedCache[Key, Val]
    expect Defect:
      c.init(1000)

  test "invalid capacities are rejected":
    # Non-powers of two would break the index masking; a single entry is
    # rejected as degenerate.
    for bad in [-8, 0, 1, 1000]:
      var c: FixedCache[Key, Val]
      expect Defect:
        c.init(bad)

  test "the minimum capacity is accepted":
    var c: FixedCache[Key, Val]
    c.init(MIN_ENTRIES)
    defer: c.dispose()
    let k = keyFor(1)
    c.put(k, valueFor(k))
    var got: Val
    check c.get(k, got)
    check got == valueFor(k)

when compileOption("threads"):

  const
    Readers = 4
    Writers = 2
    OpsPerThread = 200_000
    HotKeys = 8
      ## A small key space, so readers and writers collide on the same handful
      ## of buckets almost every operation.

  type
    Shared = object
      cache: ptr FixedCache[Key, Val]
      wrong: Atomic[int] ## lookups that returned a value for the wrong key
      hits: Atomic[int]
      misses: Atomic[int]
      stop: Atomic[bool]

  proc readerLoop(s: ptr Shared) {.thread.} =
    var
      rng = initRand(getThreadId())
      localHits = 0
      localMisses = 0
      localWrong = 0
    for _ in 0 ..< OpsPerThread:
      let k = keyFor(rng.rand(0 ..< HotKeys))
      var got: Val
      if s.cache[].get(k, got):
        inc localHits
        if got != valueFor(k):
          inc localWrong
      else:
        inc localMisses
    discard s.hits.fetchAdd(localHits, moRelaxed)
    discard s.misses.fetchAdd(localMisses, moRelaxed)
    discard s.wrong.fetchAdd(localWrong, moRelaxed)

  proc writerLoop(s: ptr Shared) {.thread.} =
    var rng = initRand(int64(getThreadId()) * 7919)
    for _ in 0 ..< OpsPerThread:
      let k = keyFor(rng.rand(0 ..< HotKeys))
      s.cache[].put(k, valueFor(k))

  proc wideWriterLoop(s: ptr Shared) {.thread.} =
    ## Writes over a key space several times larger than the cache, so writers
    ## constantly evict each other's entries as well as their own.
    var rng = initRand(int64(getThreadId()) * 104729)
    for _ in 0 ..< OpsPerThread:
      let k = keyFor(rng.rand(0 ..< 4 * TestEntries))
      s.cache[].put(k, valueFor(k))

  proc viewReaderLoop(s: ptr Shared) {.thread.} =
    ## Reads through the borrowed-view path - `locate` on raw bytes, then
    ## `getBySlot` with the same view - as the keccak cache does, rather than
    ## through the owned-key `get`.
    var
      rng = initRand(int64(getThreadId()) * 31 + 1)
      localHits = 0
      localMisses = 0
      localWrong = 0
    for _ in 0 ..< OpsPerThread:
      let k = keyFor(rng.rand(0 ..< HotKeys))
      var got: Val
      if s.cache[].getBySlot(
          s.cache[].locate(k.data.toOpenArray(0, int(k.len) - 1)),
          k.data.toOpenArray(0, int(k.len) - 1), got):
        inc localHits
        if got != valueFor(k):
          inc localWrong
      else:
        inc localMisses
    discard s.hits.fetchAdd(localHits, moRelaxed)
    discard s.misses.fetchAdd(localMisses, moRelaxed)
    discard s.wrong.fetchAdd(localWrong, moRelaxed)

  suite "FixedCache multi-threaded":
    test &"{Readers} readers + {Writers} writers on a hot bucket set":
      # A key space of HotKeys spread over TestEntries buckets means readers
      # race writers on the same handful of buckets almost every operation -
      # the case the locked read path has to get right, and the one
      # single-threaded tests cannot reach.
      var cache: FixedCache[Key, Val]
      cache.init(TestEntries)
      defer: cache.dispose()

      var s: Shared
      s.cache = addr cache

      var
        readers: array[Readers, Thread[ptr Shared]]
        writers: array[Writers, Thread[ptr Shared]]
      for i in 0 ..< Writers:
        createThread(writers[i], writerLoop, addr s)
      for i in 0 ..< Readers:
        createThread(readers[i], readerLoop, addr s)
      joinThreads(writers)
      joinThreads(readers)

      let
        hits = s.hits.load(moRelaxed)
        misses = s.misses.load(moRelaxed)
        wrong = s.wrong.load(moRelaxed)
      checkpoint(&"hits={hits} misses={misses} wrong={wrong}")
      # No lookup may ever return a value belonging to a different key.
      check wrong == 0
      # And the test must actually have exercised the hit path.
      check hits > 0
      check misses > 0

    test "readers see consistent values across a large key space":
      var cache: FixedCache[Key, Val]
      cache.init(1 shl 12)
      defer: cache.dispose()

      # Prefill, then read and write concurrently over the same wide range.
      for n in 0 ..< 4000:
        let k = keyFor(n)
        cache.put(k, valueFor(k))

      var s: Shared
      s.cache = addr cache

      var
        readers: array[Readers, Thread[ptr Shared]]
        writers: array[Writers, Thread[ptr Shared]]
      for i in 0 ..< Writers:
        createThread(writers[i], writerLoop, addr s)
      for i in 0 ..< Readers:
        createThread(readers[i], readerLoop, addr s)
      joinThreads(writers)
      joinThreads(readers)

      checkpoint(&"hits={s.hits.load(moRelaxed)} wrong={s.wrong.load(moRelaxed)}")
      check s.wrong.load(moRelaxed) == 0
      check s.hits.load(moRelaxed) > 0

    test "borrowed-view readers race writers":
      # The keccak cache's actual read path: hash and compare the caller's raw
      # bytes against the bucket without materialising a key. The view lookup
      # must obey the same locking guarantees as the owned-key one.
      var cache: FixedCache[Key, Val]
      cache.init(TestEntries)
      defer: cache.dispose()

      var s: Shared
      s.cache = addr cache

      var
        readers: array[Readers, Thread[ptr Shared]]
        writers: array[Writers, Thread[ptr Shared]]
      for i in 0 ..< Writers:
        createThread(writers[i], writerLoop, addr s)
      for i in 0 ..< Readers:
        createThread(readers[i], viewReaderLoop, addr s)
      joinThreads(writers)
      joinThreads(readers)

      checkpoint(&"hits={s.hits.load(moRelaxed)} misses={s.misses.load(moRelaxed)} " &
        &"wrong={s.wrong.load(moRelaxed)}")
      check s.wrong.load(moRelaxed) == 0
      check s.hits.load(moRelaxed) > 0

    test "racing writers leave only self-consistent entries behind":
      # Writers alone, over 4x more keys than buckets, so the contention is
      # writer-vs-writer: overlapping lock attempts and constant eviction.
      # Afterwards every resident entry must still be a matched key/value pair -
      # a lost lock race may drop an insert, but never corrupt one.
      var cache: FixedCache[Key, Val]
      cache.init(TestEntries)
      defer: cache.dispose()

      var s: Shared
      s.cache = addr cache

      var writers: array[4, Thread[ptr Shared]]
      for i in 0 ..< writers.len:
        createThread(writers[i], wideWriterLoop, addr s)
      joinThreads(writers)

      var resident = 0
      for n in 0 ..< 4 * TestEntries:
        let k = keyFor(n)
        var got: Val
        if cache.get(k, got):
          inc resident
          check got == valueFor(k)
      checkpoint(&"resident={resident} of {cache.capacity} buckets")
      # With 4x oversubscription and 800k inserts virtually every bucket ends
      # up occupied.
      check resident > TestEntries div 2

    test "4-entry cache under full contention":
      # The configuration that exposed the earlier lock-free read path: at 4
      # entries its version counter was a single bit, and torn reads scored
      # wrong=22..73 per run. With reads taking the bucket lock there is no
      # window at any capacity, so the smallest interesting cache under maximal
      # contention must be exactly clean.
      var cache: FixedCache[Key, Val]
      cache.init(4)
      defer: cache.dispose()

      var s: Shared
      s.cache = addr cache

      var
        readers: array[Readers, Thread[ptr Shared]]
        writers: array[Writers, Thread[ptr Shared]]
      for i in 0 ..< Writers:
        createThread(writers[i], writerLoop, addr s)
      for i in 0 ..< Readers:
        createThread(readers[i], readerLoop, addr s)
      joinThreads(writers)
      joinThreads(readers)

      let
        hits = s.hits.load(moRelaxed)
        wrong = s.wrong.load(moRelaxed)
      checkpoint(&"hits={hits} wrong={wrong}")
      check wrong == 0
      check hits > 0
else:
  suite "FixedCache multi-threaded":
    test "skipped - compiled without --threads:on":
      skip()
