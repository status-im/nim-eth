# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## A minimalistic, fixed-size cache.
##
## * A key maps to exactly one bucket, `hash and
##   indexMask`. There is no probing and no chaining.
## * collisions evict unconditionally - the newer entry replaces the older.
## * each bucket is its own 128-byte cache line, holding an atomic control word
##   plus the key/value pair, so buckets never falsely share.
## * the control word packs the hash bits *above* the index bits (the tag) and
##   uses bit 0 as the lock. `capacity` must therefore be a power of two of at
##   least `MIN_ENTRIES`, which `init` asserts.
## * synchronisation is a per-bucket lock that never spins: one compare-exchange
##   to take, one store to release, held by writers and readers alike for the
##   few instructions of the key/value copy. On failure the operation is
##   abandoned rather than retried: an insert is dropped, and a lookup simply
##   reports a miss so the caller falls back to computing the value.
## * an empty bucket is all zeroes, which makes it indistinguishable from an
##   entry whose tag is 0 and whose key compares equal to zeroed memory. The
##   key type must therefore have no valid key that both hashes to 0 and
##   matches an all-zero representation - a length prefix, as the keccak cache
##   key has, is enough.

{.push raises: [].}

import std/[atomics, typetraits]

const
  LOCKED_BIT = 1'u
  CACHE_LINE_SIZE = 128
  MIN_ENTRIES* = 2

type
  Bucket[K, V] = object
    control {.align: CACHE_LINE_SIZE.}: Atomic[uint]
      ## The bucket's control word: a tag plus the lock bit, not a bare tag -
      ## hence the name. For a cache of `2^N` entries:
      ##
      ## ```
      ##   bit:  63 ................ N | N-1 ........ 1 | 0
      ##        +----------------------+----------------+------+
      ##        |  tag = hash[63..N]   |  always zero   | lock |
      ##        +----------------------+----------------+------+
      ##        |<------ tagMask ----->|<----- indexMask ----->|
      ## ```
      ##
      ## Every key stored in this bucket has the same low `N` hash bits - they
      ## are what selected the bucket - so storing them here would say nothing.
      ## Bit 0 is reused as a lock taken by writers *and* readers for the few
      ## instructions of the key/value copy.
    key: K
    val: V

  FixedCache*[K, V] = object
    mem: ptr Bucket[K, V]
    entries: ptr UncheckedArray[Bucket[K, V]]
    numEntries: int

  Slot* = object
    idx*: int ## The index of the entry in the cache used to locate the bucket.
    tag*: uint # The hash with exactly that cache's index bits masked off

template capacity*[K, V](c: FixedCache[K, V]): int =
  c.numEntries

template indexMask(c: FixedCache): uint =
  uint(c.numEntries) - 1

template tagMask(c: FixedCache): uint =
  not c.indexMask()

template bucketIndex(c: FixedCache, h: uint): int =
  int(h and c.indexMask())

template bucketTag(c: FixedCache, h: uint): uint =
  h and c.tagMask()

template bucketAt(c: FixedCache, slot: Slot): auto =
  addr c.entries[slot.idx]

template unlockedControl(tag: uint): uint =
  tag

template lockedControl(tag: uint): uint =
  tag or LOCKED_BIT

template isLocked(control: uint): bool =
  (control and LOCKED_BIT) != 0

template roundUpToCacheLine(p: pointer): uint =
  ## `p` advanced to the next `CACHE_LINE_SIZE` boundary, or left alone if it is
  ## already on one.
  (cast[uint](p) + CACHE_LINE_SIZE - 1) and not uint(CACHE_LINE_SIZE - 1)

proc init*[K, V](c: var FixedCache[K, V], entries: int) =
  static:
    doAssert supportsCopyMem(K), "K must be a non-GC type"
    doAssert supportsCopyMem(V), "V must be a non-GC type"
    doAssert sizeof(Bucket[K, V]) mod CACHE_LINE_SIZE == 0
  doAssert c.mem == nil, "cache is already initialised - dispose it first"
  doAssert entries >= MIN_ENTRIES, "entries must be at least MIN_ENTRIES"
  doAssert (entries and (entries - 1)) == 0, "entries must be a power of two"

  # Nim's shared allocator nly guarantees `MemAlign` (16 bytes), so we
  # over-allocate by one bucket and round the base up to the next cache line.
  # `mem` keeps the pointer the allocator actually returned, which is the one
  # `dispose` must free.
  c.numEntries = entries
  c.mem = createShared(Bucket[K, V], entries + 1)
  c.entries = cast[ptr UncheckedArray[Bucket[K, V]]](roundUpToCacheLine(c.mem))

proc dispose*[K, V](c: var FixedCache[K, V]) =
  if c.mem != nil:
    freeShared(c.mem)
    c.mem = nil
    c.entries = nil
    c.numEntries = 0

proc `=copy`[K, V](
    dest: var FixedCache[K, V], src: FixedCache[K, V]
) {.error: "Copying FixedCache is forbidden".} =
  discard

func locate*[K, V](c: var FixedCache[K, V], key: auto): Slot {.inline.} =
  mixin hash
  let h = cast[uint](hash(key))
  Slot(idx: c.bucketIndex(h), tag: c.bucketTag(h))

proc getBySlot*[K, V](
    c: var FixedCache[K, V], slot: Slot, key: auto, val: var V): bool =
  mixin `==`
  let b = c.bucketAt(slot)

  var expected = unlockedControl(slot.tag)
  if b.control.load(moRelaxed) != expected:
    return false

  if not b.control.compareExchange(
      expected, lockedControl(slot.tag), moAcquire, moRelaxed):
    return false

  let hit = b.key == key
  if hit:
    val = b.val

  b.control.store(unlockedControl(slot.tag), moRelease)

  hit

proc putBySlot*[K, V](c: var FixedCache[K, V], slot: Slot, key: K, val: V) =
  let b = c.bucketAt(slot)

  var expected = b.control.load(moRelaxed)
  if expected.isLocked:
    return
  if not b.control.compareExchange(
      expected, lockedControl(expected), moAcquire, moRelaxed):
    return

  b.key = key
  b.val = val

  b.control.store(unlockedControl(slot.tag), moRelease)

proc get*[K, V](c: var FixedCache[K, V], key: K, val: var V): bool =
  c.getBySlot(c.locate(key), key, val)

proc put*[K, V](c: var FixedCache[K, V], key: K, val: V) =
  c.putBySlot(c.locate(key), key, val)
