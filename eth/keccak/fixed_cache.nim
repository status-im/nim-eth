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
## * each bucket is its own 128-byte cache line pair, holding a sequence lock
##   plus the key/value pair, so buckets never falsely share.
## * synchronisation is a per-bucket `SeqLock`: lookups never write to the
##   bucket, so concurrent readers of a hot entry do not contend, and writers
##   take the lock with one compare-exchange and never spin. On losing any
##   race the operation is abandoned rather than retried: an insert is
##   dropped, and a lookup reports a miss so the caller falls back to
##   computing the value.
## * a lookup reads the entry while a writer may be overwriting it and only
##   afterwards learns, from the seqlock, whether what it read was consistent.
##   The key/value types must therefore be plain memory (`supportsCopyMem`),
##   and key comparison must stay in bounds even on garbage - which it does
##   naturally when sizes come from the caller's key and the stored key is a
##   fixed-size array, as with the keccak cache key.
## * an empty bucket is all zeroes, which makes it indistinguishable from an
##   entry whose key compares equal to zeroed memory. The key type must
##   therefore have no valid key that matches an all-zero representation - a
##   length prefix, as the keccak cache key has, is enough.

{.push raises: [].}

import std/[atomics, typetraits]

const
  CACHE_LINE_SIZE = 128
  MIN_ENTRIES* = 2

# ------------------------------------------------------------------------------
# SeqLock
# ------------------------------------------------------------------------------

type SeqLock* = object
  sequence: Atomic[uint64]

const WRITE_IN_PROGRESS = 1'u64

func isWriting*(seqnum: uint64): bool {.inline.} =
  (seqnum and WRITE_IN_PROGRESS) != 0

proc beginRead*(sl: var SeqLock): uint64 {.inline.} =
  sl.sequence.load(moAcquire)

proc endRead*(sl: var SeqLock, started: uint64): bool {.inline.} =
  fence(moAcquire)
  sl.sequence.load(moRelaxed) == started

proc tryBeginWrite*(sl: var SeqLock): bool {.inline.} =
  var s = sl.sequence.load(moRelaxed)
  if s.isWriting():
    return false
  if not sl.sequence.compareExchange(
      s, s + WRITE_IN_PROGRESS, moAcquire, moRelaxed):
    return false

  fence(moRelease)
  true

proc endWrite*(sl: var SeqLock) {.inline.} =
  let s = sl.sequence.load(moRelaxed)
  sl.sequence.store(s + 1, moRelease)

# ------------------------------------------------------------------------------
# FixedCache
# ------------------------------------------------------------------------------

type
  Bucket[K, V] = object
    lock {.align: CACHE_LINE_SIZE.}: SeqLock
    key: K
    val: V

  FixedCache*[K, V] = object
    mem: ptr Bucket[K, V]
    entries: ptr UncheckedArray[Bucket[K, V]]
    numEntries: int

  Slot* = int

template capacity*[K, V](c: FixedCache[K, V]): int =
  c.numEntries

template indexMask(c: FixedCache): uint64 =
  uint64(c.numEntries) - 1

template bucketIndex(c: FixedCache, h: uint64): int =
  int(h and c.indexMask())

template bucketAt(c: FixedCache, slot: Slot): auto =
  addr c.entries[slot]

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

  # Nim's shared allocator only guarantees `MemAlign` (16 bytes), so we
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
  c.bucketIndex(uint64(cast[uint](hash(key))))

proc getBySlot*[K, V](
    c: var FixedCache[K, V], slot: Slot, key: auto, val: var V): bool =
  mixin `==`

  let
    b = c.bucketAt(slot)
    started = b.lock.beginRead()

  if started.isWriting():
    return false

  if not (b.key == key):
    return false
  val = b.val

  b.lock.endRead(started)

proc putBySlot*[K, V](c: var FixedCache[K, V], slot: Slot, key: K, val: V) =

  let b = c.bucketAt(slot)
  if not b.lock.tryBeginWrite():
    return

  b.key = key
  b.val = val

  b.lock.endWrite()

proc get*[K, V](c: var FixedCache[K, V], key: K, val: var V): bool =
  c.getBySlot(c.locate(key), key, val)

proc put*[K, V](c: var FixedCache[K, V], key: K, val: V) =
  c.putBySlot(c.locate(key), key, val)
