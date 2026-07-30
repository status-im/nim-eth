# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## A minimalistic, lock-free, fixed-size cache.
##
## * A key maps to exactly one bucket, `hash and
##   indexMask`. There is no probing and no chaining.
## * collisions evict unconditionally - the newer entry replaces the older.
## * each bucket is its own 128-byte cache line, holding an atomic tag plus the
##   key/value pair, so buckets never falsely share.
## * the tag packs the hash bits *above* the index bits, leaving the low bits
##   for the lock and a version counter. `capacity` must therefore be a power of
##   two, and at least `MinEntries` so the counter is wide enough to be sound -
##   see the note there. `init` asserts both.
## * synchronisation is a per-bucket lock that never spins: a single
##   compare-exchange, and on failure the operation is abandoned rather than
##   retried. A lookup that loses the race simply fall back to computing the value.

{.push raises: [].}

import std/[atomics, typetraits]

const
  LockedBit = 1'u
  CacheLineSize = 128

  MinEntryBits = 10
  MinEntries* = 1 shl MinEntryBits
    ## Lower bound on capacity, set by the width of the version counter rather
    ## than by memory.
    ##
    ## The counter lives in the tag word's low bits, below the index bits, so it
    ## is `log2(capacity) - 1` bits wide. A reader accepts its two samples when
    ## they are equal, which is only sound if the counter cannot wrap between
    ## them: with a 1-bit counter it wraps every two writes, and a reader that is
    ## preempted across two writes to the same bucket accepts a torn entry as a
    ## hit. That is not theoretical - a 4-entry cache under 4 readers and 2
    ## writers reproduces it in well under a second.
    ##
    ## At this minimum the counter is 9 bits, so aliasing needs 512 writes to one
    ## bucket inside a single read window of a few nanoseconds. Each write is a
    ## compare-exchange plus a key/value copy, so that is several microseconds of
    ## work - a margin of some three orders of magnitude.

type
  Bucket[K, V] = object
    tag {.align: CacheLineSize.}: Atomic[uint]
    key: K
    val: V

  FixedCache*[K, V] = object
    entries: ptr UncheckedArray[Bucket[K, V]]
    numEntries: int

  Slot* = object
    idx*: int # The index of the entry in the cache used to locate the bucket.
    tag*: uint # The hash with exactly that cache's index bits masked off

func capacity*[K, V](c: FixedCache[K, V]): int =
  c.numEntries

func indexMask[K, V](c: FixedCache[K, V]): uint =
  uint(c.numEntries) - 1

func tagMask[K, V](c: FixedCache[K, V]): uint =
  not c.indexMask()

proc init*[K, V](c: var FixedCache[K, V], entries: int) =
  ## `entries` must be a power of two and at least `MinEntries`, so that the tag
  ## bits never overlap the lock's bits and the version counter is wide enough.
  static:
    doAssert supportsCopyMem(K), "K must be a non-GC type"
    doAssert supportsCopyMem(V), "V must be a non-GC type"
  doAssert (entries and (entries - 1)) == 0, "entries must be a power of two"
  doAssert entries >= MinEntries, "entries must be at least MinEntries"

  c.numEntries = entries
  c.entries = cast[ptr UncheckedArray[Bucket[K, V]]](
    allocShared0(sizeof(Bucket[K, V]) * entries))

proc dispose*[K, V](c: var FixedCache[K, V]) =
  if c.entries != nil:
    deallocShared(c.entries)
    c.entries = nil
    c.numEntries = 0

func locate*[K, V](c: FixedCache[K, V], key: auto): Slot {.inline.} =
  ## Hash `key` once; the token is valid for `get` and `put` on the same key.
  mixin hash
  let h = cast[uint](hash(key))
  Slot(idx: int(h and c.indexMask()), tag: h and c.tagMask())

proc getBySlot*[K, V](
    c: var FixedCache[K, V], slot: Slot, key: auto, val: var V): bool =
  ## Returns true and fills `val` if `key` is resident.
  ##
  ## Seqlock read: no atomic read-modify-write, so a lookup never writes to the
  ## bucket line and never blocks a writer. The tag is sampled before and after
  ## reading the entry; if a writer touched the bucket in between, or holds it
  ## now, the read is discarded and reported as a miss. Callers recompute on a
  ## miss, so losing the race is always safe.
  ##
  ## The low bits of the tag word (below the index bits, which are always zero
  ## in a tag) carry a version counter incremented on every insert. Without it
  ## a writer could replace an entry and restore the same tag between the two
  ## samples, and the reader would return a torn key/value pair as a hit.
  mixin `==`

  let
    b = addr c.entries[slot.idx]
    versionMask = c.indexMask()
    t1 = b.tag.load(moAcquire)

  if (t1 and LockedBit) != 0 or (t1 and not versionMask) != slot.tag:
    return false

  if not (b.key == key):
    return false
  val = b.val

  # Keep the entry reads above the second sample. An acquire *load* would not be
  # enough: it constrains only the accesses that follow it, leaving the compiler
  # free to sink the value copy below the very check meant to validate it - and
  # the copy is a plain 32-byte struct read, not an opaque call. An acquire fence
  # is the barrier that applies to preceding loads. On x86 it emits no
  # instruction at all, so this costs nothing at runtime; it constrains the
  # optimiser, which is where the reordering would come from.
  fence(moAcquire)
  b.tag.load(moRelaxed) == t1

proc tryLock[K, V](b: ptr Bucket[K, V], prev: var uint): bool =
  ## Take the bucket for writing, whatever it currently holds. Never spins: a
  ## bucket already held by another writer is left alone.
  let state = b.tag.load(moRelaxed)
  if (state and LockedBit) != 0:
    return false
  prev = state
  var cmp = state
  b.tag.compareExchange(cmp, state or LockedBit, moAcquire, moRelaxed)

proc putBySlot*[K, V](c: var FixedCache[K, V], slot: Slot, key: K, val: V) =
  ## Insert, evicting whatever occupies the bucket. A bucket currently held by
  ## another writer is left alone and the insert is dropped.

  let
    b = addr c.entries[slot.idx]
    versionMask = c.indexMask()
  var prev: uint
  if not b.tryLock(prev):
    return
  b.key = key
  b.val = val
  # Publish with the version bumped, so any reader that sampled the old tag
  # before this write sees a different value on its second sample.
  let version = ((prev and versionMask) + (LockedBit shl 1)) and
    versionMask and not LockedBit
  b.tag.store((slot.tag or version), moRelease)

proc get*[K, V](c: var FixedCache[K, V], key: K, val: var V): bool =
  c.getBySlot(c.locate(key), key, val)

proc put*[K, V](c: var FixedCache[K, V], key: K, val: V) =
  c.putBySlot(c.locate(key), key, val)
