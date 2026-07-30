# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Bindings for rapidhash V3 (`rapidhash.h`, MIT, Nicolas De Carli,
## https://github.com/Nicoshev/rapidhash).
##
## Three variants, all seeded with 0 unless a seed is given:
##
## * `rapidhash` - the default, fastest on long inputs
## * `rapidhashMicro` - tuned for short-to-medium inputs; this is what
##   alloy-primitives uses to index its keccak cache
## * `rapidhashNano` - smallest code footprint
##
## These are *not* cryptographic hashes. They are for hash tables and caches
## where the input is not adversarially chosen against the seed.

{.push raises: [], gcsafe.}

import std/[os, strutils]

const
  RAPIDHASH_HEADER = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] &
    "/rapidhash.h"

func rapidhashRaw*(key: pointer, len: csize_t): uint64 {.
  importc: "rapidhash", header: RAPIDHASH_HEADER.}
func rapidhashRaw*(key: pointer, len: csize_t, seed: uint64): uint64 {.
  importc: "rapidhash_withSeed", header: RAPIDHASH_HEADER.}

func rapidhashMicroRaw*(key: pointer, len: csize_t): uint64 {.
  importc: "rapidhashMicro", header: RAPIDHASH_HEADER.}
func rapidhashMicroRaw*(key: pointer, len: csize_t, seed: uint64): uint64 {.
  importc: "rapidhashMicro_withSeed", header: RAPIDHASH_HEADER.}

func rapidhashNanoRaw*(key: pointer, len: csize_t): uint64 {.
  importc: "rapidhashNano", header: RAPIDHASH_HEADER.}
func rapidhashNanoRaw*(key: pointer, len: csize_t, seed: uint64): uint64 {.
  importc: "rapidhashNano_withSeed", header: RAPIDHASH_HEADER.}

# An empty openArray has no valid element to take the address of, so the
# wrappers below pass a nil pointer with length zero rather than indexing.
template dataPtr(data: openArray[byte]): pointer =
  if data.len == 0: nil else: unsafeAddr data[0]

func rapidhash*(data: openArray[byte]): uint64 {.inline.} =
  rapidhashRaw(dataPtr(data), csize_t(data.len))

func rapidhash*(data: openArray[byte], seed: uint64): uint64 {.inline.} =
  rapidhashRaw(dataPtr(data), csize_t(data.len), seed)

func rapidhashMicro*(data: openArray[byte]): uint64 {.inline.} =
  rapidhashMicroRaw(dataPtr(data), csize_t(data.len))

func rapidhashMicro*(data: openArray[byte], seed: uint64): uint64 {.inline.} =
  rapidhashMicroRaw(dataPtr(data), csize_t(data.len), seed)

func rapidhashNano*(data: openArray[byte]): uint64 {.inline.} =
  rapidhashNanoRaw(dataPtr(data), csize_t(data.len))

func rapidhashNano*(data: openArray[byte], seed: uint64): uint64 {.inline.} =
  rapidhashNanoRaw(dataPtr(data), csize_t(data.len), seed)

func rapidhash*(data: openArray[char]): uint64 {.inline.} =
  rapidhash(data.toOpenArrayByte(0, data.high))

func rapidhashMicro*(data: openArray[char]): uint64 {.inline.} =
  rapidhashMicro(data.toOpenArrayByte(0, data.high))

func rapidhashNano*(data: openArray[char]): uint64 {.inline.} =
  rapidhashNano(data.toOpenArrayByte(0, data.high))

