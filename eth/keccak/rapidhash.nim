# Nimbus
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

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
##
## The header compiles as both C and C++ and every function is `static inline`,
## so there is nothing to link - the definitions land in whichever translation
## unit includes it.

{.push raises: [], gcsafe.}

import std/[os, strutils]

const
  rapidhashHeader = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] &
    "/rapidhash.h"

func rapidhashRaw*(key: pointer, len: csize_t): uint64 {.
  importc: "rapidhash", header: rapidhashHeader.}
func rapidhashRaw*(key: pointer, len: csize_t, seed: uint64): uint64 {.
  importc: "rapidhash_withSeed", header: rapidhashHeader.}

func rapidhashMicroRaw*(key: pointer, len: csize_t): uint64 {.
  importc: "rapidhashMicro", header: rapidhashHeader.}
func rapidhashMicroRaw*(key: pointer, len: csize_t, seed: uint64): uint64 {.
  importc: "rapidhashMicro_withSeed", header: rapidhashHeader.}

func rapidhashNanoRaw*(key: pointer, len: csize_t): uint64 {.
  importc: "rapidhashNano", header: rapidhashHeader.}
func rapidhashNanoRaw*(key: pointer, len: csize_t, seed: uint64): uint64 {.
  importc: "rapidhashNano_withSeed", header: rapidhashHeader.}

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

