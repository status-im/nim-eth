# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

## Tests for `eth/keccak`.
##
## Two kinds of evidence:
##
## * the Keccak Team's published known-answer vectors, which check the
##   implementation against the specification;
## * differential fuzzing against two unrelated implementations - the BoringSSL
##   C kept in `keccak_boringssl`, and nimcrypto - which covers inputs no fixed
##   vector set reaches.
##
## Both run over the one-shot, the incremental context and
## `eth/common/hashes.keccak256`, so a bug confined to one entry point cannot
## hide behind the others.
##
## `-d:keccakFuzzRounds=N` raises the fuzz count; `-d:keccakFuzzSeed=N` (decimal,
## not hex - `{.intdefine.}` rejects `0x...`) changes the sample. The seed is
## fixed by default so failures reproduce.

import
  std/[os, random, strformat, strutils],
  unittest2,
  stew/byteutils,
  nimcrypto/keccak as ncrypto,
  ../../eth/common/hashes,
  ../../eth/keccak/keccak_xkcp,
  ../../eth/keccak/keccak_boringssl as bssl

# `{.all.}` for MAX_CACHED_INPUT_LEN, which the fuzz length distribution below
# straddles deliberately. It is private to the module, and `{.all.}` neither
# accepts an `as` alias nor combines with the list above, hence the separate
# statement and the `keccak.` qualification at the one ambiguous use.
import ../../eth/keccak/keccak {.all.}

const
  keccakFuzzSeed {.intdefine.} = 0x5EED
  keccakFuzzRounds {.intdefine.} = 50_000

func hashXkcp(data: openArray[byte]): array[32, byte] =
  keccak256Xkcp(data, result)

func hashEthHashes(data: openArray[byte]): array[32, byte] =
  keccak256(data).data

func hashBoringSsl(data: openArray[byte]): array[32, byte] =
  bssl.Keccak256.digest(data).data

func hashNimcrypto(data: openArray[byte]): array[32, byte] =
  var c: ncrypto.keccak256
  c.init()
  c.update(data)
  c.finish().data

func hashStream(data: openArray[byte], chunks: openArray[int]): array[32, byte] =
  ## Feed `data` through the incremental context in the given chunk sizes.
  var
    ctx: keccak.Keccak256
    pos = 0
  ctx.init()
  for c in chunks:
    let n = min(c, data.len - pos)
    if n > 0:
      ctx.update(data.toOpenArray(pos, pos + n - 1))
      pos += n
  if pos < data.len:
    ctx.update(data.toOpenArray(pos, data.high))
  ctx.finish().data

func randomChunks(rng: var Rand, total: int): seq[int] =
  ## A random partition of `total`, with zero-length updates mixed in - those
  ## must be no-ops.
  var remaining = total
  while remaining > 0:
    let n = rng.rand(0 .. remaining)
    result.add(n)
    remaining -= n
    if rng.rand(0 .. 3) == 0:
      result.add(0)

const katVectors = staticRead(
  currentSourcePath.parentDir / "ShortMsgKAT_256.txt")

iterator katEntries(): (seq[byte], string) {.raises: [ValueError].} =
  ## The vector file has already been filtered to byte-aligned entries; `Len`
  ## is retained in bits for fidelity with the original.
  var msgHex = ""
  for rawLine in katVectors.splitLines():
    let line = rawLine.strip()
    if line.startsWith("Msg = "):
      msgHex = line[6 .. ^1]
    elif line.startsWith("MD = "):
      yield (hexToSeqByte(msgHex), line[5 .. ^1].toLowerAscii())

suite "Keccak256":
  test "Keccak Team known-answer vectors":
    var count = 0
    for (msg, expected) in katEntries():
      # every entry point must reproduce the published digest
      check hashXkcp(msg).toHex == expected
      check hashEthHashes(msg).toHex == expected
      check hashStream(msg, [1, 7, 64, 136]).toHex == expected
      check hashBoringSsl(msg).toHex == expected
      inc count
    # guard against a parse bug silently reducing this to nothing
    check count == 256

  test "digest of the empty input":
    check hashXkcp([]).toHex ==
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    check emptyKeccak256 == keccak256(default(array[0, byte]))

  test "every length 0..600 agrees across implementations":
    var data = newSeq[byte](600)
    for i in 0 ..< data.len:
      data[i] = byte((i * 31 + 7) and 0xff)
    for n in 0 .. 600:
      let got = hashXkcp(data.toOpenArray(0, n - 1))
      check got == hashBoringSsl(data.toOpenArray(0, n - 1))
      check got == hashNimcrypto(data.toOpenArray(0, n - 1))
      check got == hashEthHashes(data.toOpenArray(0, n - 1))

  test "incremental updates match a single update":
    var data = newSeq[byte](500)
    for i in 0 ..< data.len:
      data[i] = byte((i * 13 + 1) and 0xff)
    let want = hashXkcp(data)
    # boundaries around the 136-byte rate, plus degenerate splits
    for chunks in [@[1], @[135], @[136], @[137], @[0, 136, 0, 136, 0],
                   @[135, 1, 135, 1], @[499, 1], @[1, 499], @[250, 250]]:
      check hashStream(data, chunks) == want

  test &"fuzz: {keccakFuzzRounds} random inputs agree across implementations":
    var
      rng = initRand(keccakFuzzSeed)
      mismatches = 0
      belowBound = 0 # <= MAX_CACHED_INPUT_LEN: the cache can serve these
      aboveBound = 0 # >  MAX_CACHED_INPUT_LEN: always hashed directly
    for round in 0 ..< keccakFuzzRounds:
      # Deliberately split across the cache cut-off, weighting the cut-off
      # itself and the 136-byte rate boundaries.
      let n =
        case rng.rand(0 .. 9)
        of 0 .. 2: rng.rand(0 .. MAX_CACHED_INPUT_LEN)
        of 3: rng.rand(0 .. 20)
        of 4: rng.rand(MAX_CACHED_INPUT_LEN - 3 .. MAX_CACHED_INPUT_LEN + 3)
        of 5: rng.rand(MAX_CACHED_INPUT_LEN + 1 .. 200)
        of 6: rng.rand(133 .. 139)
        of 7: rng.rand(269 .. 275)
        of 8: rng.rand(MAX_CACHED_INPUT_LEN + 1 .. 1200)
        else: rng.rand(0 .. 400)

      if n <= MAX_CACHED_INPUT_LEN: inc belowBound else: inc aboveBound

      var data = newSeq[byte](n)
      for i in 0 ..< n:
        data[i] = byte(rng.rand(0 .. 255))

      let
        oneShot = hashXkcp(data)
        stream = hashStream(data, randomChunks(rng, n))
        eth = hashEthHashes(data)
        boring = hashBoringSsl(data)
        nimc = hashNimcrypto(data)

      if oneShot != boring or oneShot != nimc or oneShot != eth or
          oneShot != stream:
        inc mismatches
        if mismatches <= 3:
          checkpoint(&"round {round}, len {n}: input {data.toHex}")
          checkpoint(&"  one-shot  {oneShot.toHex}")
          checkpoint(&"  stream    {stream.toHex}")
          checkpoint(&"  eth       {eth.toHex}")
          checkpoint(&"  boringssl {boring.toHex}")
          checkpoint(&"  nimcrypto {nimc.toHex}")
    check mismatches == 0
    # both sides of the cache boundary must actually have been exercised
    check belowBound > keccakFuzzRounds div 10
    check aboveBound > keccakFuzzRounds div 10

  test "repeated hashing of one input is stable":
    # Would catch a memoised digest going stale or being returned torn.
    var rng = initRand(keccakFuzzSeed + 1)
    for _ in 0 ..< 200:
      let n = rng.rand(0 .. 120)
      var data = newSeq[byte](n)
      for i in 0 ..< n:
        data[i] = byte(rng.rand(0 .. 255))
      let first = hashEthHashes(data)
      check first == hashBoringSsl(data)
      for _ in 0 ..< 10:
        check hashEthHashes(data) == first

  test "many distinct inputs stay distinct under cache eviction":
    var rng = initRand(keccakFuzzSeed + 2)
    for _ in 0 ..< 40_000:
      var data = newSeq[byte](32)
      for i in 0 ..< 32:
        data[i] = byte(rng.rand(0 .. 255))
      check hashEthHashes(data) == hashNimcrypto(data)
