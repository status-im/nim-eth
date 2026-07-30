# nim-eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

## Keccak-256 benchmark. Deliberately *not* part of `all_tests` - it measures
## rather than asserts, and timings are too machine-dependent to gate CI on.
##
## Build and run:
##
##   nim c -r -d:release tests/keccak/bench_keccak.nim
##
## Pin to a core for stable numbers, e.g. `taskset -c 2`, and prefer the median
## of a few runs: the spread between runs is larger than the difference between
## the fastest two implementations.
##
## Columns, in order:
##
##   nimcrypto  the pure-Nim implementation in nimcrypto
##   boringssl  the BoringSSL C kept in `keccak_boringssl`
##   xkcp       the current implementation in `keccak_xkcp`
##   selected   whatever `eth/common/hashes.keccak256` resolves to, including
##              the memoisation layer when it is compiled in
##
## Each iteration mutates the input, so the memoisation cache never hits and all
## four columns measure the same work. The cache's best case is reported
## separately at the end - it is a property of the workload, not the hash.

{.push raises: [].}

import
  std/[monotimes, strformat, strutils, times],
  nimcrypto/keccak as ncrypto,
  ../../eth/common/hashes,
  ../../eth/keccak/keccak as ethkeccak,
  ../../eth/keccak/keccak_xkcp,
  ../../eth/keccak/keccak_boringssl as bssl

const Sizes = [32, 64, 136, 200, 532, 1024, 8192, 65536]
  ## 32/64: trie keys and mapping-slot preimages, the dominant EVM shapes.
  ## 136: exactly one sponge block. The rest: contract code and bulk data.

func hashNimcrypto(data: openArray[byte]): array[32, byte] =
  var c: ncrypto.keccak256
  c.init()
  c.update(data)
  c.finish().data

func hashBoringSsl(data: openArray[byte]): array[32, byte] =
  bssl.Keccak256.digest(data).data

func hashXkcp(data: openArray[byte]): array[32, byte] =
  keccak256Xkcp(data, result)

func hashSelected(data: openArray[byte]): array[32, byte] =
  keccak256(data).data

var sink: byte

template timeIt(iters: int, body: untyped): float =
  ## Nanoseconds per iteration.
  let t0 = getMonoTime()
  for _ in 0 ..< iters:
    body
  float((getMonoTime() - t0).inNanoseconds) / float(iters)

proc main() =
  # Sanity check before reporting any timings: a benchmark of a wrong hash is
  # worse than no benchmark.
  block:
    var data = newSeq[byte](200)
    for i in 0 ..< data.len:
      data[i] = byte((i * 31 + 7) and 0xff)
    for n in [0, 1, 32, 136, 137, 200]:
      let want = hashNimcrypto(data.toOpenArray(0, n - 1))
      doAssert hashBoringSsl(data.toOpenArray(0, n - 1)) == want
      doAssert hashXkcp(data.toOpenArray(0, n - 1)) == want
      doAssert hashSelected(data.toOpenArray(0, n - 1)) == want

  echo "Keccak-256, nanoseconds per hash (lower is better)"
  echo "memoisation cache: ",
    (when ethkeccak.keccakCacheEnabled: "ENABLED" else: "DISABLED"),
    "  (affects the 'selected' column only)"
  echo ""
  echo &"""{"input":>8} {"nimcrypto":>11} {"boringssl":>11} {"xkcp":>11} {"selected":>11}  """ &
    &"""{"xkcp vs":>9} {"xkcp vs":>9}"""
  echo &"""{"bytes":>8} {"ns":>11} {"ns":>11} {"ns":>11} {"ns":>11}  """ &
    &"""{"nimcrypto":>9} {"boringssl":>9}"""
  echo "-".repeat(88)

  for size in Sizes:
    var data = newSeq[byte](size)
    for i in 0 ..< size:
      data[i] = byte((i * 17 + 3) and 0xff)

    let iters =
      if size <= 200: 500_000
      elif size <= 1024: 200_000
      elif size <= 8192: 50_000
      else: 10_000

    # Mutating the input each iteration keeps the cache from hitting, so every
    # column measures a real hash. The mutation cost is identical across
    # columns and therefore cancels out of the ratios.
    var counter = 0'u64

    template run(fn: untyped): float =
      timeIt(iters):
        inc counter
        copyMem(addr data[0], addr counter, 8)
        sink = sink xor fn(data)[0]

    # warm up each path before timing it
    for _ in 0 .. 1:
      discard run(hashNimcrypto)
      discard run(hashBoringSsl)
      discard run(hashXkcp)
      discard run(hashSelected)

    let
      nimc = run(hashNimcrypto)
      boring = run(hashBoringSsl)
      xkcp = run(hashXkcp)
      selected = run(hashSelected)

    echo &"{size:>8} {nimc:>11.1f} {boring:>11.1f} {xkcp:>11.1f} " &
      &"{selected:>11.1f}  {nimc / xkcp:>8.2f}x {boring / xkcp:>8.2f}x"

  echo "-".repeat(88)
  echo ""
  echo "Repeated preimage - the memoisation best case, 100% hit rate."
  echo "Not a workload: real hit rates depend on how often preimages recur."
  echo ""
  echo &"""{"bytes":>8} {"xkcp":>11} {"selected":>11}  {"speedup":>9}"""
  echo "-".repeat(44)
  for size in [32, 64, 136]:
    var data = newSeq[byte](size)
    for i in 0 ..< size:
      data[i] = byte((i * 17 + 3) and 0xff)
    const iters = 500_000
    for _ in 0 .. 1:
      discard timeIt(iters): sink = sink xor hashXkcp(data)[0]
      discard timeIt(iters): sink = sink xor hashSelected(data)[0]
    let
      xkcp = timeIt(iters): sink = sink xor hashXkcp(data)[0]
      selected = timeIt(iters): sink = sink xor hashSelected(data)[0]
    echo &"{size:>8} {xkcp:>11.1f} {selected:>11.1f}  {xkcp / selected:>8.2f}x"
  echo "-".repeat(44)

  if sink == 0xff'u8:
    echo ""

when isMainModule:
  main()
