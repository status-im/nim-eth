# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/random,
  ../../eth/[rlp, common],
  unittest2

# `encode`, `getEncodedLength` and `computeRlpHash` all measure the encoding
# with `RlpLengthTracker` before writing it. `RlpDefaultWriter` instead writes
# the payload first and shifts it to make room for the prefix, so it never
# consults the tracker - which makes it an independent oracle for everything
# the tracker produces.

proc encodeDirect[T](v: T): seq[byte] =
  var writer = initRlpWriter()
  writer.append(v)
  move(writer.finish)

template checkAgainstDirect(v: untyped) =
  let expected = encodeDirect(v)
  check:
    rlp.encode(v) == expected
    getEncodedLength(v) == expected.len
    computeRlpHash(v) == keccak256(expected)

suite "RLP length tracker":
  test "integers":
    for i in [0'u64, 1, 2, 55, 56, 57, 127, 128, 129, 255, 256, 257, 65535,
              65536, 1'u64 shl 32, 1'u64 shl 56, high(uint64)]:
      checkAgainstDirect(i)
      checkAgainstDirect(@[i])
      checkAgainstDirect(@[i, i, i])

  test "blobs across the length prefix boundaries":
    for n in [0, 1, 2, 54, 55, 56, 57, 254, 255, 256, 257, 65534, 65535,
              65536, 65537]:
      var blob = newSeq[byte](n)
      for i in 0 ..< n:
        blob[i] = byte(i)
      checkAgainstDirect(blob)
      checkAgainstDirect(@[blob])

  test "single byte blobs are their own encoding below the blob marker":
    for b in [0'u8, 1, 126, 127, 128, 129, 255]:
      checkAgainstDirect(@[b])
      checkAgainstDirect(@[@[b]])
      checkAgainstDirect(@[@[@[b]]])

  test "empty and nested lists":
    checkAgainstDirect(newSeq[uint64]())
    checkAgainstDirect(@[newSeq[uint64]()])
    checkAgainstDirect(@[newSeq[uint64](), newSeq[uint64]()])
    checkAgainstDirect(@[@[newSeq[uint64]()]])
    checkAgainstDirect(@[@[@[newSeq[byte]()]]])

  test "deep nesting closes the enclosing lists in order":
    # a list whose last element is itself a list cascades the closing outwards,
    # which is the path the tracker takes when a counter reaches zero
    checkAgainstDirect(@[@[@[@[@[@[@[1'u64]]]]]]])
    checkAgainstDirect(@[@[@[1'u64, 2], @[3'u64]], @[@[4'u64]]])
    checkAgainstDirect(@[@[@[newSeq[uint64]()]], @[newSeq[seq[uint64]]()]])

  test "lists long enough to need a multi byte length prefix":
    var many: seq[uint64]
    for i in 0 ..< 200:
      many.add uint64(i) * 1_000_000
    checkAgainstDirect(many)

    var nested: seq[seq[uint64]]
    for i in 0 ..< 200:
      nested.add @[uint64(i), uint64(i) * 1_000_000]
    checkAgainstDirect(nested)

  test "randomised nested structures":
    var rng = initRand(0x1234)
    for _ in 0 ..< 2000:
      var outer: seq[seq[seq[uint64]]]
      for a in 0 ..< rng.rand(4):
        var mid: seq[seq[uint64]]
        for b in 0 ..< rng.rand(4):
          var inner: seq[uint64]
          for c in 0 ..< rng.rand(5):
            # cover self encoding, single byte and multi byte integers
            inner.add(
              case rng.rand(2)
              of 0: uint64(rng.rand(127))
              of 1: uint64(rng.rand(255))
              else: uint64(rng.rand(int.high))
            )
          mid.add inner
        outer.add mid
      checkAgainstDirect(outer)

  test "randomised blobs":
    var rng = initRand(0x5678)
    for _ in 0 ..< 2000:
      var outer: seq[seq[byte]]
      for a in 0 ..< rng.rand(5):
        var blob = newSeq[byte](rng.rand(80))
        for i in 0 ..< blob.len:
          blob[i] = byte(rng.rand(255))
        outer.add blob
      checkAgainstDirect(outer)

  test "objects":
    checkAgainstDirect(Header(number: 21_000_000'u64, gasLimit: 30_000_000'u64))
    checkAgainstDirect(
      Account(nonce: 42, balance: high(UInt256))
    )
    checkAgainstDirect(
      @[
        Header(number: 1'u64, extraData: newSeq[byte](64)),
        Header(number: high(uint64), extraData: newSeq[byte](0)),
      ]
    )
