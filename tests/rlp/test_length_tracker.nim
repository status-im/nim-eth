# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/random,
  ../../eth/[rlp, common],
  unittest2

proc encodeDirect[T](v: T): seq[byte] =
  var writer = initRlpWriter()
  writer.append(v)
  move(writer.finish)

type WrapItem = object
  ## An integer or a list, optionally wrapped: encoded as a blob holding its
  ## encoding
  isList, wrap: bool
  value: uint64
  list: seq[uint64]

proc append(w: var RlpWriter, x: WrapItem) =
  template appendItem(w: untyped) =
    if x.isList:
      w.append(x.list)
    else:
      w.append(x.value)

  if x.wrap:
    when w is RlpDefaultWriter:
      # no `wrapEncoding` - encode separately, as a reference
      var inner = initRlpWriter()
      inner.appendItem()
      w.append(inner.finish)
    else:
      w.wrapEncoding(1)
      w.appendItem()
  else:
    w.appendItem()

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

  test "wrapped encodings anywhere in a list":
    var rng = initRand(0x9abc)
    for _ in 0 ..< 2000:
      var outer: seq[seq[WrapItem]]
      for a in 0 ..< rng.rand(1 .. 3):
        var items: seq[WrapItem]
        for b in 0 ..< rng.rand(5):
          var item = WrapItem(isList: rng.rand(1) == 1, wrap: rng.rand(1) == 1)
          if item.isList:
            for c in 0 ..< rng.rand(3):
              item.list.add uint64(rng.rand(1000))
          else:
            # below 128, an integer is its own single byte encoding
            item.value = uint64(rng.rand(200))
          items.add item
        outer.add items
      checkAgainstDirect(outer)
      checkAgainstDirect(outer[0])

  test "consecutive wrapped single bytes":
    checkAgainstDirect(@[
      WrapItem(wrap: true, value: 1), WrapItem(wrap: true, value: 2),
      WrapItem(wrap: true, value: 300), WrapItem(wrap: true, value: 3)])

  test "typed transactions and receipts in a list":
    # typed ones are wrapped in a blob, legacy ones are not
    var
      txs: seq[Transaction]
      receipts: seq[Receipt]
    for i in 0 ..< 6:
      txs.add Transaction(
        txType: if i mod 3 == 0: TxLegacy else: TxEip1559,
        nonce: uint64(i),
        payload: newSeq[byte](i * 20),
        accessList: @[AccessPair(storageKeys: newSeq[Bytes32](i mod 3))],
      )
      receipts.add Receipt(
        receiptType: if i mod 3 == 0: LegacyReceipt else: Eip1559Receipt,
        cumulativeGasUsed: uint64(i),
        logs: newSeq[Log](i mod 2),
      )
    checkAgainstDirect(txs)
    checkAgainstDirect(receipts)
    checkAgainstDirect(@[txs, txs])
    checkAgainstDirect(EthBlock(transactions: txs))
