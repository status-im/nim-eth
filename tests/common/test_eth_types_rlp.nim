# nim-eth
# Copyright (c) 2023-2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

{.used.}

import
  std/[os, strutils, typetraits],
  stew/io2,
  stew/byteutils,
  results,
  unittest2,
  ../../eth/[rlp, common]

proc importBlock(blocksRlp: openArray[byte]): bool =
  var
    # the encoded rlp can contains one or more blocks
    rlp = rlpFromBytes(blocksRlp)

  while rlp.hasData:
    let blk = rlp.read(EthBlock)
    if blk.withdrawals.isSome:
      # all of these blocks are pre shanghai blocks
      return false

  true

proc runTest(importFile: string): bool =
  let res = io2.readAllBytes(importFile)
  if res.isErr:
    echo "failed to import", importFile
    return

  importBlock(res.get)

suite "Decode multiple EthBlock from bytes":
  for filename in walkDirRec("tests/common/rlps"):
    if not filename.endsWith(".rlp"):
      continue
    test filename:
      check runTest(filename)

func `==`(a, b: ChainId): bool =
  distinctBase(a) == distinctBase(b)

template roundTrip(x) =
  type TT = type(x)
  let bytes = rlp.encode(x)
  let xx = rlp.decode(bytes, TT)
  check xx == x

suite "BlockHeader roundtrip test":
  test "Empty header":
    let h = Header()
    roundTrip(h)

  test "Header with gas":
    let h = Header(gasLimit: 10.GasInt, gasUsed: 11.GasInt)
    roundTrip(h)

  test "Header + some(baseFee)":
    let h = Header(baseFeePerGas: Opt.some(1.u256))
    roundTrip(h)

  test "Header + none(baseFee) + some(withdrawalsRoot)":
    let h = Header(withdrawalsRoot: Opt.some(default(Hash32)))
    expect AssertionDefect:
      roundTrip(h)

  test "Header + none(baseFee) + some(withdrawalsRoot) + " &
      "some(blobGasUsed) + some(excessBlobGas)":
    let h = Header(
      withdrawalsRoot: Opt.some(default(Hash32)),
      blobGasUsed: Opt.some(1'u64),
      excessBlobGas: Opt.some(1'u64)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + none(baseFee) + none(withdrawalsRoot) + " &
      "some(blobGasUsed) + some(excessBlobGas)":
    let h = Header(
      blobGasUsed: Opt.some(1'u64),
      excessBlobGas: Opt.some(1'u64)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + some(baseFee) + none(withdrawalsRoot) + " &
      "some(blobGasUsed) + some(excessBlobGas)":
    let h = Header(
      baseFeePerGas: Opt.some(2.u256),
      blobGasUsed: Opt.some(1'u64),
      excessBlobGas: Opt.some(1'u64)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + some(baseFee) + some(withdrawalsRoot)":
    let h = Header(
      baseFeePerGas: Opt.some(2.u256),
      withdrawalsRoot: Opt.some(default(Hash32))
    )
    roundTrip(h)

  test "Header + some(baseFee) + some(withdrawalsRoot) + " &
      "some(blobGasUsed) + some(excessBlobGas)":
    let h = Header(
      baseFeePerGas: Opt.some(2.u256),
      withdrawalsRoot: Opt.some(default(Hash32)),
      blobGasUsed: Opt.some(1'u64),
      excessBlobGas: Opt.some(1'u64)
    )
    roundTrip(h)

template roundTrip2(a1, a2, body: untyped) =
  type TT = type(a1)
  when type(a2) isnot TT:
    {.error: "mismatch type".}
  var bytes = rlp.encode(a1)
  bytes.add rlp.encode(a2)
  var r = rlpFromBytes(bytes)
  let
    b1 {.inject.} = r.read(TT)
    b2 {.inject.} = r.read(TT)
  check b1 == a1
  check b2 == a2
  body


template genTest(TT) =
  const TTS = astToStr(TT)
  suite TTS & " roundtrip test":
    test "Empty " & TTS:
      let blk = TT()
      roundTrip(blk)

    test TTS & " with withdrawals":
      let blk = TT(withdrawals: Opt.some(@[Withdrawal()]))
      roundTrip(blk)

    test "2 " & TTS & " none(Withdrawal)+none(Withdrawal)":
      let blk = TT()
      roundTrip2(blk, blk):
        check b1.withdrawals.isNone
        check b2.withdrawals.isNone

    test "2 " & TTS & " none(Withdrawal)+some(Withdrawal)":
      let blk1 = TT()
      let blk2 = TT(withdrawals: Opt.some(@[Withdrawal()]))
      roundTrip2(blk1, blk2):
        check b1.withdrawals.isNone
        check b2.withdrawals.isSome

    test "2 " & TTS & " some(Withdrawal)+none(Withdrawal)":
      let blk1 = TT()
      let blk2 = TT(withdrawals: Opt.some(@[Withdrawal()]))
      roundTrip2(blk2, blk1):
        check b1.withdrawals.isSome
        check b2.withdrawals.isNone

    test "2 " & TTS & " some(Withdrawal)+some(Withdrawal)":
      let blk = TT(withdrawals: Opt.some(@[Withdrawal()]))
      roundTrip2(blk, blk):
        check b1.withdrawals.isSome
        check b2.withdrawals.isSome

genTest(EthBlock)
genTest(BlockBody)

type
  BlockHeaderOpt* = object
    parentHash*:      Hash32
    ommersHash*:      Hash32
    coinbase*:        Address
    stateRoot*:       Hash32
    txRoot*:          Hash32
    receiptRoot*:     Hash32
    bloom*:           Bloom
    difficulty*:      DifficultyInt
    blockNumber*:     BlockNumber
    gasLimit*:        GasInt
    gasUsed*:         GasInt
    timestamp*:       EthTime
    extraData*:       seq[byte]
    mixDigest*:       Hash32
    nonce*:           Bytes8
    fee*:             Opt[UInt256]
    withdrawalsRoot*: Opt[Hash32]
    blobGasUsed*:     Opt[GasInt]
    excessBlobGas*:   Opt[GasInt]
    systemLogsRoot*:  Opt[Hash32]

  BlockBodyOpt* = object
    transactions*:  seq[Transaction]
    uncles*:        seq[BlockHeaderOpt]
    withdrawals*:   Opt[seq[Withdrawal]]

  EthBlockOpt* = object
    header*     : Header
    txs*        : seq[Transaction]
    uncles*     : seq[BlockHeaderOpt]
    withdrawals*: Opt[seq[Withdrawal]]

template genTestOpt(TT) =
  const TTS = astToStr(TT)
  suite TTS & " roundtrip test":
    test "Empty " & TTS:
      let blk = TT()
      roundTrip(blk)

    test TTS & " with withdrawals":
      let blk = TT(withdrawals: Opt.some(@[Withdrawal()]))
      roundTrip(blk)

    test "2 " & TTS & " none(Withdrawal)+none(Withdrawal)":
      let blk = TT()
      roundTrip2(blk, blk):
        check b1.withdrawals.isNone
        check b2.withdrawals.isNone

    test "2 " & TTS & " none(Withdrawal)+some(Withdrawal)":
      let blk1 = TT()
      let blk2 = TT(withdrawals: Opt.some(@[Withdrawal()]))
      roundTrip2(blk1, blk2):
        check b1.withdrawals.isNone
        check b2.withdrawals.isSome

    test "2 " & TTS & " some(Withdrawal)+none(Withdrawal)":
      let blk1 = TT()
      let blk2 = TT(withdrawals: Opt.some(@[Withdrawal()]))
      roundTrip2(blk2, blk1):
        check b1.withdrawals.isSome
        check b2.withdrawals.isNone

    test "2 " & TTS & " some(Withdrawal)+some(Withdrawal)":
      let blk = TT(withdrawals: Opt.some(@[Withdrawal()]))
      roundTrip2(blk, blk):
        check b1.withdrawals.isSome
        check b2.withdrawals.isSome

genTestOpt(BlockBodyOpt)
genTestOpt(EthBlockOpt)
