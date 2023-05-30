{.used.}

import
  std/[os, strutils],
  stew/[io2, results, shims/stddefects],
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
  for filename in walkDirRec("tests/rlp/rlps"):
    if not filename.endsWith(".rlp"):
      continue
    test filename:
      check runTest(filename)

func `==`(a, b: ChainId): bool =
  a.uint == b.uint

template roundTrip(x) =
  type TT = type(x)
  let bytes = rlp.encode(x)
  let xx = rlp.decode(bytes, TT)
  check xx == x

suite "BlockHeader roundtrip test":
  test "Empty header":
    let h = BlockHeader()
    roundTrip(h)

  test "Header with gas":
    let h = BlockHeader(gasLimit: 10.GasInt, gasUsed: 11.GasInt)
    roundTrip(h)

  test "Header + some(baseFee)":
    let h = BlockHeader(fee: some(1.u256))
    roundTrip(h)

  test "Header + none(baseFee) + some(withdrawalsRoot)":
    let h = BlockHeader(withdrawalsRoot: some(Hash256()))
    expect AssertionDefect:
      roundTrip(h)

  test "Header + none(baseFee) + some(withdrawalsRoot) + some(excessDataGas)":
    let h = BlockHeader(
      withdrawalsRoot: some(Hash256()),
      excessDataGas: some(1.u256)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + none(baseFee) + none(withdrawalsRoot) + some(excessDataGas)":
    let h = BlockHeader(
      excessDataGas: some(1.u256)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + some(baseFee) + none(withdrawalsRoot) + some(excessDataGas)":
    let h = BlockHeader(
      fee: some(2.u256),
      excessDataGas: some(1.u256)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + some(baseFee) + some(withdrawalsRoot)":
    let h = BlockHeader(
      fee: some(2.u256),
      withdrawalsRoot: some(Hash256())
    )
    roundTrip(h)

  test "Header + some(baseFee) + some(withdrawalsRoot) + some(excessDataGas)":
    let h = BlockHeader(
      fee: some(2.u256),
      withdrawalsRoot: some(Hash256()),
      excessDataGas: some(1.u256)
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
      let blk = TT(withdrawals: some(@[Withdrawal()]))
      roundTrip(blk)
  
    test "2 " & TTS & " none(Withdrawal)+none(Withdrawal)":
      let blk = TT()
      roundTrip2(blk, blk):
        check b1.withdrawals.isNone
        check b2.withdrawals.isNone
  
    test "2 " & TTS & " none(Withdrawal)+some(Withdrawal)":
      let blk1 = TT()
      let blk2 = TT(withdrawals: some(@[Withdrawal()]))
      roundTrip2(blk1, blk2):
        check b1.withdrawals.isNone
        check b2.withdrawals.isSome
  
    test "2 " & TTS & " some(Withdrawal)+none(Withdrawal)":
      let blk1 = TT()
      let blk2 = TT(withdrawals: some(@[Withdrawal()]))
      roundTrip2(blk2, blk1):
        check b1.withdrawals.isSome
        check b2.withdrawals.isNone
  
    test "2 " & TTS & " some(Withdrawal)+some(Withdrawal)":
      let blk = TT(withdrawals: some(@[Withdrawal()]))
      roundTrip2(blk, blk):
        check b1.withdrawals.isSome
        check b2.withdrawals.isSome

genTest(EthBlock)
genTest(BlockBody)
