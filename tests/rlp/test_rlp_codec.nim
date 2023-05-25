{.used.}

import
  std/[os, strutils],
  stew/[io2, results, shims/stddefects],
  unittest2,
  ../../eth/[rlp, common]

type
  # trick the rlp decoder
  # so we can separate the body and header
  EthHeader = object
    header: BlockHeader

proc importBlock(blocksRlp: openArray[byte]): bool =
  var
    # the encoded rlp can contains one or more blocks
    rlp = rlpFromBytes(blocksRlp)

  while rlp.hasData:
    let
      header = rlp.read(EthHeader).header
      body = rlp.readRecordType(BlockBody, false)

  true

proc runTest(importFile: string): bool =
  let res = io2.readAllBytes(importFile)
  if res.isErr:
    echo "failed to import", importFile
    return

  importBlock(res.get)

suite "Partial EthBlock read using rlp.read and rlp.readRecordType":
  for filename in walkDirRec("tests/rlp/rlps"):
    if not filename.endsWith(".rlp"):
      continue
    test filename:
      check runTest(filename)

func `==`(a, b: ChainId): bool =
  a.uint == b.uint
  
template roundTrip(blk: EthBlock) =
  let bytes = rlp.encode(blk)
  let blk2 = rlp.decode(bytes, EthBlock)
  check blk2 == blk

template roundTrip(h: BlockHeader) =
  let bytes = rlp.encode(h)
  let h2 = rlp.decode(bytes, BlockHeader)
  check h2 == h

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
    
suite "EthBlock roundtrip test":
  test "Empty EthBlock":
    let blk = EthBlock()
    roundTrip(blk)

  test "EthBlock with withdrawals":
    let blk = EthBlock(withdrawals: some(@[Withdrawal()]))
    roundTrip(blk)
