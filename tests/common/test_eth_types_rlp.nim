# nim-eth
# Copyright (c) 2023-2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

{.used.}

import
  std/[os, strutils],
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
    let h = BlockHeader(baseFeePerGas: Opt.some(1.u256))
    roundTrip(h)

  test "Header + none(baseFee) + some(withdrawalsRoot)":
    let h = BlockHeader(withdrawalsRoot: Opt.some(Hash256()))
    expect AssertionDefect:
      roundTrip(h)

  test "Header + none(baseFee) + some(withdrawalsRoot) + " &
      "some(blobGasUsed) + some(excessBlobGas)":
    let h = BlockHeader(
      withdrawalsRoot: Opt.some(Hash256()),
      blobGasUsed: Opt.some(1'u64),
      excessBlobGas: Opt.some(1'u64)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + none(baseFee) + none(withdrawalsRoot) + " &
      "some(blobGasUsed) + some(excessBlobGas)":
    let h = BlockHeader(
      blobGasUsed: Opt.some(1'u64),
      excessBlobGas: Opt.some(1'u64)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + some(baseFee) + none(withdrawalsRoot) + " &
      "some(blobGasUsed) + some(excessBlobGas)":
    let h = BlockHeader(
      baseFeePerGas: Opt.some(2.u256),
      blobGasUsed: Opt.some(1'u64),
      excessBlobGas: Opt.some(1'u64)
    )
    expect AssertionDefect:
      roundTrip(h)

  test "Header + some(baseFee) + some(withdrawalsRoot)":
    let h = BlockHeader(
      baseFeePerGas: Opt.some(2.u256),
      withdrawalsRoot: Opt.some(Hash256())
    )
    roundTrip(h)

  test "Header + some(baseFee) + some(withdrawalsRoot) + " &
      "some(blobGasUsed) + some(excessBlobGas)":
    let h = BlockHeader(
      baseFeePerGas: Opt.some(2.u256),
      withdrawalsRoot: Opt.some(Hash256()),
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
    parentHash*:      Hash256
    ommersHash*:      Hash256
    coinbase*:        EthAddress
    stateRoot*:       Hash256
    txRoot*:          Hash256
    receiptRoot*:     Hash256
    bloom*:           BloomFilter
    difficulty*:      DifficultyInt
    blockNumber*:     BlockNumber
    gasLimit*:        GasInt
    gasUsed*:         GasInt
    timestamp*:       EthTime
    extraData*:       Blob
    mixDigest*:       Hash256
    nonce*:           BlockNonce
    fee*:             Opt[UInt256]
    withdrawalsRoot*: Opt[Hash256]
    blobGasUsed*:     Opt[GasInt]
    excessBlobGas*:   Opt[GasInt]

  BlockBodyOpt* = object
    transactions*:  seq[Transaction]
    uncles*:        seq[BlockHeaderOpt]
    withdrawals*:   Opt[seq[Withdrawal]]

  EthBlockOpt* = object
    header*     : BlockHeader
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

suite "EIP-7865 tests":
  const reqs = [
    Request(
      requestType: DepositRequestType,
      deposit: DepositRequest(
        pubkey               : hexToByteArray[48]("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        withdrawalCredentials: hexToByteArray[32]("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        amount               : 1,
        signature            : hexToByteArray[96]("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        index                : 3,
      )
    ),
    Request(
      requestType: WithdrawalRequestType,
      withdrawal: WithdrawalRequest(
        sourceAddress  : hexToByteArray[20]("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
        validatorPubkey: hexToByteArray[48]("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        amount         : 7,
      )
    ),
    Request(
      requestType: ConsolidationRequestType,
      consolidation: ConsolidationRequest(
        sourceAddress: hexToByteArray[20]("0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"),
        sourcePubkey : hexToByteArray[48]("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        targetPubkey : hexToByteArray[48]("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
      )
    )
  ]

  test "rlp roundtrip":
    let
      body = BlockBody(
        withdrawals: Opt.some(@[Withdrawal()]),
        requests: Opt.some(@reqs)
      )

      blk = EthBlock(
        withdrawals: Opt.some(@[Withdrawal()]),
        requests: Opt.some(@reqs)
      )

      encodedBody = rlp.encode(body)
      encodedBlock = rlp.encode(blk)
      decodedBody = rlp.decode(encodedBody, BlockBody)
      decodedBlk = rlp.decode(encodedBlock, EthBlock)

    check decodedBody == body
    check decodedBlk == blk

