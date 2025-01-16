# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import 
  ../../eth/[rlp, common],
  unittest2,
  times,
  std/[os, strutils],
  stew/io2,
  results

proc readBlock(): EthBlock =
  
  let
    filename = "tests/common/rlps/blocks_1024_td_135112316.rlp"
    res = io2.readAllBytes(filename)

  if res.isErr:
    echo "failed to import", filename
    return
  
  var
    # the encoded rlp can contains one or more blocks
    rlpBytes = rlpFromBytes(res.get)

  while rlpBytes.hasData:
    result = rlpBytes.read(EthBlock)

template benchmark(benchmarkName: string, code: untyped) =
  block:
    var sum = 0.0
    for i in countup(1,100):
      let t0 = epochTime()
      code
      sum += (epochTime() - t0)
    let elapsed = sum/100
    let elapsedStr = elapsed.formatFloat(format = ffDecimal, precision = 9)
    echo "CPU Time [", benchmarkName, "] ", elapsedStr, "s"

const 
  accesses  = @[AccessPair(
    address: address"0x0000000000000000000000000000000000000001", 
    storageKeys: @[default(Bytes32)]
  )]

let myTx = Transaction(
  txType:     TxEip1559,
  chainId:    1.ChainId,
  nonce:      0.AccountNonce,
  gasLimit:   123457.GasInt,
  maxPriorityFeePerGas: 42.GasInt,
  maxFeePerGas: 10.GasInt,
  accessList: accesses
)

let blkSeq = @[
  BlockBody(
    transactions: @[
      Transaction(nonce: 1)]),
  BlockBody(
    uncles: @[Header(nonce: Bytes8([0x20u8,0,0,0,0,0,0,0]))]),
  BlockBody(),
  BlockBody(
    transactions: @[
      Transaction(nonce: 3),
      Transaction(nonce: 4)])]

let h = BlockHeader(
  nonce: Bytes8([0x20u8,0,0,0,0,0,0,0]),
  baseFeePerGas: Opt.some(2.u256),
  withdrawalsRoot: Opt.some(default(Hash32)),
  blobGasUsed: Opt.some(1'u64),
  excessBlobGas: Opt.some(1'u64)
)

let nonEmptyBlock = readBlock()

proc encodeOnePass[T](v: T): seq[byte] =
  var writer = initRlpWriter()

  writer.append(v)
  move(writer.finish)

proc encodeAndHash[T](v: T): Hash32 =
  keccak256(encodeOnePass(v))

suite "test running times of rlp encode and encodeHash":
  test "encoding using two pass writer":
    benchmark "Transaction serialization using two pass writer":
      let bytes1 = rlp.encode(myTx)
    benchmark "Block Sequence serialization using two pass writer":
      let bytes2 = rlp.encode(blkSeq)
    benchmark "Block serialization using two pass writer":
      let bytes3 = rlp.encode(nonEmptyBlock)
    benchmark "Block header serialization using two pass writer":
      let bytes4 = rlp.encode(h)

  test "encoding using default writer":
    benchmark "Transaction serialization using default writer":
      let bytes5 = encodeOnePass(myTx)
    benchmark "Block Sequence serailization using default writer":
      let bytes6 = encodeOnePass(blkSeq)
    benchmark "Block serialization using default writer":
      let bytes7 = encodeOnePass(nonEmptyBlock)
    benchmark "Block header serialization using default writer":
      let bytes8 = encodeOnePass(h)

  test "encoding and hashing using hash writer":
    benchmark "Transaction hashing using hash writer":
      let bytes9 = rlp.encodeHash(myTx)
    benchmark "Block Sequence hashing using hash writer":
      let bytes10 = rlp.encodeHash(blkSeq)
    benchmark "Block hashing using hash writer":
      let bytes11 = rlp.encodeHash(nonEmptyBlock)
    benchmark "Block header hashing using hash writer":
      let bytes12 = rlp.encodeHash(h)

  test "encoding and hashin using default writer":
    benchmark "Transaction hashing using default writer and then hash":
      let bytes13 = encodeAndHash(myTx)
    benchmark "Block Sequence hashing using default writer and then hash":
      let bytes14 = encodeAndHash(blkSeq)
    benchmark "Block hashing using default writer and then hash":
      let bytes15 = encodeAndHash(nonEmptyBlock)
    benchmark "Block header hashing using default writer and then hash":
      let bytes16 = encodeAndHash(h)
