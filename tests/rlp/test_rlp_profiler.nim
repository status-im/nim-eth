{.used.}

import 
  ../../eth/[rlp, common],
  unittest2,
  times,
  os,
  strutils

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

proc encodeOnePass[T](v: T): seq[byte] =
  var writer = initRlpWriter()

  writer.append(v)
  move(writer.finish)


suite "test running time of rlp serialization":
  test "transaction serialization":
    benchmark "Transaction serialization (two pass)":
      let myTxBytes = rlp.encode(myTx)
    benchmark "Block Sequence serialization (two pass)":
      let myBlockBytes = rlp.encode(blkSeq)
    benchmark "Transaction serialization (one pass)":
      let myTxBytesOnePass = encodeOnePass(myTx)
    benchmark "Block Sequence serailization (one pass)":
      let myBlockBytesOnePass = encodeOnePass(blkSeq)
