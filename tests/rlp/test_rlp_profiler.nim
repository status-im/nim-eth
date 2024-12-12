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

proc encodeAndHash[T](v: T): Hash32 =
  keccak256(encodeOnePass(v))

suite "test running times of rlp encode and encodeHash":
  test "encoding using two pass writer":
    benchmark "Transaction serialization using two pass writer":
      let bytes1 = rlp.encode(myTx)
    benchmark "Block Sequence serialization using two pass writer":
      let bytes2 = rlp.encode(blkSeq)
  test "encoding using default writer":
    benchmark "Transaction serialization using default writer":
      let bytes3 = encodeOnePass(myTx)
    benchmark "Block Sequence serailization using default writer":
      let bytes4 = encodeOnePass(blkSeq)
  test "encoding and hashing using hash writer":
    benchmark "Transaction hashing using hash writer":
      let bytes5 = rlp.encodeHash(myTx)
    benchmark "Block Sequence hashing using hash writer":
      let bytes6 = rlp.encodeHash(blkSeq)
  test "encoding and hashin using default writer":
    benchmark "Transaction hashing using default writer and then hash":
      let bytes7 = encodeAndHash(myTx)
    benchmark "Block Sequence hashing using default writer and then hash":
      let bytes8 = encodeAndHash(blkSeq)
