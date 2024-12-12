{.used.}

import 
  ../../eth/[rlp, common],
  unittest2,
  times,
  os,
  strutils

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

proc encodeAndHash[T](v: T): Hash32 =
  var writer = initRlpWriter()

  writer.append(v)

  keccak256(writer.finish())

suite "test simulatneous encoding and hashing using hash writer":
  test "sanity check - Transaction":
    let hashedTx = encodeAndHash(myTx)
    check rlp.encodeHash(myTx) == hashedTx
  test "sanity check - Transaction":
    let hashedBlockSeq = encodeAndHash(blkSeq)
    check rlp.encodeHash(blkSeq) == hashedBlockSeq
