{.used.}

import 
  ../../eth/[rlp, common],
  unittest2,
  times,
  os,
  strutils

template benchmark(benchmarkName: string, code: untyped) =
  block:
    let t0 = epochTime()
    code
    let elapsed = (epochTime() - t0)
    let elapsedStr = elapsed.formatFloat(format = ffDecimal, precision = 9)
    echo "CPU Time [", benchmarkName, "] ", elapsedStr, "s"

const 
  accesses  = @[AccessPair(
    address: address"0x0000000000000000000000000000000000000001", 
    storageKeys: @[default(Bytes32)]
  )]

let my_tx = Transaction(
  txType:     TxEip1559,
  chainId:    1.ChainId,
  nonce:      0.AccountNonce,
  gasLimit:   123457.GasInt,
  maxPriorityFeePerGas: 42.GasInt,
  maxFeePerGas: 10.GasInt,
  accessList: accesses
)

suite "test running time of rlp serialization":
  test "transaction serialization":
    benchmark "Transaction":
      let myBytes = rlp.encode(my_tx)
