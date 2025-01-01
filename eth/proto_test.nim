import
  ./common/transactions,
  ./common/transactions_rlp,
  stew/byteutils,
  ./proto,
  ./protov2,
  ./rlp/writer

import
  ./rlp/object_serialization

func makeAuth(): Authorization =
  Authorization(
    chainId: 1.ChainId,
    address: address"0x0000000000000000000000000000000000000002",
    nonce  : 3.AccountNonce,
    v: 4'u64,
    r: 5.u256,
    s: 6.u256,
  )

func makeAL(): AccessPair =
  AccessPair(
    address: address"0x0000000000000000000000000000000000000003",
    storageKeys: @[bytes32"0102030405060708091011121314151617181920212223242526272829303132"],
  )

func makeTx(txType: TxType): Transaction =
  Transaction(
    txType        : txType,
    chainId       : 1.ChainId,
    nonce         : 2.AccountNonce,
    gasPrice      : 3.GasInt,
    maxPriorityFeePerGas: 4.GasInt,
    maxFeePerGas  : 5.GasInt,
    gasLimit      : 6.GasInt,
    to            : Opt.some(address"0x0000000000000000000000000000000000000007"),
    value         : 123.u256,
    payload       : hexToSeqByte("0x1234567890"),
    accessList    : @[makeAL()],
    maxFeePerBlobGas: 456.u256,
    versionedHashes: @[hash32"010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"],
    authorizationList: @[makeAuth()],
    V             : 789'u64,
    R             : 10111213.u256,
    S             : 14151617.u256,
  )

proc main() =
  let tx = makeTx(TxEip4844)
  let w = encodeHash(tx)
  debugEcho "ENCODE HASH: ", w
  let z = protoHash(tx)
  debugEcho "PROTO HASH: ", z
  let y = protoHash(tx)
  debugEcho "PROTO HASH V2: ", y

  doAssert(z == w)
  doAssert(y == w)
  debugEcho "------------------------"

import
  std/times

proc test() =
  let txs = [
    makeTx(TxLegacy),
    makeTx(TxEip2930),
    makeTx(TxEip1559),
    makeTx(TxEip4844),
    makeTx(TxEip7702),
  ]

  for tx in txs:
    let
      ph = protoHash(tx)
      eh = encodeHash(tx)
      v2 = protoHashV2(tx)
    doAssert(ph == eh)
    doAssert(eh == v2)


proc bench() =
  let txs = [
    makeTx(TxLegacy),
    makeTx(TxEip2930),
    makeTx(TxEip1559),
    makeTx(TxEip4844),
    makeTx(TxEip7702),
  ]

  const MAX_ITER = 1_000_000

  var start = getTime()
  for _ in 0..<MAX_ITER:
    for tx in txs:
      let ph = protoHash(tx)
  var elapsed = getTime() - start
  debugEcho "PROTOHASH TIME: ", elapsed

  start = getTime()
  for _ in 0..<MAX_ITER:
    for tx in txs:
      let eh = protoHashV2(tx)
  elapsed = getTime() - start
  debugEcho "PROTOV2 TIME: ", elapsed

  start = getTime()
  for _ in 0..<MAX_ITER:
    for tx in txs:
      let eh = encodeHash(tx)
  elapsed = getTime() - start
  debugEcho "ENCODEHASH TIME: ", elapsed

  start = getTime()
  for _ in 0..<MAX_ITER:
    for tx in txs:
      let bytes = encode(tx)
      let kh = keccak256(bytes)

  elapsed = getTime() - start
  debugEcho "ENCODEBYTES TIME: ", elapsed

main()
test()
bench()
