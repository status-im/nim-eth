# Nimbus
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.
{.used.}

import
  stew/byteutils,
  unittest2,
  ../../eth/common,
  ../../eth/rlp,
  ../../eth/common/transaction


const
  recipient = hexToByteArray[20]("095e7baea6a6c7c4c2dfeb977efac326af552d87")
  zeroG1    = hexToByteArray[48]("0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
  source    = hexToByteArray[20]("0x0000000000000000000000000000000000000001")
  storageKey= default(StorageKey)
  accesses  = @[AccessPair(address: source, storageKeys: @[storageKey])]
  blob      = default(NetworkBlob)
  abcdef    = hexToSeqByte("abcdef")

proc tx0(i: int): Transaction =
  Transaction(
    txType:   TxLegacy,
    nonce:    i.AccountNonce,
    to:       recipient.some,
    gasLimit: 1.GasInt,
    gasPrice: 2.GasInt,
    payload:  abcdef)

proc tx1(i: int): Transaction =
  Transaction(
    # Legacy tx contract creation.
    txType:   TxLegacy,
    nonce:    i.AccountNonce,
    gasLimit: 1.GasInt,
    gasPrice: 2.GasInt,
    payload:  abcdef)

proc tx2(i: int): Transaction =
  Transaction(
    # Tx with non-zero access list.
    txType:     TxEip2930,
    chainId:    1.ChainId,
    nonce:      i.AccountNonce,
    to:         recipient.some,
    gasLimit:   123457.GasInt,
    gasPrice:   10.GasInt,
    accessList: accesses,
    payload:    abcdef)

proc tx3(i: int): Transaction =
  Transaction(
    # Tx with empty access list.
    txType:   TxEip2930,
    chainId:  1.ChainId,
    nonce:    i.AccountNonce,
    to:       recipient.some,
    gasLimit: 123457.GasInt,
    gasPrice: 10.GasInt,
    payload:  abcdef)

proc tx4(i: int): Transaction =
  Transaction(
    # Contract creation with access list.
    txType:     TxEip2930,
    chainId:    1.ChainId,
    nonce:      i.AccountNonce,
    gasLimit:   123457.GasInt,
    gasPrice:   10.GasInt,
    accessList: accesses)

proc tx5(i: int): Transaction =
  Transaction(
    txType:     TxEip1559,
    chainId:    1.ChainId,
    nonce:      i.AccountNonce,
    gasLimit:   123457.GasInt,
    maxPriorityFee: 42.GasInt,
    maxFee:     10.GasInt,
    accessList: accesses)

proc tx6(i: int): Transaction =
  const
    digest = "010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014".toDigest

  Transaction(
    txType:              TxEip4844,
    chainId:             1.ChainId,
    nonce:               i.AccountNonce,
    gasLimit:            123457.GasInt,
    maxPriorityFee:      42.GasInt,
    maxFee:              10.GasInt,
    accessList:          accesses,
    versionedHashes:     @[digest],
    networkPayload: NetworkPayload(        
        blobs: @[blob],
        commitments: @[zeroG1],
        proofs: @[zeroG1],
    )
  )

proc tx7(i: int): Transaction =
  const
    digest = "01624652859a6e98ffc1608e2af0147ca4e86e1ce27672d8d3f3c9d4ffd6ef7e".toDigest

  Transaction(
    txType:              TxEip4844,
    chainID:             1.ChainId,
    nonce:               i.AccountNonce,
    gasLimit:            123457.GasInt,
    maxPriorityFee:      42.GasInt,
    maxFee:              10.GasInt,
    accessList:          accesses,
    versionedHashes:     @[digest],
    maxFeePerDataGas:    10000000.GasInt,
  )

proc tx8(i: int): Transaction =
  const
    digest = "01624652859a6e98ffc1608e2af0147ca4e86e1ce27672d8d3f3c9d4ffd6ef7e".toDigest

  Transaction(
    txType:              TxEip4844,
    chainID:             1.ChainId,
    nonce:               i.AccountNonce,
    to:                  some(recipient),
    gasLimit:            123457.GasInt,
    maxPriorityFee:      42.GasInt,
    maxFee:              10.GasInt,
    accessList:          accesses,
    versionedHashes:     @[digest],
    maxFeePerDataGas:    10000000.GasInt,
  )

template roundTrip(txFunc: untyped, i: int) =
  let tx = txFunc(i)
  let bytes = rlp.encode(tx)
  let tx2 = rlp.decode(bytes, Transaction)
  let bytes2 = rlp.encode(tx2)
  check bytes == bytes2

suite "Transaction RLP Encoding":
  test "Legacy Tx Call":
    roundTrip(tx0, 1)

  test "Legacy tx contract creation":
    roundTrip(tx1, 2)

  test "Tx with non-zero access list":
    roundTrip(tx2, 3)

  test "Tx with empty access list":
    roundTrip(tx3, 4)

  test "Contract creation with access list":
    roundTrip(tx4, 5)

  test "Dynamic Fee Tx":
    roundTrip(tx5, 6)

  test "NetworkBlob Tx":
    roundTrip(tx6, 7)

  test "Minimal Blob Tx":
    roundTrip(tx7, 8)

  test "Minimal Blob Tx contract creation":
    roundTrip(tx8, 9)

  test "Network payload survive encode decode":
    let tx = tx6(10)
    let bytes = rlp.encode(tx)
    let zz = rlp.decode(bytes, Transaction)
    check not zz.networkPayload.isNil
    check zz.networkPayload.proofs == tx.networkPayload.proofs
    check zz.networkPayload.blobs == tx.networkPayload.blobs
    check zz.networkPayload.commitments == tx.networkPayload.commitments

  test "No Network payload still no network payload":
    let tx = tx7(11)
    let bytes = rlp.encode(tx)
    let zz = rlp.decode(bytes, Transaction)
    check zz.networkPayload.isNil

  test "Minimal Blob tx recipient survive encode decode":
    let tx = tx8(12)
    let bytes = rlp.encode(tx)
    let zz = rlp.decode(bytes, Transaction)
    check zz.to.isSome

  test "Tx List 0,1,2,3,4,5,6,7,8":
    let txs = @[tx0(3), tx1(3), tx2(3), tx3(3), tx4(3),
                tx5(3), tx6(3), tx7(3), tx8(3)]

    let bytes = rlp.encode(txs)
    let zz = rlp.decode(bytes, seq[Transaction])
    let bytes2 = rlp.encode(zz)
    check bytes2 == bytes

  test "Tx List 8,7,6,5,4,3,2,1,0":
    let txs = @[tx8(3), tx7(3) , tx6(3), tx5(3), tx4(3),
                tx3(3), tx2(3), tx1(3), tx0(3)]

    let bytes = rlp.encode(txs)
    let zz = rlp.decode(bytes, seq[Transaction])
    let bytes2 = rlp.encode(zz)
    check bytes2 == bytes

  test "Tx List 0,5,8,7,6,4,3,2,1":
    let txs = @[tx0(3), tx5(3), tx8(3), tx7(3), tx6(3),
                tx4(3), tx3(3), tx2(3), tx1(3)]

    let bytes = rlp.encode(txs)
    let zz = rlp.decode(bytes, seq[Transaction])
    let bytes2 = rlp.encode(zz)
    check bytes2 == bytes

  test "Receipts":
    let rec = Receipt(
      receiptType: Eip4844Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    let bytes = rlp.encode(rec)
    let zz = rlp.decode(bytes, Receipt)
    let bytes2 = rlp.encode(zz)
    check bytes2 == bytes
