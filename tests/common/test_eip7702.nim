# Nimbus
# Copyright (c) 2024 Status Research & Development GmbH
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
  results,
  unittest2,
  ../../eth/common,
  ../../eth/rlp,
  ../../eth/common/transaction,
  ../../eth/keys

const
  recipient = address"095e7baea6a6c7c4c2dfeb977efac326af552d87"
  zeroG1    = bytes48"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  source    = address"0x0000000000000000000000000000000000000001"
  storageKey= default(StorageKey)
  accesses  = @[AccessPair(address: source, storageKeys: @[storageKey])]
  abcdef    = hexToSeqByte("abcdef")
  authList  = @[Authorization(
    chainID: 1.ChainId,
    address: source,
    nonce: 2.AccountNonce,
    yParity: 3,
    R: 4.u256,
    S: 5.u256
  )]

proc tx0(i: int): Transaction =
  Transaction(
    txType:   TxEip7702,
    chainId:  1.ChainId,
    nonce:    i.AccountNonce,
    maxPriorityFeePerGas: 2.GasInt,
    maxFeePerGas: 3.GasInt,
    gasLimit: 4.GasInt,
    to:       Opt.some recipient,
    value:    5.u256,
    payload:  abcdef,
    accessList: accesses,
    authorizationList: authList
  )

func `==`(a, b: ChainId): bool =
  a.uint64 == b.uint64

template roundTrip(txFunc: untyped, i: int) =
  let tx = txFunc(i)
  let bytes = rlp.encode(tx)
  let tx2 = rlp.decode(bytes, Transaction)
  let bytes2 = rlp.encode(tx2)
  check bytes == bytes2

template read[T](rlp: var Rlp, val: var T) =
  val = rlp.read(type val)

proc read[T](rlp: var Rlp, val: var Opt[T]) =
  if rlp.blobLen != 0:
    val = Opt.some(rlp.read(T))
  else:
    rlp.skipElem

proc readTx(rlp: var Rlp, tx: var Transaction) =
  rlp.tryEnterList()
  tx.chainId = rlp.read(uint64).ChainId
  rlp.read(tx.nonce)
  rlp.read(tx.maxPriorityFeePerGas)
  rlp.read(tx.maxFeePerGas)
  rlp.read(tx.gasLimit)
  rlp.read(tx.to)
  rlp.read(tx.value)
  rlp.read(tx.payload)
  rlp.read(tx.accessList)
  rlp.read(tx.authorizationList)

proc decodeTxEip7702(bytes: openArray[byte]): Transaction =
  var rlp = rlpFromBytes(bytes)
  result.txType = TxType(rlp.getByteValue)
  rlp.position += 1
  readTx(rlp, result)

suite "Transaction EIP-7702 tests":
  test "Tx RLP roundtrip":
    roundTrip(tx0, 1)

  test "Tx Sign":
    const
      keyHex = "63b508a03c3b5937ceb903af8b1b0c191012ef6eb7e9c3fb7afa94e5d214d376"

    var
      tx = tx0(2)

    let
      privateKey = PrivateKey.fromHex(keyHex).valueOr:
        echo "ERROR: ", error
        quit(QuitFailure)
      rlpTx = rlpEncode(tx)
      sig = sign(privateKey, rlpTx).toRaw

    tx.V = sig[64].uint64
    tx.R = UInt256.fromBytesBE(sig[0..31])
    tx.S = UInt256.fromBytesBE(sig[32..63])

    let
      bytes = rlp.encode(tx)
      decodedTx = rlp.decode(bytes, Transaction)
      decodedNoSig = decodeTxEip7702(rlpTx)

    var
      expectedTx = tx0(2)

    check expectedTx == decodedNoSig

    expectedTx.V = tx.V
    expectedTx.R = tx.R
    expectedTx.S = tx.S

    check expectedTx == tx

  test "Receipt RLP roundtrip":
    let rec = Receipt(
      receiptType: Eip7702Receipt,
      isHash: false,
      status: false,
      cumulativeGasUsed: 100.GasInt)

    let bytes = rlp.encode(rec)
    let zz = rlp.decode(bytes, Receipt)
    let bytes2 = rlp.encode(zz)
    check bytes2 == bytes
