# Nimbus
# Copyright (c) 2023-2025 Status Research & Development GmbH
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
  ../../eth/common/[transactions_rlp, transaction_utils]

const
  recipient = address"095e7baea6a6c7c4c2dfeb977efac326af552d87"
  zeroG1    = bytes48"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  source    = address"0x0000000000000000000000000000000000000001"
  storageKey= default(Bytes32)
  accesses  = @[AccessPair(address: source, storageKeys: @[storageKey])]
  abcdef    = hexToSeqByte("abcdef")
  authList  = @[Authorization(
    chainID: chainId(1),
    address: source,
    nonce: 2.AccountNonce,
    yParity: 1,
    r: 1.u256,
    s: 1.u256
  )]

proc tx0*(i: int): Transaction =
  Transaction(
    txType:   TxLegacy,
    nonce:    i.AccountNonce,
    to:       Opt.some recipient,
    gasLimit: 1.GasInt,
    gasPrice: 2.GasInt,
    payload:  abcdef)

proc tx1*(i: int): Transaction =
  Transaction(
    # Legacy tx contract creation.
    txType:   TxLegacy,
    nonce:    i.AccountNonce,
    gasLimit: 1.GasInt,
    gasPrice: 2.GasInt,
    payload:  abcdef)

proc tx2*(i: int): Transaction =
  Transaction(
    # Tx with non-zero access list.
    txType:     TxEip2930,
    chainId:    chainId(1),
    nonce:      i.AccountNonce,
    to:         Opt.some recipient,
    gasLimit:   123457.GasInt,
    gasPrice:   10.GasInt,
    accessList: accesses,
    payload:    abcdef)

proc tx3*(i: int): Transaction =
  Transaction(
    # Tx with empty access list.
    txType:   TxEip2930,
    chainId:  chainId(1),
    nonce:    i.AccountNonce,
    to:       Opt.some recipient,
    gasLimit: 123457.GasInt,
    gasPrice: 10.GasInt,
    payload:  abcdef)

proc tx4*(i: int): Transaction =
  Transaction(
    # Contract creation with access list.
    txType:     TxEip2930,
    chainId:    chainId(1),
    nonce:      i.AccountNonce,
    gasLimit:   123457.GasInt,
    gasPrice:   10.GasInt,
    accessList: accesses)

proc tx5*(i: int): Transaction =
  Transaction(
    txType:     TxEip1559,
    chainId:    chainId(1),
    nonce:      i.AccountNonce,
    gasLimit:   123457.GasInt,
    maxPriorityFeePerGas: 42.GasInt,
    maxFeePerGas: 10.GasInt,
    accessList: accesses)

proc tx6*(i: int): Transaction =
  const
    digest = hash32"010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"

  Transaction(
    txType:              TxEip4844,
    chainId:             chainId(1),
    nonce:               i.AccountNonce,
    gasLimit:            123457.GasInt,
    maxPriorityFeePerGas:42.GasInt,
    maxFeePerGas:        10.GasInt,
    accessList:          accesses,
    versionedHashes:     @[digest])

proc tx7*(i: int): Transaction =
  const
    digest = hash32"01624652859a6e98ffc1608e2af0147ca4e86e1ce27672d8d3f3c9d4ffd6ef7e"

  Transaction(
    txType:              TxEip4844,
    chainID:             chainId(1),
    nonce:               i.AccountNonce,
    gasLimit:            123457.GasInt,
    maxPriorityFeePerGas:42.GasInt,
    maxFeePerGas:        10.GasInt,
    accessList:          accesses,
    versionedHashes:     @[digest],
    maxFeePerBlobGas:    10000000.u256)

proc tx8*(i: int): Transaction =
  const
    digest = hash32"01624652859a6e98ffc1608e2af0147ca4e86e1ce27672d8d3f3c9d4ffd6ef7e"

  Transaction(
    txType:              TxEip4844,
    chainID:             chainId(1),
    nonce:               i.AccountNonce,
    to:                  Opt.some(recipient),
    gasLimit:            123457.GasInt,
    maxPriorityFeePerGas:42.GasInt,
    maxFeePerGas:        10.GasInt,
    accessList:          accesses,
    
    versionedHashes:     @[digest],
    maxFeePerBlobGas:    10000000.u256)

proc txEip7702*(i: int): Transaction =
  Transaction(
    txType:   TxEip7702,
    chainId:  chainId(1),
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

template roundTrip(txFunc: untyped, i: int) =
  let tx = txFunc(i)
  let bytes = rlp.encode(tx)
  let tx2 = rlp.decode(bytes, Transaction)
  let bytes2 = rlp.encode(tx2)
  check bytes == bytes2

suite "Transactions":
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

  test "EIP 7702":
    roundTrip(txEip7702, 9)

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

  test "EIP-155 signature":
    # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#example
    var
      tx = Transaction(
        txType: TxLegacy,
        chainId: chainId(1),
        nonce: 9,
        gasPrice: 20000000000'u64,
        gasLimit: 21000'u64,
        to: Opt.some address"0x3535353535353535353535353535353535353535",
        value: u256"1000000000000000000",
      )
      txEnc = tx.encodeForSigning(true)
      txHash = tx.rlpHashForSigning(true)
      key = PrivateKey.fromHex("0x4646464646464646464646464646464646464646464646464646464646464646").expect(
          "working key"
        )

    tx.signature = tx.sign(key, true)

    check:
      txEnc.to0xHex == "0xec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
      txHash == hash32"0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
      tx.V == 37
      tx.R ==
        u256"18515461264373351373200002665853028612451056578545711640558177340181847433846"
      tx.S ==
        u256"46948507304638947509940763649030358759909902576025900602547168820602576006531"

  test "sign transaction":
    let
      txs = @[
        tx0(3), tx1(3), tx2(3), tx3(3), tx4(3),
        tx5(3), tx6(3), tx7(3), tx8(3), txEip7702(3)]

      privKey = PrivateKey.fromHex("63b508a03c3b5937ceb903af8b1b0c191012ef6eb7e9c3fb7afa94e5d214d376").expect("valid key")
      sender = privKey.toPublicKey().to(Address)

    for tx in txs:
      var tx = tx
      tx.signature = tx.sign(privKey, true)

      check:
        tx.recoverKey().expect("valid key").to(Address) == sender
