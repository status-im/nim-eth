# Nimbus
# Copyright (c) 2023-2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  stew/byteutils,
  unittest2,
  ../../eth/common/[transactions_rlp, transaction_utils]

const
  recipient = address"095e7baea6a6c7c4c2dfeb977efac326af552d87"
  source    = address"0x0000000000000000000000000000000000000001"
  storageKey= default(Bytes32)
  accesses  = @[AccessPair(address: source, storageKeys: @[storageKey])]
  abcdef    = hexToSeqByte("abcdef")
  authList  = @[Authorization(
    chainID: chainId(1),
    address: source,
    nonce: 2.AccountNonce,
    yParity: 3,
    r: 4.u256,
    s: 5.u256
  )]

func tx0(i: int): Transaction =
  Transaction(
    txType:   TxLegacy,
    nonce:    i.AccountNonce,
    to:       Opt.some recipient,
    gasLimit: 1.GasInt,
    gasPrice: 2.GasInt,
    payload:  abcdef)

func tx1(i: int): Transaction =
  Transaction(
    # Legacy tx contract creation.
    txType:   TxLegacy,
    nonce:    i.AccountNonce,
    gasLimit: 1.GasInt,
    gasPrice: 2.GasInt,
    payload:  abcdef)

func tx2(i: int): Transaction =
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

func tx3(i: int): Transaction =
  Transaction(
    # Tx with empty access list.
    txType:   TxEip2930,
    chainId:  chainId(1),
    nonce:    i.AccountNonce,
    to:       Opt.some recipient,
    gasLimit: 123457.GasInt,
    gasPrice: 10.GasInt,
    payload:  abcdef)

func tx4(i: int): Transaction =
  Transaction(
    # Contract creation with access list.
    txType:     TxEip2930,
    chainId:    chainId(1),
    nonce:      i.AccountNonce,
    gasLimit:   123457.GasInt,
    gasPrice:   10.GasInt,
    accessList: accesses)

func tx5(i: int): Transaction =
  Transaction(
    txType:     TxEip1559,
    chainId:    chainId(1),
    nonce:      i.AccountNonce,
    gasLimit:   123457.GasInt,
    maxPriorityFeePerGas: 42.GasInt,
    maxFeePerGas: 10.GasInt,
    accessList: accesses)

func tx6(i: int): Transaction =
  const
    digest = hash32"010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"

  Transaction(
    txType:              TxEip4844,
    chainId:             chainId(1),
    nonce:               i.AccountNonce,
    to:                  Opt.some(recipient),
    gasLimit:            123457.GasInt,
    maxPriorityFeePerGas:42.GasInt,
    maxFeePerGas:        10.GasInt,
    accessList:          accesses,
    versionedHashes:     @[digest])

func tx7(i: int): Transaction =
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

func tx8(i: int): Transaction =
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

func txEip7702(i: int): Transaction =
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

type
  TxCase = object
    tx: Transaction
    toIdx, accessListIdx: int

  TxParts = object
    prefix: seq[byte] ## type byte of typed transactions
    fields: seq[seq[byte]] ## RLP encoded fields of the transaction list

const txCases = [
  TxCase(tx: tx0(1), toIdx: 3, accessListIdx: -1),
  TxCase(tx: tx2(1), toIdx: 4, accessListIdx: 7),
  TxCase(tx: tx5(1), toIdx: 5, accessListIdx: 8),
  TxCase(tx: tx8(1), toIdx: 5, accessListIdx: 8),
  TxCase(tx: txEip7702(1), toIdx: 5, accessListIdx: 8)]

proc parts(tx: Transaction): TxParts {.raises: [RlpError].} =
  let
    bytes = rlp.encode(tx)
    prefix = if tx.txType != TxLegacy: bytes[0 ..< 1] else: newSeq[byte]()
  var
    r = rlpFromBytes(bytes[prefix.len .. ^1])
    fields: seq[seq[byte]]
  for item in r:
    fields.add @(item.rawData)
  TxParts(prefix: prefix, fields: fields)

proc toBytes(
    p: TxParts, numInList = p.fields.len, extra: seq[byte] = @[]): seq[byte] =
  ## Fields past `numInList` are appended after the end of the list
  var w = initRlpList(numInList)
  for i in 0 ..< numInList:
    w.appendRawBytes(p.fields[i])
  var bytes = p.prefix & w.finish()
  for i in numInList ..< p.fields.len:
    bytes.add p.fields[i]
  bytes & extra

suite "Transaction decoding":
  test "Decode all transaction types":
    for c in txCases:
      checkpoint $c.tx.txType
      let decoded = rlp.decode(c.tx.parts.toBytes(), Transaction)
      check rlp.encode(decoded) == rlp.encode(c.tx)

  test "Missing fields":
    for c in txCases:
      checkpoint $c.tx.txType
      var p = c.tx.parts
      let fieldsAfterList = p.toBytes(numInList = c.toIdx)
      p.fields.setLen(c.toIdx)
      let endOfInput = p.toBytes()
      expect MalformedRlpError:
        discard rlp.decode(endOfInput, Transaction)
      expect MalformedRlpError:
        discard rlp.decode(fieldsAfterList, Transaction)

  test "Fields after the end of the list":
    for c in txCases:
      checkpoint $c.tx.txType
      let p = c.tx.parts
      expect MalformedRlpError:
        discard rlp.decode(p.toBytes(numInList = p.fields.len - 1), Transaction)

  test "Extra field":
    for c in txCases:
      checkpoint $c.tx.txType
      var p = c.tx.parts
      p.fields.add rlp.encode(1'u64)
      expect MalformedRlpError:
        discard rlp.decode(p.toBytes(), Transaction)

  test "Trailing bytes after typed transaction":
    for c in txCases[1 .. ^1]:
      checkpoint $c.tx.txType
      let bytes = c.tx.parts.toBytes(extra = @[byte 0x01])
      expect MalformedRlpError:
        discard rlp.decode(bytes, Transaction)
      var w = initRlpList(1)
      w.append(bytes)
      expect MalformedRlpError:
        discard rlp.decode(w.finish(), seq[Transaction])

  test "Recipient encoded as a list":
    for c in txCases:
      checkpoint $c.tx.txType
      var p = c.tx.parts
      p.fields[c.toIdx] = @[byte 0xc0]
      expect RlpTypeMismatch:
        discard rlp.decode(p.toBytes(), Transaction)

  test "Empty recipient":
    for c in txCases:
      checkpoint $c.tx.txType
      var p = c.tx.parts
      p.fields[c.toIdx] = @[byte 0x80]
      let bytes = p.toBytes()
      if c.tx.txType in {TxEip4844, TxEip7702}:
        expect RlpTypeMismatch:
          discard rlp.decode(bytes, Transaction)
      else:
        check rlp.decode(bytes, Transaction).to.isNone

  test "Integers with leading zeros":
    for c in txCases:
      checkpoint $c.tx.txType
      var p = c.tx.parts
      let nonceIdx = if c.tx.txType == TxLegacy: 0 else: 1
      for nonce in [@[byte 0x82, 0x00, 0x01], @[byte 0x00]]:
        p.fields[nonceIdx] = nonce
        expect MalformedRlpError:
          discard rlp.decode(p.toBytes(), Transaction)

  test "Access list entry with extra element":
    for c in txCases[1 .. ^1]:
      checkpoint $c.tx.txType
      var p = c.tx.parts
      var w = initRlpList(1)
      w.startList(3)
      w.append(source)
      w.append(@[storageKey])
      w.append(1'u64)
      p.fields[c.accessListIdx] = w.finish()
      expect MalformedRlpError:
        discard rlp.decode(p.toBytes(), Transaction)

  test "Access list entry with missing element":
    for c in txCases[1 .. ^1]:
      checkpoint $c.tx.txType
      var p = c.tx.parts
      var w = initRlpList(1)
      w.startList(1)
      w.append(source)
      p.fields[c.accessListIdx] = w.finish()
      expect RlpTypeMismatch:
        discard rlp.decode(p.toBytes(), Transaction)

  test "Authorization with extra element":
    var p = txEip7702(1).parts
    var w = initRlpList(1)
    w.startList(7)
    w.append(1'u64)
    w.append(source)
    w.append(2'u64)
    w.append(1'u64)
    w.append(4'u64)
    w.append(5'u64)
    w.append(6'u64)
    p.fields[9] = w.finish()
    expect MalformedRlpError:
      discard rlp.decode(p.toBytes(), Transaction)
