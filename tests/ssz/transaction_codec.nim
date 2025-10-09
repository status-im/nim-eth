import
  unittest,
  stew/byteutils,
  std/sequtils,
  ../../eth/ssz/[sszcodec,transaction_ssz, transaction_builder, signatures, adapter],
  ../../eth/common/[addresses, hashes, base, eth_types_json_serialization, transactions],
  ../../eth/rlp,
  ssz_serialization,
  ../common/test_transactions


const
  recipient = address"095e7baea6a6c7c4c2dfeb977efac326af552d87"
  zeroG1    = bytes48"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  source    = address"0x0000000000000000000000000000000000000001"
  storageKey= default(Bytes32)
  accesses  = @[AccessPair(address: source, storageKeys: @[storageKey])]
  abcdef    = hexToSeqByte("abcdef")

template sszRoundTrip(txFunc: untyped, i: int) =
  let oldTx = txFunc(i)
  let sszTx = toSszTx(oldTx)
  check sszTx.kind == RlpTransaction
  let rlptxn = toOldTx(sszTx)

template sszFullRoundTrip(txFunc: untyped, i: int) =
  ## RLP -> SSZ -> RLP
  let oldTx = txFunc(i)
  let sszTx = toSszTx(oldTx)
  let back = toOldTx(sszTx)
  check back == oldTx

template sszDoubleRoundTrip(txFunc: untyped, i: int) =
  let oldTx = txFunc(i)
  let sszTx = toSszTx(oldTx)
  let oldBack = toOldTx(sszTx)
  let sszBack = toSszTx(oldBack)
  # Work around Nim case object comparison limitation https://github.com/nim-lang/Nim/issues/6676
  check oldBack.txType == oldTx.txType
  check oldBack.chainId == oldTx.chainId
  check oldBack.nonce == oldTx.nonce
  check oldBack.gasLimit == oldTx.gasLimit
  check oldBack.to == oldTx.to
  check oldBack.value == oldTx.value
  check oldBack.payload == oldTx.payload
  check sszBack.kind == sszTx.kind
  check SSZ.encode(sszBack) == SSZ.encode(sszTx)

suite "SSZ Transactions (full round-trip)":
  test "Legacy Tx Call":
    sszRoundTrip(tx0, 1)
  test "Legacy tx contract creation":
    sszRoundTrip(tx1, 2)

  test "Tx with non-zero access list":
    sszRoundTrip(tx2, 3)

  test "Tx with empty access list":
    sszRoundTrip(tx3, 4)

  test "Contract creation with access list":
    sszRoundTrip(tx4, 5)

  test "Dynamic Fee Tx":
    sszRoundTrip(tx5, 6)

# Will never work as blob Txns must have a To
  # test "NetworkBlob Tx":
  #   sszRoundTrip(tx6, 7)

  # test "Minimal Blob Tx":
  #   sszRoundTrip(tx7, 8)

# Will never work as blob Txns must have a To
  test "Minimal Blob Tx contract creation":
    sszRoundTrip(tx8, 9)


suite "Transactions SSZ Codec: 7702 SetCode (RLP ↔ SSZ)":
  test "7702 with auth: RLP -> SSZ":
    let oldTx = txEip7702(1)
    let sszTx = toSszTx(oldTx)

    check sszTx.kind == RlpTransaction
    check sszTx.rlp.kind == txSetCode

    # Verify authorization list was converted
    let authList = sszTx.rlp.setCode.payload.authorization_list
    check authList.len == 1
    check authList[0].payload.kind == authBasic
    check authList[0].payload.basic.chain_id == ChainId(1.u256)
    check authList[0].payload.basic.address == source
    check authList[0].payload.basic.nonce == 2

  test "7702 with auth: RLP -> SSZ -> RLP (Full Roundtrip)":
    let oldTx = txEip7702(1)
    let sszTx = toSszTx(oldTx)
    let backTx = toOldTx(sszTx)

    # Verify all fields match
    check backTx.txType == oldTx.txType
    check backTx.chainId == oldTx.chainId
    check backTx.nonce == oldTx.nonce
    check backTx.maxPriorityFeePerGas == oldTx.maxPriorityFeePerGas
    check backTx.maxFeePerGas == oldTx.maxFeePerGas
    check backTx.gasLimit == oldTx.gasLimit
    check backTx.to == oldTx.to
    check backTx.value == oldTx.value
    check backTx.payload == oldTx.payload
    check backTx.accessList == oldTx.accessList

    check backTx.authorizationList.len == oldTx.authorizationList.len
    check backTx.authorizationList.len == 1

    let origAuth = oldTx.authorizationList[0]
    let backAuth = backTx.authorizationList[0]
    check backAuth.chainId == origAuth.chainId
    check backAuth.address == origAuth.address
    check backAuth.nonce == origAuth.nonce
    check backAuth.yParity == origAuth.yParity
    check backAuth.r == origAuth.r
    check backAuth.s == origAuth.s

  test "7702 with auth: Double Roundtrip (RLP -> SSZ -> RLP -> SSZ)":
    sszDoubleRoundTrip(txEip7702, 1)

  test "7702 authorization data integrity":
    let oldTx = txEip7702(5)
    let sszTx = toSszTx(oldTx)
    let backTx = toOldTx(sszTx)

    check backTx == oldTx

    for i, auth in oldTx.authorizationList:
      check backTx.authorizationList[i].chainId == auth.chainId
      check backTx.authorizationList[i].address == auth.address
      check backTx.authorizationList[i].nonce == auth.nonce
      check backTx.authorizationList[i].yParity == auth.yParity
      check backTx.authorizationList[i].r == auth.r
      check backTx.authorizationList[i].s == auth.s

  test "7702 with replayable auth (chainId = 0)":
    var tx = txEip7702(1)
    tx.authorizationList[0].chainId = ChainId(0.u256)

    let sszTx = toSszTx(tx)
    check sszTx.rlp.setCode.payload.authorization_list.len == 1
    check sszTx.rlp.setCode.payload.authorization_list[0].payload.kind == authReplayableBasic
    let backTx = toOldTx(sszTx)
    check backTx.authorizationList[0].chainId == ChainId(0.u256)
    check backTx == tx

  test "7702 with mixed authorization types":
    var tx = txEip7702(1)

    tx.authorizationList.add transactions.Authorization(
        chainId: ChainId(0.u256),
        address: recipient,
        nonce: 5.AccountNonce,
        yParity: 1,
        r: 999.u256,
        s: 888.u256
      )

    let sszTx = toSszTx(tx)
    let authList = sszTx.rlp.setCode.payload.authorization_list

    check authList.len == 2
    check authList[0].payload.kind == authBasic
    check authList[1].payload.kind == authReplayableBasic

    let backTx = toOldTx(sszTx)
    check backTx.authorizationList.len == 2
    check backTx.authorizationList[0].chainId == ChainId(1.u256)
    check backTx.authorizationList[1].chainId == ChainId(0.u256)
    check backTx == tx

  test "7702 with multiple authorizations (5 entries)":
    var tx = txEip7702(1)
    for i in 1..4:
      tx.authorizationList.add transactions.Authorization(
            chainId: ChainId(u256(i)),
            address: Address.copyFrom(newSeqWith(20, byte(i))),
            nonce: AccountNonce(i * 10),
            yParity: uint8(i mod 2),
            r: u256(100 + i),
            s: u256(200 + i)
          )

    let sszTx = toSszTx(tx)
    check sszTx.rlp.setCode.payload.authorization_list.len == 5

    let backTx = toOldTx(sszTx)
    check backTx.authorizationList.len == 5
    check backTx == tx

    for i in 0..4:
      check backTx.authorizationList[i] == tx.authorizationList[i]



  test "7702 authorization with zero address":
    var tx = txEip7702(1)
    tx.authorizationList[0].address = zeroAddress

    let sszTx = toSszTx(tx)
    let backTx = toOldTx(sszTx)

    check backTx.authorizationList[0].address == zeroAddress
    check backTx == tx

  test "7702 authorization signature values":
    ## Test that signature r, s, yParity values are preserved
    var tx = txEip7702(1)
    tx.authorizationList[0].r = u256"12345678901234567890123456789012345678901234567890"
    tx.authorizationList[0].s = u256"98765432109876543210987654321098765432109876543210"
    tx.authorizationList[0].yParity = 1

    let sszTx = toSszTx(tx)
    let backTx = toOldTx(sszTx)

    check backTx.authorizationList[0].r == tx.authorizationList[0].r
    check backTx.authorizationList[0].s == tx.authorizationList[0].s
    check backTx.authorizationList[0].yParity == 1
    check backTx == tx

  test "7702 with access list and authorization list":
    var tx = txEip7702(1)

    let sszTx = toSszTx(tx)
    let backTx = toOldTx(sszTx)

    check backTx.accessList.len == tx.accessList.len
    check backTx.authorizationList.len == tx.authorizationList.len
    check backTx == tx


suite "Transactions SSZ Codec: Double Roundtrip":
  test "Legacy Call: double roundtrip":
    sszDoubleRoundTrip(tx0, 1)

  test "Legacy Create: double roundtrip":
    sszDoubleRoundTrip(tx1, 2)

  test "AccessList Call: double roundtrip":
    sszDoubleRoundTrip(tx2, 3)

  test "AccessList Create: double roundtrip":
    sszDoubleRoundTrip(tx4, 5)

  test "DynamicFee: double roundtrip":
    sszDoubleRoundTrip(tx5, 6)

  test "Blob Tx: double roundtrip":
    sszDoubleRoundTrip(tx8, 9)

  test "7702 SetCode: double roundtrip":
    sszDoubleRoundTrip(txEip7702, 1)


suite "Transactions SSZ Codec: Mixed Transaction Lists":
  test "Mixed list including 7702":
    let txs = @[
      tx0(1),      # Legacy
      tx2(2),      # AccessList
      tx5(3),      # DynamicFee
      tx8(4),      # Blob
      txEip7702(5) # 7702 SetCode
    ]

    var sszTxs: seq[typeof(toSszTx(txs[0]))] = @[]
    for tx in txs:
      sszTxs.add toSszTx(tx)

    check sszTxs.len == 5


    var backTxs: seq[transactions.Transaction] = @[]
    for sszTx in sszTxs:
      backTxs.add toOldTx(sszTx)

    check backTxs.len == 5

    for i in 0..<txs.len:
      check backTxs[i].txType == txs[i].txType
      check backTxs[i].nonce == txs[i].nonce

    check backTxs[4].authorizationList.len == txs[4].authorizationList.len
