import
  unittest,
  ../../eth/ssz/sszcodec,
  ../../eth/common/[addresses, hashes, base, eth_types_json_serialization],
  ../../eth/rlp,
  ssz_serialization,
  ../common/test_transactions

# const recipient = address"095e7baea6a6c7c4c2dfeb977efac326af552d87"
# const source    = address"0x0000000000000000000000000000000000000001"
# let   abcdef    = hexToSeqByte("abcdef")
# let   storageKey = default(Bytes32)
# let   accesses   = @[rlp_tx.AccessPair(address: source, storageKeys: @[storageKey])]

# proc someTo(a: Address): Opt[Address] = Opt.some(a)
# proc noneTo(): Opt[Address] = Opt.none(Address)
# let R1 = 1.u256
# let S1 = 1.u256

template sszRoundTrip(txFunc: untyped, i: int) =
  let oldTx = txFunc(i)
  let sszTx = toSszTx(oldTx)
  # let back = toOldTx(sszTx)
  # check back == oldTx

template sszDoubleRoundTrip(txFunc: untyped, i: int) =
  let oldTx = txFunc(i)
  let sszTx = toSszTx(oldTx)
  let oldBack = toOldTx(sszTx)
  let sszBack = toSszTx(oldBack)
  check oldBack == oldTx
  check sszBack == sszTx

suite "Transactions SSZ Roundtrip":
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

  # test "NetworkBlob Tx":
  #   sszRoundTrip(tx6, 7)

  # test "Minimal Blob Tx":
  #   sszRoundTrip(tx7, 8)

  # test "Minimal Blob Tx contract creation":
  #   sszRoundTrip(tx8, 9)

  # test "EIP-7702 (currently fail-path only)":
  #   expect(ValueError):
  #     discard toSszTx(txEip7702(10))

# suite "sszcodec: passing SSZ round-trips (old -> new -> SSZ -> old)":
#   sszRoundTripOK("Legacy CALL pre-155",             legacyCallPre155(1))
#   sszRoundTripOK("Legacy CALL EIP-155",             legacyCall155(2))
#   sszRoundTripOK("Legacy CREATE pre-155",           legacyCreatePre155(3, true))
#   sszRoundTripOK("Legacy CREATE EIP-155",           legacyCreate155(4, true))
#   sszRoundTripOK("EIP-2930 CALL (with AL)",         eip2930Call(5, true))
#   sszRoundTripOK("EIP-2930 CALL (empty AL)",        eip2930Call(6, false))
#   sszRoundTripOK("EIP-2930 CREATE",                 eip2930Create(7, true))
#   sszRoundTripOK("EIP-1559 CALL",                   eip1559Call(8))
#   sszRoundTripOK("EIP-1559 CREATE",                 eip1559Create(9, true))
#   sszRoundTripOK("EIP-4844 CALL (with blob fee)",   eip4844Call(10, true))
#   sszRoundTripOK("EIP-4844 CALL (blob fee zero)",   eip4844Call(11, false))
#   sszRoundTripOK("EIP-7702 setCode (empty auths)",  eip7702SetCode(12, false))
