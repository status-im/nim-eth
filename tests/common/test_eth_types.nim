{.used.}

import
  unittest2,
  std/strutils,
  serialization/testing/generic_suite,
  ../../eth/common/[eth_types, eth_types_json_serialization],
  ../../eth/common/eth_types_rlp

func `==`*(lhs, rhs: BlockHashOrNumber): bool =
  if lhs.isHash != rhs.isHash:
    return false

  if lhs.isHash:
    lhs.hash == rhs.hash
  else:
    lhs.number == rhs.number

const testHash =
  hash32"0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c588"

suite "BlockHashOrNumber":
  test "construction":
    expect ValueError:
      var x = BlockHashOrNumber.init ""
      echo "An empty string should not produce the value ", x

    let x1 = BlockHashOrNumber.init "0"
    check((not x1.isHash) and x1.number == 0)

    let x2 = BlockHashOrNumber.init "1241328"
    check((not x1.isHash) and x2.number == 1241328)

    expect ValueError:
      var x = BlockHashOrNumber.init "0x"
      echo "An empty hash should not produce the value ", x

    expect ValueError:
      var x = BlockHashOrNumber.init "0xff11"
      echo "A shorter hash should not produce the value ", x

    expect ValueError:
      var x = BlockHashOrNumber.init "0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c58z"
      echo "An invalid hash should not produce the value ", x

    expect ValueError:
      var x = BlockHashOrNumber.init "0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c58811"
      echo "A longer hash should not produce the value ", x

  test "serialization":
    const hash =
      hash32"0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c588"

    Json.roundtripTest BlockHashOrNumber(isHash: true, hash: hash),
      "\"0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c588\""

    Json.roundtripTest BlockHashOrNumber(isHash: false, number: 1209231231),
      "\"1209231231\""

suite "Block encodings":
  test "EIP-4399 prevRandao field":
    var blk: Header
    blk.prevRandao = Bytes32 testHash
    let res = blk.prevRandao
    check Bytes32(testHash) == res

  test "EIP-4788 parentBeaconBlockRoot field":
    let header = Header(
      baseFeePerGas: Opt.some(0.u256),
      withdrawalsRoot: Opt.some(testHash),
      blobGasUsed: Opt.some(1'u64),
      excessBlobGas: Opt.some(2'u64),
      parentBeaconBlockRoot: Opt.some(testHash),
    )
    let rlpBytes = rlp.encode(header)
    let dh = rlp.decode(rlpBytes, Header)
    check dh.parentBeaconBlockRoot.isSome
    check dh.parentBeaconBlockRoot.get == testHash

suite "Address":
  test "Bytes conversion":
    let bytes =
      bytes32"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    check:
      bytes.to(Address) == address"ccddeeff00112233445566778899aabbccddeeff"
      bytes.to(Address).to(Bytes32) ==
        bytes32"000000000000000000000000ccddeeff00112233445566778899aabbccddeeff"

  test "EIP-55 checksum":
    let
      cases = [
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
      ]
      fails = cases[4 .. 7]

    # https://eips.ethereum.org/EIPS/eip-55#test-cases
    for s in cases:
      check:
        Address.fromHex(s).toChecksum0xHex() == s
        Address.hasValidChecksum(s)
    for s in fails:
      check:
        not Address.hasValidChecksum(s.toLowerAscii)

suite "Bytes":
  test "copyFrom":
    check:
      Bytes4.copyFrom([]) == default(Bytes4)
      Bytes4.copyFrom([byte 0]) == default(Bytes4)
      Bytes4.copyFrom([byte 0, 0, 0, 0, 0]) == default(Bytes4)
      Bytes4.copyFrom([byte 1, 0], 1) == default(Bytes4)
      Bytes4.copyFrom([byte 1, 1], 2) == default(Bytes4)
      Bytes4.copyFrom([byte 1, 1], 20) == default(Bytes4)

  test "toHex":
    check:
      bytes4"0xaabbccdd".toHex == "aabbccdd"
      bytes4"0xaabbccdd".to0xHex == "0xaabbccdd"

suite "Hashes":
  test "constants":
    check:
      emptyKeccak256 == keccak256(default(array[0, byte]))
      emptyRoot == keccak256([byte 128])
