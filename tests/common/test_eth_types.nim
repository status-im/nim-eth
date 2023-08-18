{.used.}

import
  unittest2,
  nimcrypto/hash,
  serialization/testing/generic_suite,
  ../../eth/common/[eth_types, eth_types_json_serialization],
  ../../eth/common/eth_types_rlp,
  ../../eth/rlp

func `==`*(lhs, rhs: BlockHashOrNumber): bool =
  if lhs.isHash != rhs.isHash:
    return false

  if lhs.isHash:
    lhs.hash == rhs.hash
  else:
    lhs.number == rhs.number

const
  testHash = Hash256.fromHex "0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c588"

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
    let hash = Hash256.fromHex "0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c588"

    Json.roundtripTest BlockHashOrNumber(isHash: true, hash: hash),
                       "\"0x7a64245f7f95164f6176d90bd4903dbdd3e5433d555dd1385e81787f9672c588\""

    Json.roundtripTest BlockHashOrNumber(isHash: false, number: 1209231231),
                       "\"1209231231\""

  test "EIP-4399 prevRandao field":
    var blk: BlockHeader
    blk.prevRandao = testHash
    let res = blk.prevRandao
    check testHash == res

  test "EIP-4788 parentBeaconBlockRoot field":
    let header = BlockHeader(
      fee: some(0.u256),
      withdrawalsRoot: some(testHash),
      blobGasUsed: some(1'u64),
      excessBlobGas: some(2'u64),
      parentBeaconBlockRoot: some(testHash),
    )
    let rlpBytes = rlp.encode(header)
    let dh = rlp.decode(rlpBytes, BlockHeader)
    check dh.parentBeaconBlockRoot.isSome
    check dh.parentBeaconBlockRoot.get == testHash
