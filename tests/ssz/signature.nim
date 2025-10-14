import unittest2, stew/byteutils, stint, ../../eth/ssz/[signatures]

suite "secp256k1 execution signatures":
  test "pack/unpack roundtrip":
    let r = UInt256.fromHex(
      "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"
    )
    let s = (SECP256K1N div 2'u256) # low-s boundary (valid)
    let y: uint8 = 1
    let sig = secp256k1Pack(r, s, y)
    let (rr, ss, yy) = secp256k1Unpack(sig)
    check rr == r
    check ss == s
    check yy == y
    check secp256k1Validate(sig)

  test "validate rejects high-s and bad parity":
    let r = 1.u256
    let sHigh = (SECP256K1N div 2'u256) + 1'u256
    let sigHigh = secp256k1Pack(r, sHigh, 0)
    check not secp256k1Validate(sigHigh)

    let sigBadParity = secp256k1Pack(r, (SECP256K1N div 2'u256), 2'u8)
    check not secp256k1Validate(sigBadParity)

  test "legacy V <-> yParity roundtrip (pre-155)":
    let y0: uint8 = 0
    let y1: uint8 = 1
    let v0 = legacyVFromParity(y0, 0'u64, false)
    let v1 = legacyVFromParity(y1, 0'u64, false)
    check yParityFromLegacyV(v0, false) == y0
    check yParityFromLegacyV(v1, false) == y1
    check v0 in {27'u64, 28'u64}
    check v1 in {27'u64, 28'u64}

  test "legacy V <-> yParity roundtrip (EIP-155)":
    let chainId = 1'u64
    for y in [0'u8, 1'u8]:
      let v = legacyVFromParity(y, chainId, true)
      check yParityFromLegacyV(v, true) == y
      check v == 35'u64 + (2 * chainId) + uint64(y) or
        v == 36'u64 + (2 * chainId) + uint64(y)

test "keccak32 sign & recover":
  when compiles(PrivateKey.fromHex):
    let sk = PrivateKey.fromHex(
      "0x46c5d3e7b0f4d01caa9c2025a3d49b9d2a8d3e4edb2f7a1b6c3e2d1f0a9b8c7d"
    ).valueOr:
      raise newException(ValueError, "could not parse test seckey")
    let msg = "deadbeefcafebabe".toBytes
    let h = keccak256(msg)

    let sig = signKeccak32(sk, h)
    check secp256k1Validate(sig)

    let recAddr = secp256k1RecoverSigner(sig, h)

    when compiles(sk.toPublicKey):
      let pk = sk.toPublicKey()
      when compiles(pk.to(Address)):
        let expected = pk.to(Address)
        check recAddr == expected
      else:
        let rec2 = secp256k1RecoverSigner(sig, h)
        check rec2 == recAddr
    else:
      let rec2 = secp256k1RecoverSigner(sig, h)
      check rec2 == recAddr
  else:
    skip()

  test "signKeccak32 r/s not zero and y in {0,1}":
    when compiles(PrivateKey.fromHex):
      let sk = PrivateKey.fromHex("0x1".repeat(32)).valueOr:
        raise newException(ValueError, "could not parse test seckey")
      let h = keccak256("hello".toBytes)
      let sig = signKeccak32(sk, h)
      let (r, s, y) = secp256k1Unpack(sig)
      check r != 0.u256
      check s != 0.u256
      check y == 0'u8 or y == 1'u8
    else:
      skip()
