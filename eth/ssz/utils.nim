import stint, results, ../common/[keys, hashes, addresses], ssz_serialization

const
  SECP256K1_SIGNATURE_SIZE* = 32 + 32 + 1
  SECP256K1N* =
    UInt256.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

type Secp256k1ExecutionSignature* = array[SECP256K1_SIGNATURE_SIZE, byte]

#TODO: add libsecp256k1 fn where necessary
proc secp256k1Pack*(r, s: UInt256, yParity: uint8): Secp256k1ExecutionSignature =
  var sig: Secp256k1ExecutionSignature
  sig[0 .. 31] = r.toBytesBE()
  sig[32 .. 63] = s.toBytesBE()
  sig[64] = yParity
  sig

proc secp256k1Unpack*(
    signature: Secp256k1ExecutionSignature
): (UInt256, UInt256, uint8) =
  (
    UInt256.fromBytesBE(signature.toOpenArray(0, 31)),
    UInt256.fromBytesBE(signature.toOpenArray(32, 63)),
    signature[64],
  )

proc secp256k1Validate*(signature: Secp256k1ExecutionSignature): bool =
  let (r, s, yParity) = secp256k1Unpack(signature)
  let zero = UInt256.fromDecimal("0")
  let two = UInt256.fromDecimal("2")

  doAssert (r > zero) and (r < SECP256K1N)
  doAssert (s > zero) and (s <= SECP256K1N div two)
  doAssert (yParity == 0) or (yParity == 1)
  true

proc secp256k1RecoverSigner*(
    signature: Secp256k1ExecutionSignature, sigHash: Hash32
): Address =
  let sig = Signature.fromRaw(signature).valueOr:
    raise newException(ValueError, "invalid signature")
  let pk = recover(sig, SkMessage(sigHash.data)).valueOr:
    raise newException(ValueError, "recovery failed")
  pk.to(Address)
