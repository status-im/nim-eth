import stint, results, ../common/[keys, hashes, addresses, base], ssz_serialization

const
  SECP256K1_SIGNATURE_SIZE* = 32 + 32 + 1
  SECP256K1N* =
    UInt256.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
  EIP155_CHAIN_ID_OFFSET* = 35'u64

type Secp256k1ExecutionSignature* = array[SECP256K1_SIGNATURE_SIZE, byte]

proc secp256k1Pack*(r, s: UInt256, yParity: uint8): Secp256k1ExecutionSignature =
  ## r||s||yParity (65B)
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
  ## EIP-2 low-s validation: 0<r<N, 0<s<=N/2, y in {0,1}
  let (r, s, y) = secp256k1Unpack(signature)
  let zero = 0.u256
  let halfN = SECP256K1N div 2.u256
  (r > zero) and (r < SECP256K1N) and (s > zero) and (s <= halfN) and
    (y == 0'u8 or y == 1'u8)

proc secp256k1RecoverSigner*(
    signature: Secp256k1ExecutionSignature, sigHash: Hash32
): Address =
  ## Recover address from 65B signature over a 32B hash
  let sig = Signature.fromRaw(signature).valueOr:
    raise newException(ValueError, "invalid signature")
  let pk = recover(sig, SkMessage(sigHash.data)).valueOr:
    raise newException(ValueError, "recovery failed")
  pk.to(Address)

proc yParityFromLegacyV*(V: uint64, isEip155: bool): uint8 =
  ## Legacy: pre-155 => V in {27,28}; EIP-155 => V=2*chainId+35/36
  if isEip155:
    uint8((V - EIP155_CHAIN_ID_OFFSET) and 1)
  else:
    uint8((V - 27'u64) and 1)

proc legacyVFromParity*(yParity: uint8, chainId: SomeInteger, isEip155: bool): uint64 =
  ## Build a legacy V from yParity and (optional) chainId.
  if isEip155:
    EIP155_CHAIN_ID_OFFSET + (2 * uint64(chainId)) + uint64(yParity)
  else:
    27'u64 + uint64(yParity)

# ------------------------------------------------------------------------------
# SSZ-native (EIP-6493-style)
# ------------------------------------------------------------------------------

# type
#   DomainType* = array[4, byte]
#   ExecutionSigningData* = object
#     object_root*: Hash32
#     domain_type*: DomainType

# proc sszObjectRoot*(payload: auto): Hash32 =
#   hash_tree_root(payload)

# proc sszSigningRoot*(payload: auto; domain: DomainType): Hash32 =
#   hash_tree_root(ExecutionSigningData(object_root: sszObjectRoot(payload),
#                                       domain_type: domain))

# proc signSsz6493*(seckey: PrivateKey, payload: auto; domain: DomainType): Secp256k1ExecutionSignature =
#   let h = sszSigningRoot(payload, domain)
#   let sig = sign(seckey, SkMessage(h.data)).valueOr:
#     raise newException(ValueError, "signing failed")
#   let raw = sig.toRaw()
#   if not secp256k1Validate(raw):
#     raise newException(ValueError, "non-canonical secp256k1 signature")
#   raw

# proc recoverSsz6493Signer*(signature: Secp256k1ExecutionSignature, payload: auto;
#                            domain: DomainType): Address =
#   let h = sszSigningRoot(payload, domain)
#   let sigObj = Signature.fromRaw(signature).valueOr:
#     raise newException(ValueError, "invalid signature")
#   let pk = recover(sigObj, SkMessage(h.data)).valueOr:
#     raise newException(ValueError, "recovery failed")
#   pk.to(Address)

# proc verifySsz6493*(signature: Secp256k1ExecutionSignature, payload: auto,
#                     expected: Address; domain: DomainType): bool =
#   recoverSsz6493Signer(signature, payload, domain) == expected

# # SSZ-native id/root helper (no keccak)
# proc sszTxRoot*(tx: auto): Hash32 =
#   hash_tree_root(tx)
