import 
  stint, 
  results,
  ../common/[keys, hashes, addresses], 
  ssz_serialization

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

# Bytes to sign: SSZ.encode(payload-without-signature)
proc sszPreimage*(payload: auto): seq[byte] =
  SSZ.encode(payload)

# sig_hash = keccak256(SSZ.encode(payload))
proc computeSszKeccakSigHash*(payload: auto): Hash32 =
  keccak256(SSZ.encode(payload))
  
# Sign over the 32-byte keccak(sig_preimage)
proc signSszKeccak*(seckey: PrivateKey, payload: auto): Secp256k1ExecutionSignature =
  let h = computeSszKeccakSigHash(payload)
  let sig = sign(seckey, SkMessage(h.data))   # IMPORTANT: no extra keccak
  sig.toRaw() 

proc recoverSszKeccakSigner*(signature: Secp256k1ExecutionSignature, payload: auto): Address =
  let h = computeSszKeccakSigHash(payload)
  let sigObj = Signature.fromRaw(signature).valueOr:
    raise newException(ValueError, "invalid signature")
  let pk = recover(sigObj, SkMessage(h.data)).valueOr:
    raise newException(ValueError, "recovery failed")
  pk.to(Address)

# Verify against expected address
proc verifySszKeccak*(signature: Secp256k1ExecutionSignature,payload: auto,expected: Address): bool =
  recoverSszKeccakSigner(signature, payload) == expected

# tx_hash = keccak256(SSZ.encode(full_tx_with_signature))
proc computeSszKeccakTxHash*(tx: auto): Hash32 =
  keccak256(SSZ.encode(tx))

# convenience
proc sszSerialize*(x: auto): seq[byte] =
  SSZ.encode(x)

# --- SSZ-bytes signing (keccak over SSZ.encode(payload)) --------------------
# NOTE: payload must NOT contain a signature field.

# proc signSszKeccak*(seckey: PrivateKey, payload: auto): Secp256k1ExecutionSignature =
#   ## Produce r||s||yParity (65B). Uses SkMessage so we don't double-keccak.
#   let h = computeSszKeccakSigHash(payload)
#   let sig = sign(seckey, SkMessage(h.data))
#   let raw = sig.toRaw()
#   doAssert secp256k1Validate(raw)          # TODO: return error instead of assert in prod
#   raw

# proc signAndAssembleSszKeccak*[P](seckey: PrivateKey, payload: P): SignedTx[P] =
#   ## One-shot: sign payload and return SignedTx[P].
#   result.payload = payload
#   result.signature = signSszKeccak(seckey, payload)

# proc recoverSszKeccakSigner*(signature: Secp256k1ExecutionSignature, payload: auto): Address =
#   let h = computeSszKeccakSigHash(payload)
#   let sigObj = Signature.fromRaw(signature).valueOr:
#     raise newException(ValueError, "invalid signature")
#   let pk = recover(sigObj, SkMessage(h.data)).valueOr:
#     raise newException(ValueError, "recovery failed")
#   pk.to(Address)


# proc computeSszKeccakTxHash*(tx: SignedTx): Hash32 =
#   ## "tx id" in this transitional scheme: keccak(SSZ.encode(tx_with_signature))
#   keccak256(SSZ.encode(tx))

# Maybe also add the 6493 changes here
# maybe we can also
# 
# # --- SSZ signing (EIP-6493 style): sign the SSZ signing-root, not keccak ----
# Then sign signing_root with secp256k1 (SkMessage) and return 65B r||s||y.
# Tx identifier/root for native SSZ = hash_tree_root(full SSZ Transaction).
# type
#   DomainType* = array[4, byte]               # 4-byte domain per 6493
#   ExecutionSigningData* = object              # SSZ container
#     object_root*: Hash32                      # hash_tree_root(payload)
#     domain_type*: DomainType                  # domain separation

# # TODO: set this from config/spec (DON'T hard-code until confirmed).
# # Example often used for execution tx is 0x00_00_00_80, but leave as TODO.
# const DOMAIN_TX_SSZ*: DomainType = [byte 0x00, 0x00, 0x00, 0x00]  # TODO

# proc sszObjectRoot*(payload: auto): Hash32 =
#   ## SSZ Merkle root of the payload (object root).
#   hash_tree_root(payload)

# proc sszSigningRoot*(payload: auto; domain: DomainType = DOMAIN_TX_SSZ): Hash32 =
#   ## EIP-6493 signing root = HTR(ExecutionSigningData{object_root, domain}).
#   let ed = ExecutionSigningData(object_root: hash_tree_root(payload),
#                                 domain_type: domain)
#   hash_tree_root(ed)

# proc signSsz6493*(seckey: PrivateKey, payload: auto;
#                   domain: DomainType = DOMAIN_TX_SSZ): Secp256k1ExecutionSignature =
#   ## Sign the SSZ signing root. IMPORTANT: use SkMessage (no keccak here).
#   let h = sszSigningRoot(payload, domain)
#   let sigObj = sign(seckey, SkMessage(h.data))
#   let raw = sigObj.toRaw()                         # 65B r||s||y
#   doAssert secp256k1Validate(raw)                  # TODO: return Result in prod
#   raw

# proc recoverSsz6493Signer*(signature: Secp256k1ExecutionSignature, payload: auto;
#                            domain: DomainType = DOMAIN_TX_SSZ): Address =
#   ## Recover sender from payload + signature under the given domain.
#   let h = sszSigningRoot(payload, domain)
#   let sigObj = Signature.fromRaw(signature).valueOr:
#     raise newException(ValueError, "invalid signature")
#   let pk = recover(sigObj, SkMessage(h.data)).valueOr:
#     raise newException(ValueError, "recovery failed")
#   pk.to(Address)

# proc verifySsz6493*(signature: Secp256k1ExecutionSignature, payload: auto,
#                     expected: Address; domain: DomainType = DOMAIN_TX_SSZ): bool =
#   recoverSsz6493Signer(signature, payload, domain) == expected

# proc sszTxRoot*(tx: auto): Hash32 =
#   ## Native SSZ transaction identifier/root.
#   hash_tree_root(tx)

# proc sszSerialize*(x: auto): seq[byte] =
#   ## Wire/storage bytes for Engine API (ssz.serialize(x)).
#   SSZ.encode(x)
