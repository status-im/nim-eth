# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# This module contains adaptations of the general secp interface to help make
# working with keys and signatures as they appear in Ethereum in particular:
#
# * Public keys as serialized in uncompressed format without the initial byte
# * Shared secrets are serialized in raw format without the initial byte
# * distinct types are used to avoid confusion with the "standard" secp types

import
  std/strformat,
  secp256k1, bearssl/rand,
  stew/[byteutils, objects, ptrops],
  results,
  "."/[hashes, addresses]

from nimcrypto/utils import burnMem

export secp256k1, results, rand

const
  KeyLength* = SkEcdhSecretSize
    ## Ecdh shared secret key length without leading byte
    ## (publicKey * privateKey).x, where length of x is 32 bytes

  FullKeyLength* = KeyLength + 1
    ## Ecdh shared secret with leading byte 0x02 or 0x03

  RawPublicKeySize* = SkRawPublicKeySize - 1
    ## Size of uncompressed public key without format marker (0x04)

  RawSignatureSize* = SkRawRecoverableSignatureSize

  RawSignatureNRSize* = SkRawSignatureSize

type
  PrivateKey* = distinct SkSecretKey

  PublicKey* = distinct SkPublicKey
    ## Public key that's serialized to raw format without 0x04 marker
  Signature* = distinct SkRecoverableSignature
    ## Ethereum uses recoverable signatures allowing some space savings
  SignatureNR* = distinct SkSignature
    ## ...but ENR uses non-recoverable signatures!

  SharedSecretFull* = object
    ## Representation of ECDH shared secret, with leading `y` byte
    ## (`y` is 0x02 when (publicKey * privateKey).y is even or 0x03 when odd)
    data*: array[FullKeyLength, byte]

  SharedSecret* = object
    ## Representation of ECDH shared secret, without leading `y` byte
    data*: array[KeyLength, byte]

  KeyPair* = distinct SkKeyPair

template pubkey*(v: KeyPair): PublicKey = PublicKey(SkKeyPair(v).pubkey)
template seckey*(v: KeyPair): PrivateKey = PrivateKey(SkKeyPair(v).seckey)

proc newRng*(): ref HmacDrbgContext =
  # You should only create one instance of the RNG per application / library
  # Ref is used so that it can be shared between components
  HmacDrbgContext.new()

proc random*(T: type PrivateKey, rng: var HmacDrbgContext): T =
  let rngPtr = unsafeAddr rng # doesn't escape
  proc callRng(data: var openArray[byte]) =
    generate(rngPtr[], data)

  T(SkSecretKey.random(callRng))

func fromRaw*(T: type PrivateKey, data: openArray[byte]): SkResult[T] =
  SkSecretKey.fromRaw(data).mapConvert(T)

func fromHex*(T: type PrivateKey, data: string): SkResult[T] =
  SkSecretKey.fromHex(data).mapConvert(T)

func toRaw*(seckey: PrivateKey): array[SkRawSecretKeySize, byte] =
  SkSecretKey(seckey).toRaw()

func toPublicKey*(seckey: PrivateKey): PublicKey {.borrow.}

func fromRaw*(T: type PublicKey, data: openArray[byte]): SkResult[T] =
  if data.len() == SkRawCompressedPublicKeySize:
    return SkPublicKey.fromRaw(data).mapConvert(T)

  if len(data) < SkRawPublicKeySize - 1:
    return err(static(
      &"keys: raw eth public key should be {SkRawPublicKeySize - 1} bytes"))

  var d: array[SkRawPublicKeySize, byte]
  d[0] = 0x04'u8
  copyMem(addr d[1], unsafeAddr data[0], 64)

  SkPublicKey.fromRaw(d).mapConvert(T)

func fromHex*(T: type PublicKey, data: string): SkResult[T] =
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(pubkey: PublicKey): array[RawPublicKeySize, byte] =
  let tmp = SkPublicKey(pubkey).toRaw()
  copyMem(addr result[0], unsafeAddr tmp[1], 64)

func toRawCompressed*(pubkey: PublicKey): array[33, byte] {.borrow.}

proc random*(T: type KeyPair, rng: var HmacDrbgContext): T =
  let seckey = SkSecretKey(PrivateKey.random(rng))
  KeyPair(SkKeyPair(
    seckey: seckey,
    pubkey: seckey.toPublicKey()
  ))

func toKeyPair*(seckey: PrivateKey): KeyPair =
  KeyPair(SkKeyPair(
    seckey: SkSecretKey(seckey), pubkey: SkSecretKey(seckey).toPublicKey()))

func fromRaw*(T: type Signature, data: openArray[byte]): SkResult[T] =
  SkRecoverableSignature.fromRaw(data).mapConvert(T)

func fromHex*(T: type Signature, data: string): SkResult[T] =
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(sig: Signature): array[RawSignatureSize, byte] {.borrow.}

func fromRaw*(T: type SignatureNR, data: openArray[byte]): SkResult[T] =
  SkSignature.fromRaw(data).mapConvert(T)

func toRaw*(sig: SignatureNR): array[RawSignatureNRSize, byte] {.borrow.}

func to*(pubkey: PublicKey, _: type Address): Address =
  ## Convert public key to canonical address.
  let hash = keccak256(pubkey.toRaw())
  hash.to(Address)

func toAddress*(pubkey: PublicKey): string {.deprecated.} =
  ## Convert public key to hexadecimal string address.
  pubkey.to(Address).to0xHex()

func toChecksumAddress*(pubkey: PublicKey): string =
  ## Convert public key to checksumable mixed-case address (EIP-55).
  pubkey.to(Address).toChecksum0xHex()

func validateChecksumAddress*(a: string): bool =
  ## Validate checksumable mixed-case address (EIP-55).
  Address.hasValidChecksum(a)

template toCanonicalAddress*(pubkey: PublicKey): Address =
  ## Convert public key to canonical address.
  pubkey.to(Address)

func `$`*(pubkey: PublicKey): string =
  ## Convert public key to hexadecimal string representation.
  toHex(pubkey.toRaw())

func `$`*(sig: Signature): string =
  ## Convert signature to hexadecimal string representation.
  toHex(sig.toRaw())

func `$`*(seckey: PrivateKey): string =
  ## Convert private key to hexadecimal string representation
  toHex(seckey.toRaw())

func `==`*(lhs, rhs: PublicKey): bool {.borrow.}
func `==`*(lhs, rhs: Signature): bool {.borrow.}
func `==`*(lhs, rhs: SignatureNR): bool {.borrow.}

func clear*(v: var PrivateKey) {.borrow.}
func clear*(v: var KeyPair) =
  v.seckey.clear()

func clear*(v: var SharedSecret) = burnMem(v.data)
func clear*(v: var SharedSecretFull) = burnMem(v.data)

func sign*(seckey: PrivateKey, msg: SkMessage): Signature =
  Signature(signRecoverable(SkSecretKey(seckey), msg))

func sign*(seckey: PrivateKey, msg: openArray[byte]): Signature =
  let hash = keccak256(msg)
  sign(seckey, SkMessage(hash.data))

func signNR*(seckey: PrivateKey, msg: SkMessage): SignatureNR =
  SignatureNR(sign(SkSecretKey(seckey), msg))

func signNR*(seckey: PrivateKey, msg: openArray[byte]): SignatureNR =
  let hash = keccak256(msg)
  signNR(seckey, SkMessage(hash.data))

func recover*(sig: Signature, msg: SkMessage): SkResult[PublicKey] =
  recover(SkRecoverableSignature(sig), msg).mapConvert(PublicKey)

func recover*(sig: Signature, msg: openArray[byte]): SkResult[PublicKey] =
  let hash = keccak256(msg)
  recover(sig, SkMessage(hash.data))

func verify*(sig: SignatureNR, msg: SkMessage, key: PublicKey): bool =
  verify(SkSignature(sig), msg, SkPublicKey(key))

func verify*(sig: SignatureNR, msg: openArray[byte], key: PublicKey): bool =
  let hash = keccak256(msg)
  verify(sig, SkMessage(hash.data), key)

proc ecdhSharedSecretHash(output: ptr byte, x32, y32: ptr byte, data: pointer): cint
                    {.cdecl, raises: [].} =
  ## Hash function used by `ecdhSharedSecret` below
  # `x32` and `y32` are result of scalar multiplication of publicKey * privateKey.
  # Both `x32` and `y32` are 32 bytes length.
  # Take the `x32` part as ecdh shared secret.

  # output length is derived from x32 length and taken from ecdh
  # generic parameter `KeyLength`
  copyMem(output, x32, KeyLength)
  return 1

func ecdhSharedSecret*(seckey: PrivateKey, pubkey: PublicKey): SharedSecret =
  ## Compute ecdh agreed shared secret.
  let res = ecdh[KeyLength](SkSecretKey(seckey), SkPublicKey(pubkey), ecdhSharedSecretHash, nil)
  # This function only fail if the hash function return zero.
  # Because our hash function always success, we can turn the error into defect
  doAssert res.isOk, $res.error
  SharedSecret(data: res.get)

proc ecdhSharedSecretFullHash(output: ptr byte, x32, y32: ptr byte, data: pointer): cint
                    {.cdecl, raises: [].} =
  ## Hash function used by `ecdhSharedSecretFull` below
  # `x32` and `y32` are result of scalar multiplication of publicKey * privateKey.
  # Leading byte is 0x02 if `y32` is even and 0x03 if odd. Then concat with `x32`.

  # output length is derived from `x32` length + 1 and taken from ecdh
  # generic parameter `FullKeyLength`

  # output[0] = 0x02 | (y32[31] & 1)
  output[] = 0x02 or (y32.offset(31)[] and 0x01)
  copyMem(output.offset(1), x32, KeyLength)
  return 1

func ecdhSharedSecretFull*(seckey: PrivateKey, pubkey: PublicKey): SharedSecretFull =
  ## Compute ecdh agreed shared secret with leading byte.
  let res = ecdh[FullKeyLength](SkSecretKey(seckey), SkPublicKey(pubkey), ecdhSharedSecretFullHash, nil)
  # This function only fail if the hash function return zero.
  # Because our hash function always success, we can turn the error into defect
  doAssert res.isOk, $res.error
  SharedSecretFull(data: res.get)
