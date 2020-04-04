# Nim Ethereum Keys (nim-eth-keys)
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed under either of
# - Apache License, version 2.0, (LICENSE-APACHEv2)
# - MIT license (LICENSE-MIT)
#

# This module contains adaptations of the general secp interface to help make
# working with keys and signatures as they appear in Ethereum in particular:
#
# * Public keys as serialized in uncompressed format without the initial byte
# * Shared secrets are serialized in raw format without the intial byte
# * distinct types are used to avoid confusion with the "standard" secp types

{.push raises: [Defect].}

import
  nimcrypto/hash, nimcrypto/keccak, ./keys/secp,
  stew/[byteutils, objects, result], strformat

from nimcrypto/utils import burnMem

export secp, result

const
  KeyLength* = SkEcdhRawSecretSize - 1
    ## Shared secret key length without format marker
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

  SharedSecretFull* = SkEcdhRawSecret
  SharedSecret* = object
    data*: array[KeyLength, byte]

  KeyPair* = object
    seckey*: PrivateKey
    pubkey*: PublicKey

proc random*(T: type PrivateKey): SkResult[T] =
  SkSecretKey.random().mapConvert(T)

proc fromRaw*(T: type PrivateKey, data: openArray[byte]): SkResult[T] =
  SkSecretKey.fromRaw(data).mapConvert(T)

proc fromHex*(T: type PrivateKey, data: string): SkResult[T] =
  SkSecretKey.fromHex(data).mapConvert(T)

proc toRaw*(seckey: PrivateKey): array[SkRawSecretKeySize, byte] {.borrow.}

proc toPublicKey*(seckey: PrivateKey): SkResult[PublicKey] =
  SkSecretKey(seckey).toPublicKey().mapConvert(PublicKey)

proc verify*(seckey: PrivateKey): bool {.borrow.}

proc fromRaw*(T: type PublicKey, data: openArray[byte]): SkResult[T] =
  if data.len() == SkRawCompressedPubKeySize:
    return SkPublicKey.fromRaw(data).mapConvert(PublicKey)

  if len(data) < SkRawPublicKeySize - 1:
    return err(static(
      &"keys: raw eth public key should be {SkRawPublicKeySize - 1} bytes"))

  var d: array[SkRawPublicKeySize, byte]
  d[0] = 0x04'u8
  copyMem(addr d[1], unsafeAddr data[0], 64)

  SkPublicKey.fromRaw(d).mapConvert(PublicKey)

proc fromHex*(T: type PublicKey, data: string): SkResult[T] =
  T.fromRaw(? seq[byte].fromHex(data))

proc toRaw*(pubkey: PublicKey): array[RawPublicKeySize, byte] =
  let tmp = SkPublicKey(pubkey).toRaw()
  copyMem(addr result[0], unsafeAddr tmp[1], 64)

proc toRawCompressed*(pubkey: PublicKey): array[33, byte] {.borrow.}

proc random*(T: type KeyPair): SkResult[T] =
  let tmp = ?SkKeypair.random()
  ok(T(seckey: PrivateKey(tmp.seckey), pubkey: PublicKey(tmp.pubkey)))

proc toKeyPair*(seckey: PrivateKey): SkResult[KeyPair] =
  let
    pubkey = seckey.toPublicKey()
  pubkey and ok(KeyPair(seckey: seckey, pubkey: pubkey[]))

proc fromRaw*(T: type Signature, data: openArray[byte]): SkResult[T] =
  SkRecoverableSignature.fromRaw(data).mapConvert(Signature)

proc fromHex*(T: type Signature, data: string): SkResult[T] =
  T.fromRaw(? seq[byte].fromHex(data))

proc toRaw*(sig: Signature): array[RawSignatureSize, byte] {.borrow.}

proc fromRaw*(T: type SignatureNR, data: openArray[byte]): SkResult[T] =
  SkSignature.fromRaw(data).mapConvert(SignatureNR)

proc toRaw*(sig: SignatureNR): array[RawSignatureNRSize, byte] {.borrow.}

proc toAddress*(pubkey: PublicKey, with0x = true): string =
  ## Convert public key to hexadecimal string address.
  var hash = keccak256.digest(pubkey.toRaw())
  result = if with0x: "0x" else: ""
  result.add(toHex(toOpenArray(hash.data, 12, len(hash.data) - 1)))

proc toChecksumAddress*(pubkey: PublicKey, with0x = true): string =
  ## Convert public key to checksumable mixed-case address (EIP-55).
  result = if with0x: "0x" else: ""
  var hash1 = keccak256.digest(pubkey.toRaw())
  var hhash1 = toHex(toOpenArray(hash1.data, 12, len(hash1.data) - 1))
  var hash2 = keccak256.digest(hhash1)
  var hhash2 = toHex(hash2.data)
  for i in 0..<len(hhash1):
    if hhash2[i] >= '0' and hhash2[i] <= '7':
      result.add(hhash1[i])
    else:
      if hhash1[i] >= '0' and hhash1[i] <= '9':
        result.add(hhash1[i])
      else:
        let ch = chr(ord(hhash1[i]) - ord('a') + ord('A'))
        result.add(ch)

proc validateChecksumAddress*(a: string): bool =
  ## Validate checksumable mixed-case address (EIP-55).
  var address = ""
  var check = "0x"
  if len(a) != 42:
    return false
  if a[0] != '0' and a[1] != 'x':
    return false
  for i in 2..41:
    let ch = a[i]
    if ch in {'0'..'9'} or ch in {'a'..'f'}:
      address &= ch
    elif ch in {'A'..'F'}:
      address &= chr(ord(ch) - ord('A') + ord('a'))
    else:
      return false
  var hash = keccak256.digest(address)
  var hexhash = toHex(hash.data)
  for i in 0..<len(address):
    if hexhash[i] >= '0' and hexhash[i] <= '7':
      check.add(address[i])
    else:
      if address[i] >= '0' and address[i] <= '9':
        check.add(address[i])
      else:
        let ch = chr(ord(address[i]) - ord('a') + ord('A'))
        check.add(ch)
  result = (check == a)

func toCanonicalAddress*(pubkey: PublicKey): array[20, byte] =
  ## Convert public key to canonical address.
  var hash = keccak256.digest(pubkey.toRaw())
  copyMem(addr result[0], addr hash.data[12], 20)

func `$`*(pubkey: PublicKey): string =
  ## Convert public key to hexadecimal string representation.
  toHex(pubkey.toRaw())

func `$`*(sig: Signature): string =
  ## Convert signature to hexadecimal string representation.
  toHex(sig.toRaw())

func `$`*(seckey: PrivateKey): string =
  ## Convert private key to hexadecimal string representation
  toHex(seckey.toRaw())

proc `==`*(lhs, rhs: PublicKey): bool {.borrow.}
proc `==`*(lhs, rhs: Signature): bool {.borrow.}
proc `==`*(lhs, rhs: SignatureNR): bool {.borrow.}

proc clear*(v: var PrivateKey) {.borrow.}
proc clear*(v: var PublicKey) {.borrow.}
proc clear*(v: var Signature) {.borrow.}
proc clear*(v: var SignatureNR) {.borrow.}
proc clear*(v: var KeyPair) =
  v.seckey.clear()
  v.pubkey.clear()

proc clear*(v: var SharedSecret) = burnMem(v.data)
proc clear*(v: var SharedSecretFull) = burnMem(v.data)

proc sign*(seckey: PrivateKey, msg: SkMessage): SkResult[Signature] =
  signRecoverable(SkSecretKey(seckey), msg).mapConvert(Signature)

proc sign*(seckey: PrivateKey, msg: openArray[byte]): SkResult[Signature] =
  let hash = keccak256.digest(msg)
  sign(seckey, hash)

proc signNR*(seckey: PrivateKey, msg: SkMessage): SkResult[SignatureNR] =
  sign(SkSecretKey(seckey), msg).mapConvert(SignatureNR)

proc signNR*(seckey: PrivateKey, msg: openArray[byte]): SkResult[SignatureNR] =
  let hash = keccak256.digest(msg)
  signNR(seckey, hash)

proc recover*(sig: Signature, msg: SkMessage): SkResult[PublicKey] =
  recover(SkRecoverableSignature(sig), msg).mapConvert(PublicKey)

proc recover*(sig: Signature, msg: openArray[byte]): SkResult[PublicKey] =
  let hash = keccak256.digest(msg)
  recover(sig, hash)

proc verify*(sig: SignatureNR, msg: SkMessage, key: PublicKey): bool =
  verify(SkSignature(sig), msg, SkPublicKey(key))

proc verify*(sig: SignatureNR, msg: openArray[byte], key: PublicKey): bool =
  let hash = keccak256.digest(msg)
  verify(sig, hash, key)

proc ecdhRaw*(seckey: PrivateKey, pubkey: PublicKey): SkResult[SharedSecret] =
  ecdhRaw(
    SkSecretKey(seckey), SkPublicKey(pubkey)).map proc(v: auto): SharedSecret =
      # Remove first byte!
      copyMem(addr result.data[0], unsafeAddr(v.data[1]), sizeof(result))

proc ecdhRawFull*(seckey: PrivateKey, pubkey: PublicKey): SkResult[SharedSecretFull] =
  ecdhRaw(SkSecretKey(seckey), SkPublicKey(pubkey)).mapconvert(SharedSecretFull)
