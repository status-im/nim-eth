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

proc random*(t: type KeyPair): SkResult[KeyPair] =
  let tmp = ?SkKeypair.random()
  ok(KeyPair(seckey: PrivateKey(tmp.seckey), pubkey: PublicKey(tmp.pubkey)))

proc fromRaw(T: type Signature, data: openArray[byte]): SkResult[T] =
  SkRecoverableSignature.fromRaw(data).mapConvert(Signature)

proc fromHex*(T: type Signature, data: string): SkResult[T] =
  T.fromRaw(? seq[byte].fromHex(data))

proc toRaw*(sig: Signature): array[RawSignatureSize, byte] {.borrow.}

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


# Backwards compat - the functions in here are deprecated and should be moved
# reimplemented using functions that return Result instead!

{.pop.} # raises

from nimcrypto/utils import stripSpaces

type
  EthKeysException* {.deprecated.} = object of CatchableError
  Secp256k1Exception* {.deprecated.} = object of CatchableError

  EthKeysStatus* {.deprecated.} = enum
    Success
    Error

template data*(pubkey: PublicKey): auto =
  SkPublicKey(pubkey).data

template data*(seckey: PrivateKey): auto =
  SkSecretKey(seckey).data

template data*(sig: Signature): auto =
  SkRecoverableSignature(sig).data

proc isZeroKey*(seckey: PrivateKey): bool {.deprecated.} =
  ## Check if private key `seckey` contains only 0 bytes.
  # TODO this is a weird check - better would be to check if the key is valid!
  result = true
  for i in seckey.data: # constant time, loop all bytes always
    if i != byte(0):
      result = false

proc isZeroKey*(pubkey: PublicKey): bool {.deprecated.} =
  ## Check if public key `pubkey` contains only 0 bytes.
  # TODO this is a weird check - better would be to check if the key is valid!
  result = true
  for i in pubkey.data: # constant time, loop all bytes always
    if i != byte(0):
      result = false

proc newPrivateKey*(): PrivateKey {.deprecated: "random".} =
  let key = PrivateKey.random()
  if key.isErr:
    raise newException(Secp256k1Exception, $key.error)
  key[]

proc newKeyPair*(): KeyPair {.deprecated: "random".} =
  let kp = KeyPair.random()
  if kp.isErr:
    raise newException(Secp256k1Exception, $kp.error)
  kp[]

proc getPublicKey*(seckey: PrivateKey): PublicKey {.deprecated: "toPublicKey".} =
  let key = seckey.toPublicKey()
  if key.isErr:
    raise newException(Secp256k1Exception, "invalid private key")
  key[]

proc ecdhAgree*(
    seckey: PrivateKey, pubkey: PublicKey,
    s: var SharedSecret): EthKeysStatus {.deprecated.} =
  let v = ecdhRaw(
    SkSecretKey(seckey), SkPublicKey(pubkey)).map proc(v: auto): SharedSecret =
    copyMem(addr result.data[0], unsafeAddr(v.data[1]), sizeof(result))

  if v.isOk():
    s = v[]
    return Success
  return Error

proc getRaw*(
    pubkey: PublicKey): array[RawPublicKeySize, byte] {.deprecated: "toRaw".} =
  pubkey.toRaw()

proc getRawCompressed*(
    pubkey: PublicKey): array[SkRawCompressedPubKeySize, byte] {.
    deprecated: "toRawCompressed".} =
  pubkey.toRawCompressed()

proc recoverPublicKey*(
    data: openArray[byte], pubkey: var PublicKey): EthKeysStatus {.
    deprecated: "fromRaw".} =
  let v = PublicKey.fromRaw(data)
  if v.isOk():
    pubkey = v[]
    return Success

  return Error

proc signRawMessage*(data: openarray[byte], seckey: PrivateKey,
                     signature: var Signature): EthKeysStatus {.deprecated.} =
  if len(data) != SkMessageSize:
    return Error
  let sig = signRecoverable(
    SkSecretKey(seckey), SkMessage(data: toArray(32, data.toOpenArray(0, 31))))
  if sig.isOk():
    signature = Signature(sig[])
    return Success

  return Error

proc signRawMessage*(data: openarray[byte], seckey: PrivateKey,
                     signature: var SignatureNR): EthKeysStatus  {.deprecated.} =
  ## Sign message `data` of `KeyLength` size using private key `seckey` and
  ## store result into `signature`.
  let length = len(data)
  if length != KeyLength:
    return(EthKeysStatus.Error)
  let sig = sign(
    SkSecretKey(seckey), SkMessage(data: toArray(32, data.toOpenArray(0, 31))))
  if sig.isOk():
    signature = SignatureNR(sig[])
    return Success

  return Error

proc signMessage*(seckey: PrivateKey,
                  data: openarray[byte]): Signature {.deprecated.} =
  let hash = keccak256.digest(data)
  if signRawMessage(hash.data, seckey, result) != EthKeysStatus.Success:
    raise newException(EthKeysException, "signature failed")

proc getRaw*(
    s: SignatureNR): array[SkRawSignatureSize, byte] {.deprecated: "toRaw".} =
  ## Converts signature `s` to serialized form.
  SkSignature(s).toRaw()

proc getRaw*(
    s: Signature): array[SkRawRecoverableSignatureSize, byte] {.
    deprecated: "toRaw".} =
  ## Converts signature `s` to serialized form.
  SkRecoverableSignature(s).toRaw()

proc recoverSignatureKey*(signature: Signature,
                          msg: openarray[byte],
                          pubkey: var PublicKey): EthKeysStatus  {.deprecated.} =
  if len(msg) < SkMessageSize:
    return Error
  let pk = recover(
    SkRecoverableSignature(signature),
    SkMessage(data: toArray(32, msg.toOpenArray(0, 31))))
  if pk.isErr(): return Error

  pubkey = PublicKey(pk[])
  return Success

proc recoverSignatureKey*(data: openarray[byte],
                          msg: openarray[byte],
                          pubkey: var PublicKey): EthKeysStatus  {.deprecated.} =
  let signature = SkRecoverableSignature.fromRaw(data)
  if signature.isErr(): return Error

  if len(msg) < SkMessageSize:
    return Error
  let pk = recover(
    SkRecoverableSignature(signature[]),
    SkMessage(data: toArray(32, msg.toOpenArray(0, 31))))
  if pk.isErr(): return Error

  pubkey = PublicKey(pk[])
  return Success

proc initPrivateKey*(
    data: openArray[byte]): PrivateKey {.deprecated: "PrivateKey.fromRaw".} =
  let res = PrivateKey.fromRaw(data)
  if res.isOk():
    return res[]

  raise (ref EthKeysException)(msg: $res.error)

proc initPrivateKey*(
    data: string): PrivateKey {.deprecated: "PrivateKey.fromHex".} =
  let res = PrivateKey.fromHex(stripSpaces(data))
  if res.isOk():
    return res[]

  raise (ref EthKeysException)(msg: $res.error)

proc initPublicKey*(
    hexstr: string): PublicKey {.deprecated: "PublicKey.fromHex".} =
  let pk = PublicKey.fromHex(stripSpaces(hexstr))
  if pk.isOk(): return pk[]

  raise newException(EthKeysException, $pk.error)

proc initPublicKey*(data: openarray[byte]): PublicKey {.deprecated.} =
  let pk = PublicKey.fromRaw(data)
  if pk.isOk(): return pk[]

  raise newException(EthKeysException, $pk.error)

proc signMessage*(seckey: PrivateKey, data: string): Signature {.deprecated.} =
  signMessage(seckey, cast[seq[byte]](data))

proc toKeyPair*(key: PrivateKey): KeyPair {.deprecated.} =
  KeyPair(seckey: key, pubkey: key.getPublicKey())

proc initSignature*(data: openArray[byte]): Signature {.deprecated.} =
  let sig = SkRecoverableSignature.fromRaw(data)
  if sig.isOk(): return Signature(sig[])

  raise newException(EthKeysException, $sig.error)

proc initSignature*(hexstr: string): Signature {.deprecated.} =
  let sig = SkRecoverableSignature.fromHex(stripSpaces(hexstr))
  if sig.isOk(): return Signature(sig[])

  raise newException(EthKeysException, $sig.error)

proc recoverSignature*(data: openarray[byte],
                       signature: var Signature): EthKeysStatus {.deprecated.} =
  ## Deprecated, use `parseCompact` instead
  if data.len < RawSignatureSize:
    return(EthKeysStatus.Error)
  let sig = SkRecoverableSignature.fromRaw(data)
  if sig.isErr():
    return Error
  signature = Signature(sig[])
  return Success

proc recoverKeyFromSignature*(signature: Signature,
                              hash: MDigest[256]): PublicKey {.deprecated.} =
  ## Recover public key from signature `signature` using `message`.
  let key = recover(SkRecoverableSignature(signature), hash)
  if key.isOk():
    return PublicKey(key[])
  raise newException(EthKeysException, $key.error)

proc recoverKeyFromSignature*(
    signature: Signature,
    message: openArray[byte]): PublicKey {.deprecated.} =
  let hash = keccak256.digest(message)
  recoverKeyFromSignature(signature, hash)

proc recoverKeyFromSignature*(
    signature: Signature, data: string): PublicKey {.deprecated.} =
  recoverKeyFromSignature(signature, cast[seq[byte]](data))

proc parseCompact*(
    signature: var SignatureNR,
    data: openarray[byte]): EthKeysStatus {.deprecated.} =
  let sig = SkSignature.fromRaw(data)
  if sig.isErr():
    return Error

  signature = SignatureNR(sig[])
  return Success

proc verifySignatureRaw*(
    signature: SignatureNR, message: openarray[byte],
    publicKey: PublicKey): EthKeysStatus {.deprecated.} =
  ## Verify `signature` using original `message` (32 bytes) and `publicKey`.
  if verify(
      SkSignature(signature),
      SkMessage(data: toArray(32, message.toOpenArray(0, 31))),
      SkPublicKey(publicKey)):
    return Success

  return Error

proc ecdhAgree*(
    seckey: PrivateKey, pubkey: PublicKey,
    s: var SharedSecretFull): EthKeysStatus {.deprecated.} =
  let v = ecdhRaw(SkSecretKey(seckey), SkPublicKey(pubkey))
  if v.isOk():
    s = SharedSecretFull(v[])
    return Success
  return Error
