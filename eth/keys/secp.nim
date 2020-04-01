## Copyright (c) 2018-2020 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.
##

import
  secp256k1, stew/[byteutils, objects, result], nimcrypto/sysrand, strformat

from nimcrypto/utils import burnMem

export result

# Implementation notes
#
# The goal of this wrapper is to create a thin later on top of the API presented
# in libsecp256k1, exploiting some of its regulatities to make it slightly more
# convenient to use from Nim
#
# * We hide raw pointer accesses and lengths behind nim types
# * We guarantee certain parameter properties, like not null and proper length,
#   on the Nim side - in turn, we can rely on certain errors never happening in
#   libsecp256k1, so we can skip checking for them
# * Functions like "fromRaw/toRaw" are balanced and will always rountrip
# * Functions like `fromRaw` are not called `init` because they may fail
# * Exception-free

const
  SkRawSecretKeySize* = 32 # 256 div 8
    ## Size of private key in octets (bytes)
  SkRawSignatureSize* = 64
    ## Compact serialized non-recoverable signature
  SkDerSignatureMaxSize* = 72
    ## Max bytes in DER encoding

  SkRawRecoverableSignatureSize* = 65
    ## Size of recoverable signature in octets (bytes)

  SkRawPublicKeySize* = 65
    ## Size of uncompressed public key in octets (bytes)

  SkRawCompressedPubKeySize* = 33
    ## Size of compressed public key in octets (bytes)

  SkMessageSize* = 32
    ## Size of message that can be signed

  SkEdchSecretSize* = 32
    ## ECDH-agreed key size
  SkEcdhRawSecretSize* = 33
    ## ECDH-agreed raw key size

type
  SkPublicKey* = secp256k1_pubkey
    ## Representation of public key.

  SkSecretKey* = object
    ## Representation of secret key.
    data*: array[SkRawSecretKeySize, byte]

  SkKeyPair* = object
    ## Representation of private/public keys pair.
    seckey*: SkSecretKey
    pubkey*: SkPublicKey

  SkSignature* = secp256k1_ecdsa_signature
    ## Representation of non-recoverable signature.

  SkRecoverableSignature* = secp256k1_ecdsa_recoverable_signature
    ## Representation of recoverable signature.

  SkContext* = ref object
    ## Representation of Secp256k1 context object.
    context: ptr secp256k1_context

  SkMessage* = object
    ## Message that can be signed or verified
    data*: array[SkMessageSize, byte]

  SkEcdhSecret* = object
    ## Representation of ECDH shared secret
    data*: array[SkEdchSecretSize, byte]

  SkEcdhRawSecret* = object
    ## Representation of ECDH shared secret, with leading `y` byte
    # (`y` is 0x02 when pubkey.y is even or 0x03 when odd)
    data*: array[SkEcdhRawSecretSize, byte]

  SkResult*[T] = result.Result[T, cstring]

##
## Private procedures interface
##

var secpContext {.threadvar.}: SkContext
  ## Thread local variable which holds current context

proc illegalCallback(message: cstring, data: pointer) {.cdecl.} =
  # This should never happen because we check all parameters before passing
  # them to secp
  echo message
  echo getStackTrace()
  quit 1

proc errorCallback(message: cstring, data: pointer) {.cdecl.} =
  # Internal panic - should never happen
  echo message
  echo getStackTrace()
  quit 1

template ptr0(v: array|openArray): ptr cuchar =
  cast[ptr cuchar](unsafeAddr v[0])

proc shutdownLibsecp256k1(ctx: SkContext) =
  # TODO: use destructor when finalizer are deprecated for destructors
  if not(isNil(ctx.context)):
    secp256k1_context_destroy(ctx.context)

proc newSkContext(): SkContext =
  ## Create new Secp256k1 context object.
  new(result, shutdownLibsecp256k1)
  let flags = cuint(SECP256K1_CONTEXT_VERIFY or SECP256K1_CONTEXT_SIGN)
  result.context = secp256k1_context_create(flags)
  secp256k1_context_set_illegal_callback(result.context, illegalCallback,
                                         cast[pointer](result))
  secp256k1_context_set_error_callback(result.context, errorCallback,
                                       cast[pointer](result))

func getContext(): ptr secp256k1_context =
  ## Get current `EccContext`
  {.noSideEffect.}: # TODO what problems will this cause?
    if isNil(secpContext):
      secpContext = newSkContext()
    secpContext.context

proc random*(T: type SkSecretKey): SkResult[T] =
  ## Generates new random private key.
  let ctx = getContext()
  var sk: T
  while randomBytes(sk.data) == SkRawSecretKeySize:
    if secp256k1_ec_seckey_verify(ctx, sk.data.ptr0) == 1:
      return ok(sk)

  return err("secp: cannot get random bytes for key")

proc fromRaw*(T: type SkSecretKey, data: openArray[byte]): SkResult[T] =
  ## Load a valid private key, as created by `toRaw`
  if len(data) < SkRawSecretKeySize:
    return err(&"secp: raw private key should be {SkRawSecretKeySize} bytes")

  if secp256k1_ec_seckey_verify(getContext(), data.ptr0) != 1:
    return err("secp: invalid private key")

  ok(T(data: toArray(32, data.toOpenArray(0, SkRawSecretKeySize - 1))))

proc fromHex*(T: type SkSecretKey, data: string): SkResult[SkSecretKey] =
  ## Initialize Secp256k1 `private key` ``key`` from hexadecimal string
  ## representation ``data``.
  try:
    # TODO strip string?
    T.fromRaw(hexToSeqByte(data))
  except CatchableError:
    err("secp: cannot parse private key")

proc toRaw*(seckey: SkSecretKey): array[SkRawSecretKeySize, byte] =
  ## Serialize Secp256k1 `private key` ``key`` to raw binary form
  seckey.data

proc toPublicKey*(key: SkSecretKey): SkResult[SkPublicKey] =
  ## Calculate and return Secp256k1 `public key` from `private key` ``key``.
  var pubkey: SkPublicKey
  if secp256k1_ec_pubkey_create(getContext(), addr pubkey, key.data.ptr0) != 1:
    return err("secp: cannot create pubkey, private key invalid?")

  ok(pubkey)

proc fromRaw*(T: type SkPublicKey, data: openArray[byte]): SkResult[T] =
  ## Initialize Secp256k1 `public key` ``key`` from raw binary
  ## representation ``data``, which may be compressed, uncompressed or hybrid
  if len(data) < 1:
    return err(&"secp: public key must be {SkRawCompressedPubKeySize} or {SkRawPublicKeySize} bytes")

  var length: int
  if data[0] == 0x02'u8 or data[0] == 0x03'u8:
    length = min(len(data), SkRawCompressedPubKeySize)
  elif data[0] == 0x04'u8 or data[0] == 0x06'u8 or data[0] == 0x07'u8:
    length = min(len(data), SkRawPublicKeySize)
  else:
    return err("secp: public key format not recognised")

  var key: SkPublicKey
  if secp256k1_ec_pubkey_parse(
      getContext(), addr key, data.ptr0, length) != 1:
    return err("secp: cannot parse public key")

  ok(key)

proc fromHex*(T: type SkPublicKey, data: string): SkResult[T] =
  ## Initialize Secp256k1 `public key` ``key`` from hexadecimal string
  ## representation ``data``.
  try:
    # TODO strip string?
    T.fromRaw(hexToSeqByte(data))
  except CatchableError:
    err("secp: cannot parse public key")

proc toRaw*(pubkey: SkPublicKey): array[SkRawPublicKeySize, byte] =
  ## Serialize Secp256k1 `public key` ``key`` to raw uncompressed form
  var length = csize(len(result))
  # Can't fail, per documentation
  discard secp256k1_ec_pubkey_serialize(
    getContext(), result.ptr0, addr length, unsafeAddr pubkey,
    SECP256K1_EC_UNCOMPRESSED)

proc toRawCompressed*(key: SkPublicKey): array[SkRawCompressedPubKeySize, byte] =
  ## Serialize Secp256k1 `public key` ``key`` to raw compressed form
  var length = csize(len(result))
  # Can't fail, per documentation
  discard secp256k1_ec_pubkey_serialize(
    getContext(), result.ptr0, addr length, unsafeAddr key,
    SECP256K1_EC_COMPRESSED)

proc fromRaw*(T: type SkSignature, data: openArray[byte]): SkResult[T] =
  ## Load compact signature from data
  if data.len() < SkRawSignatureSize:
    return err(&"secp: signature must be {SkRawSignatureSize} bytes")

  var sig: SkSignature
  if secp256k1_ecdsa_signature_parse_compact(
      getContext(), addr sig, data.ptr0) != 1:
    return err("secp: cannot parse signaure")

  ok(sig)

proc fromDer*(T: type SkSignature, data: openarray[byte]): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from DER
  ## representation ``data``.
  if len(data) < 1:
    return err("secp: DER signature too short")

  var sig: T
  if secp256k1_ecdsa_signature_parse_der(
      getContext().context, addr sig, data.ptr0, csize(len(data))) != 1:
    return err("secp: cannot parse DER signature")

  ok(sig)

proc fromHex*(T: type SkSignature, data: string): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from hexadecimal string
  ## representation ``data``.
  try:
    # TODO strip string?
    T.fromRaw(hexToSeqByte(data))
  except CatchableError:
    err("secp: cannot parse signature")

proc toRaw*(sig: SkSignature): array[SkRawSignatureSize, byte] =
  ## Serialize signature to compact binary form
  # Can't fail, per documentation
  discard secp256k1_ecdsa_signature_serialize_compact(
    getContext(), result.ptr0, unsafeAddr sig)

proc toDer*(sig: SkSignature, data: var openarray[byte]): int =
  ## Serialize Secp256k1 `signature` ``sig`` to raw binary form and store it
  ## to ``data``.
  ##
  ## Procedure returns number of bytes (octets) needed to store
  ## Secp256k1 signature.
  let ctx = getContext()
  var buffer: array[SkDerSignatureMaxSize, byte]
  var plength = csize(len(buffer))
  discard secp256k1_ecdsa_signature_serialize_der(
    ctx, buffer.ptr0, addr plength, unsafeAddr sig)
  result = plength
  if len(data) >= plength:
    copyMem(addr data[0], addr buffer[0], plength)

proc toDer*(sig: SkSignature): seq[byte] =
  ## Serialize Secp256k1 `signature` and return it.
  result = newSeq[byte](72)
  let length = toDer(sig, result)
  result.setLen(length)

proc fromRaw*(T: type SkRecoverableSignature, data: openArray[byte]): SkResult[T] =
  if data.len() < SkRawRecoverableSignatureSize:
    return err(&"secp: recoverable signature must be {SkRawRecoverableSignatureSize} bytes")

  let recid = cint(data[64])
  var sig: SkRecoverableSignature
  if secp256k1_ecdsa_recoverable_signature_parse_compact(
      getContext(), addr sig, data.ptr0, recid) != 1:
    return err("secp: invalid recoverable signature")

  ok(sig)

proc fromHex*(T: type SkRecoverableSignature, data: string): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from hexadecimal string
  ## representation ``data``.
  try:
    # TODO strip string?
    T.fromRaw(hexToSeqByte(data))
  except CatchableError:
    err("secp: cannot parse recoverable signature")

proc toRaw*(sig: SkRecoverableSignature): array[SkRawRecoverableSignatureSize, byte] =
  ## Converts recoverable signature to compact binary form
  var recid = cint(0)
  # Can't fail, per documentation
  discard secp256k1_ecdsa_recoverable_signature_serialize_compact(
      getContext(), result.ptr0, addr recid, unsafeAddr sig)
  result[64] = byte(recid)

proc random*(T: type SkKeyPair): SkResult[T] =
  ## Generates new random key pair.
  let seckey = ? SkSecretKey.random()
  ok(T(
    seckey: seckey,
    pubkey: seckey.toPublicKey().expect("random key should always be valid")
  ))

proc `==`*(lhs, rhs: SkSecretKey): bool =
  ## Compare Secp256k1 `private key` objects for equality.
  lhs.data == rhs.data

proc `==`*(lhs, rhs: SkPublicKey): bool =
  ## Compare Secp256k1 `public key` objects for equality.
  lhs.toRaw() == rhs.toRaw()

proc `==`*(lhs, rhs: SkSignature): bool =
  ## Compare Secp256k1 `signature` objects for equality.
  lhs.toRaw() == rhs.toRaw()

proc `==`*(lhs, rhs: SkRecoverableSignature): bool =
  ## Compare Secp256k1 `recoverable signature` objects for equality.
  lhs.toRaw() == rhs.toRaw()

proc `==`*(lhs, rhs: SkEcdhSecret): bool =
  ## Compare Secp256k1 `ECDH key` objects for equality.
  lhs.data == rhs.data

proc `==`*(lhs, rhs: SkEcdhRawSecret): bool =
  ## Compare Secp256k1 `ECDH raw key` objects for equality.
  lhs.data == rhs.data

proc sign*(key: SkSecretKey, msg: SkMessage): SkResult[SkSignature] =
  ## Sign message `msg` using private key `key` and return signature object.
  var sig: SkSignature
  if secp256k1_ecdsa_sign(
      getContext(), addr sig, msg.data.ptr0, key.data.ptr0, nil, nil) != 1:
    return err("secp: cannot create signature, key invalid?")

  ok(sig)

proc signRecoverable*(key: SkSecretKey, msg: SkMessage): SkResult[SkRecoverableSignature] =
  ## Sign message `msg` using private key `key` and return signature object.
  var sig: SkRecoverableSignature
  if secp256k1_ecdsa_sign_recoverable(
      getContext(), addr sig, msg.data.ptr0, key.data.ptr0, nil, nil) != 1:
    return err("secp: cannot create recoverable signature, key invalid?")

  ok(sig)

proc verify*(sig: SkSignature, msg: SkMessage, key: SkPublicKey): bool =
  secp256k1_ecdsa_verify(
    getContext(), unsafeAddr sig, msg.data.ptr0, unsafeAddr key) == 1

proc recover*(sig: SkRecoverableSignature, msg: SkMessage): SkResult[SkPublicKey] =
  var pubkey: SkPublicKey
  if secp256k1_ecdsa_recover(
      getContext(), addr pubkey, unsafeAddr sig, msg.data.ptr0) != 1:
    return err("secp: cannot recover public key from signature")

  ok(pubkey)

proc ecdh*(seckey: SkSecretKey, pubkey: SkPublicKey): SkResult[SkEcdhSecret] =
  ## Calculate ECDH shared secret.
  var secret: SkEcdhSecret
  if secp256k1_ecdh(
      getContext(), secret.data.ptr0, unsafeAddr pubkey, seckey.data.ptr0) != 1:
    return err("secp: cannot compute ECDH secret")

  ok(secret)

proc ecdhRaw*(seckey: SkSecretKey, pubkey: SkPublicKey): SkResult[SkEcdhRawSecret] =
  ## Calculate ECDH shared secret.
  var secret: SkEcdhRawSecret
  if secp256k1_ecdh_raw(
      getContext(), secret.data.ptr0, unsafeAddr pubkey, seckey.data.ptr0) != 1:
    return err("Cannot compute raw ECDH secret")

  ok(secret)

proc clear*(v: var SkSecretKey) {.inline.} =
  ## Wipe and clear memory of Secp256k1 `private key`.
  burnMem(v.data)

proc clear*(v: var SkPublicKey) {.inline.} =
  ## Wipe and clear memory of Secp256k1 `public key`.
  burnMem(v.data)

proc clear*(v: var SkSignature) {.inline.} =
  ## Wipe and clear memory of Secp256k1 `signature`.
  burnMem(v.data)

proc clear*(v: var SkRecoverableSignature) {.inline.} =
  ## Wipe and clear memory of Secp256k1 `signature`.
  burnMem(v.data)

proc clear*(v: var SkKeyPair) {.inline.} =
  ## Wipe and clear memory of Secp256k1 `key pair`.
  v.seckey.clear()
  v.pubkey.clear()

proc clear*(v: var SkEcdhSecret) =
  burnMem(v.data)

proc clear*(v: var SkEcdhRawSecret) =
  burnMem(v.data)
