#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

## This module implements ECIES method encryption/decryption.

{.push raises: [Defect].}

import
  stew/[results, endians2],
  nimcrypto/[rijndael, bcmode, hash, hmac, sha2, utils],
  ../keys

export results

const
  emptyMac* = array[0, byte]([])

type
  EciesError* = enum
    BufferOverrun   = "ecies: output buffer size is too small"
    EcdhError       = "ecies: ECDH shared secret could not be calculated"
    WrongHeader     = "ecies: header is incorrect"
    IncorrectKey    = "ecies: recovered public key is invalid"
    IncorrectTag    = "ecies: tag verification failed"
    IncompleteError = "ecies: decryption needs more data"

  EciesHeader* {.packed.} = object
    version*: byte
    pubkey*: array[RawPublicKeySize, byte]
    iv*: array[aes128.sizeBlock, byte]
    data*: byte

  EciesResult*[T] = Result[T, EciesError]

proc mapErrTo[T](r: SkResult[T], v: static EciesError): EciesResult[T] =
  r.mapErr(proc (e: cstring): EciesError = v)

template eciesOverheadLength*(): int =
  ## Return data overhead size for ECIES encrypted message
  1 + sizeof(PublicKey) + aes128.sizeBlock + sha256.sizeDigest

template eciesEncryptedLength*(size: int): int =
  ## Return size of encrypted message for message with size `size`.
  size + eciesOverheadLength()

template eciesDecryptedLength*(size: int): int =
  ## Return size of decrypted message for encrypted message with size `size`.
  size - eciesOverheadLength()

template eciesMacLength(size: int): int =
  ## Return size of authenticated data
  size + aes128.sizeBlock

template eciesMacPos(size: int): int =
  ## Return position of MAC code in encrypted block
  size - sha256.sizeDigest

template eciesDataPos(): int =
  ## Return position of encrypted data in block
  1 + sizeof(PublicKey) + aes128.sizeBlock

template eciesIvPos(): int =
  ## Return position of IV in block
  1 + sizeof(PublicKey)

template eciesTagPos(size: int): int =
  1 + sizeof(PublicKey) + aes128.sizeBlock + size

proc kdf*(data: openArray[byte]): array[KeyLength, byte] {.noinit.} =
  ## NIST SP 800-56a Concatenation Key Derivation Function (see section 5.8.1)
  var ctx: sha256
  var counter: uint32
  var counterLe: uint32
  let reps = ((KeyLength + 7) * 8) div (int(ctx.sizeBlock) * 8)
  var offset = 0
  var storage = newSeq[byte](int(ctx.sizeDigest) * (reps + 1))
  while counter <= uint32(reps):
    counter = counter + 1
    counterLe = toBE(counter)
    ctx.init()
    ctx.update(cast[ptr byte](addr counterLe), uint(sizeof(uint32)))
    ctx.update(unsafeAddr data[0], uint(len(data)))
    var hash = ctx.finish()
    copyMem(addr storage[offset], addr hash.data[0], ctx.sizeDigest)
    offset += int(ctx.sizeDigest)
  ctx.clear() # clean ctx
  copyMem(addr result[0], addr storage[0], KeyLength)

proc eciesEncrypt*(rng: var HmacDrbgContext, input: openArray[byte],
                   output: var openArray[byte], pubkey: PublicKey,
                   sharedmac: openArray[byte] = emptyMac): EciesResult[void] =
  ## Encrypt data with ECIES method using given public key `pubkey`.
  ## ``input``     - input data
  ## ``output``    - output data
  ## ``pubkey``    - ECC public key
  ## ``sharedmac`` - additional data used to calculate encrypted message MAC
  ## Length of output data can be calculated using ``eciesEncryptedLength()``
  ## template.
  var
    encKey: array[aes128.sizeKey, byte]
    cipher: CTR[aes128]
    ctx: HMAC[sha256]

  if len(output) < eciesEncryptedLength(len(input)):
    return err(BufferOverrun)

  var
    ephemeral = KeyPair.random(rng)
    secret = ecdhRaw(ephemeral.seckey, pubkey)
    material = kdf(secret.data)

  clear(secret)

  copyMem(addr encKey[0], addr material[0], aes128.sizeKey)

  var macKey =
    sha256.digest(material.toOpenArray(KeyLength div 2, material.high))
  burnMem(material)

  var header = cast[ptr EciesHeader](addr output[0])
  header.version = 0x04
  header.pubkey = ephemeral.pubkey.toRaw()
  rng.generate(header[].iv)

  clear(ephemeral)

  var so = eciesDataPos()
  var eo = so + len(input)
  cipher.init(encKey, header.iv)
  cipher.encrypt(input, toOpenArray(output, so, eo))
  burnMem(encKey)
  cipher.clear()

  so = eciesIvPos()
  eo = so + aes128.sizeBlock + len(input) - 1
  ctx.init(macKey.data)
  ctx.update(toOpenArray(output, so, eo))
  if len(sharedmac) > 0:
    ctx.update(sharedmac)
  var tag = ctx.finish()

  so = eciesTagPos(len(input))
  # ctx.sizeDigest() crash compiler
  copyMem(addr output[so], addr tag.data[0], sha256.sizeDigest)
  ctx.clear()

  ok()

proc eciesDecrypt*(input: openArray[byte],
                   output: var openArray[byte],
                   seckey: PrivateKey,
                   sharedmac: openArray[byte] = emptyMac): EciesResult[void] =
  ## Decrypt data with ECIES method using given private key `seckey`.
  ## ``input``     - input data
  ## ``output``    - output data
  ## ``pubkey``    - ECC private key
  ## ``sharedmac`` - additional data used to calculate encrypted message MAC
  ## Length of output data can be calculated using ``eciesDecryptedLength()``
  ## template.
  var
    encKey: array[aes128.sizeKey, byte]
    cipher: CTR[aes128]
    ctx: HMAC[sha256]

  if len(input) <= 0:
    return err(IncompleteError)

  var header = cast[ptr EciesHeader](unsafeAddr input[0])
  if header.version != 0x04:
    return err(WrongHeader)
  if len(input) <= eciesOverheadLength():
    return err(IncompleteError)
  if len(input) - eciesOverheadLength() > len(output):
    return err(BufferOverrun)

  var
    pubkey = ? PublicKey.fromRaw(header.pubkey).mapErrTo(IncorrectKey)
    secret = ecdhRaw(seckey, pubkey)

  var material = kdf(secret.data)
  burnMem(secret)

  copyMem(addr encKey[0], addr material[0], aes128.sizeKey)
  var macKey =
    sha256.digest(material.toOpenArray(KeyLength div 2, material.high))
  burnMem(material)

  let macsize = eciesMacLength(len(input) - eciesOverheadLength())
  ctx.init(macKey.data)
  burnMem(macKey)
  ctx.update(toOpenArray(input, eciesIvPos(), eciesIvPos() + macsize - 1))
  if len(sharedmac) > 0:
    ctx.update(sharedmac)
  var tag = ctx.finish()
  ctx.clear()

  if not equalMem(addr tag.data[0], unsafeAddr input[eciesMacPos(len(input))],
                  sha256.sizeDigest):
    return err(IncorrectTag)

  let datsize = eciesDecryptedLength(len(input))
  cipher.init(encKey, header.iv)
  burnMem(encKey)
  cipher.decrypt(toOpenArray(input, eciesDataPos(),
                             eciesDataPos() + datsize - 1), output)
  cipher.clear()

  ok()
