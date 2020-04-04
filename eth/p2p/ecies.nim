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

import eth/keys, nimcrypto/[rijndael, bcmode, hash, hmac, sysrand, sha2, utils]

const
  emptyMac* = array[0, byte]([])

type
  EciesException* = object of CatchableError
  EciesStatus* = enum
    Success,        ## Operation was successful
    BufferOverrun,  ## Output buffer size is too small
    RandomError,    ## Could not obtain random data
    EcdhError,      ## ECDH shared secret could not be calculated
    WrongHeader,    ## ECIES header is incorrect
    IncorrectKey,   ## Recovered public key is invalid
    IncorrectTag,   ## ECIES tag verification failed
    IncompleteError ## Decryption needs more data

  EciesHeader* = object {.packed.}
    version*: byte
    pubkey*: array[RawPublicKeySize, byte]
    iv*: array[aes128.sizeBlock, byte]
    data*: byte

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

proc kdf*(data: openarray[byte]): array[KeyLength, byte] {.noInit.} =
  ## NIST SP 800-56a Concatenation Key Derivation Function (see section 5.8.1)
  var ctx: sha256
  var counter: uint32
  var counterLe: uint32
  let reps = ((KeyLength + 7) * 8) div (int(ctx.sizeBlock) * 8)
  var offset = 0
  var storage = newSeq[byte](int(ctx.sizeDigest) * (reps + 1))
  while counter <= uint32(reps):
    counter = counter + 1
    counterLe = LSWAP(counter)
    ctx.init()
    ctx.update(cast[ptr byte](addr counterLe), uint(sizeof(uint32)))
    ctx.update(unsafeAddr data[0], uint(len(data)))
    var hash = ctx.finish()
    copyMem(addr storage[offset], addr hash.data[0], ctx.sizeDigest)
    offset += int(ctx.sizeDigest)
  ctx.clear() # clean ctx
  copyMem(addr result[0], addr storage[0], KeyLength)

proc eciesEncrypt*(input: openarray[byte], output: var openarray[byte],
                   pubkey: PublicKey,
                   sharedmac: openarray[byte] = emptyMac): EciesStatus =
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
    iv: array[aes128.sizeBlock, byte]
    material: array[KeyLength, byte]

  if len(output) < eciesEncryptedLength(len(input)):
    return(BufferOverrun)
  if randomBytes(iv) != aes128.sizeBlock:
    return(RandomError)

  var ephemeral = KeyPair.random()
  if ephemeral.isErr:
    return(RandomError)

  var secret = ecdhRaw(ephemeral[].seckey, pubkey)
  if secret.isErr:
    return(EcdhError)

  material = kdf(secret[].data)
  burnMem(secret)

  copyMem(addr encKey[0], addr material[0], aes128.sizeKey)
  var macKey = sha256.digest(material, ostart = KeyLength div 2)
  burnMem(material)

  var header = cast[ptr EciesHeader](addr output[0])
  header.version = 0x04
  header.pubkey = ephemeral[].pubkey.toRaw()
  header.iv = iv

  var so = eciesDataPos()
  var eo = so + len(input)
  cipher.init(encKey, iv)
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

  result = Success

proc eciesDecrypt*(input: openarray[byte],
                   output: var openarray[byte],
                   seckey: PrivateKey,
                   sharedmac: openarray[byte] = emptyMac): EciesStatus =
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
    return(IncompleteError)

  var header = cast[ptr EciesHeader](unsafeAddr input[0])
  if header.version != 0x04:
    return(WrongHeader)
  if len(input) <= eciesOverheadLength():
    return(IncompleteError)
  if len(input) - eciesOverheadLength() > len(output):
    return(BufferOverrun)
  let pubkey = PublicKey.fromRaw(header.pubkey)
  if pubkey.isErr:
    return(IncorrectKey)
  var secret = ecdhRaw(seckey, pubkey[])
  if secret.isErr:
    return(EcdhError)

  var material = kdf(secret[].data)
  burnMem(secret)
  copyMem(addr encKey[0], addr material[0], aes128.sizeKey)
  var macKey = sha256.digest(material, ostart = KeyLength div 2)
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
    return(IncorrectTag)

  let datsize = eciesDecryptedLength(len(input))
  cipher.init(encKey, header.iv)
  burnMem(encKey)
  cipher.decrypt(toOpenArray(input, eciesDataPos(),
                             eciesDataPos() + datsize - 1), output)
  cipher.clear()
  result = Success
