#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

## This module implements Ethereum authentication

{.push raises: [Defect].}

import
  nimcrypto/[rijndael, keccak, utils], bearssl,
  stew/[byteutils, endians2, objects, results],
  ".."/[keys, rlp],
  ./ecies

export results

const
  SupportedRlpxVersion* = 4'u8
  PlainAuthMessageV4Length* = 194
  AuthMessageV4Length* = 307
  PlainAuthMessageEIP8Length = 169
  PlainAuthMessageMaxEIP8* = PlainAuthMessageEIP8Length + 255
  AuthMessageEIP8Length* = 282 + 2
  AuthMessageMaxEIP8* = AuthMessageEIP8Length + 255
  PlainAckMessageV4Length* = 97
  AckMessageV4Length* = 210
  PlainAckMessageEIP8Length* = 102
  PlainAckMessageMaxEIP8* = PlainAckMessageEIP8Length + 255
  AckMessageEIP8Length* = 215 + 2
  AckMessageMaxEIP8* = AckMessageEIP8Length + 255

type
  Nonce* = array[KeyLength, byte]

  AuthMessageV4* {.packed.} = object
    signature: array[RawSignatureSize, byte]
    keyhash: array[keccak256.sizeDigest, byte]
    pubkey: array[RawPublicKeySize, byte]
    nonce: array[keccak256.sizeDigest, byte]
    flag: byte

  AckMessageV4* {.packed.} = object
    pubkey: array[RawPublicKeySize, byte]
    nonce: array[keccak256.sizeDigest, byte]
    flag: byte

  HandshakeFlag* = enum
    Initiator,      ## `Handshake` owner is connection initiator
    Responder,      ## `Handshake` owner is connection responder
    EIP8            ## Flag indicates that EIP-8 handshake is used

  AuthError* = enum
    EcdhError       = "auth: ECDH shared secret could not be calculated"
    BufferOverrun   = "auth: buffer overrun"
    SignatureError  = "auth: signature could not be obtained"
    EciesError      = "auth: ECIES encryption/decryption error"
    InvalidPubKey   = "auth: invalid public key"
    InvalidAuth     = "auth: invalid Authentication message"
    InvalidAck      = "auth: invalid Authentication ACK message"
    RlpError        = "auth: error while decoding RLP stream"
    IncompleteError = "auth: data incomplete"

  Handshake* = object
    version*: uint8             ## protocol version
    flags*: set[HandshakeFlag]  ## handshake flags
    host*: KeyPair              ## host keypair
    ephemeral*: KeyPair         ## ephemeral host keypair
    remoteHPubkey*: PublicKey   ## remote host public key
    remoteEPubkey*: PublicKey   ## remote host ephemeral public key
    initiatorNonce*: Nonce      ## initiator nonce
    responderNonce*: Nonce      ## responder nonce
    expectedLength*: int        ## expected incoming message length

  ConnectionSecret* = object
    aesKey*: array[aes256.sizeKey, byte]
    macKey*: array[KeyLength, byte]
    egressMac*: keccak256
    ingressMac*: keccak256

  AuthResult*[T] = Result[T, AuthError]

template toa(a, b, c: untyped): untyped =
  toOpenArray((a), (b), (b) + (c) - 1)

proc `xor`[N: static int](a, b: array[N, byte]): array[N, byte] =
  for i in 0 ..< len(a):
    result[i] = a[i] xor b[i]

proc mapErrTo[T, E](r: Result[T, E], v: static AuthError): AuthResult[T] =
  r.mapErr(proc (e: E): AuthError = v)

proc tryInit*(
    T: type Handshake, rng: var BrHmacDrbgContext, host: KeyPair,
    flags: set[HandshakeFlag] = {Initiator},
    version: uint8 = SupportedRlpxVersion): AuthResult[T] =
  ## Create new `Handshake` object.

  var
    initiatorNonce: Nonce
    responderNonce: Nonce
    expectedLength: int
    ephemeral = KeyPair.random(rng)

  if Initiator in flags:
    expectedLength = AckMessageV4Length
    brHmacDrbgGenerate(rng, initiatorNonce)
  else:
    expectedLength = AuthMessageV4Length
    brHmacDrbgGenerate(rng, responderNonce)

  return ok(T(
    version: version,
    flags: flags,
    host: host,
    ephemeral: ephemeral,
    initiatorNonce: initiatorNonce,
    responderNonce: responderNonce,
    expectedLength: expectedLength
  ))

proc authMessagePreEIP8(h: var Handshake,
                        rng: var BrHmacDrbgContext,
                        pubkey: PublicKey,
                        output: var openArray[byte],
                        outlen: var int,
                        flag: byte = 0,
                        encrypt: bool = true): AuthResult[void] =
  ## Create plain pre-EIP8 authentication message.
  var
    buffer: array[PlainAuthMessageV4Length, byte]
  outlen = 0
  let header = cast[ptr AuthMessageV4](addr buffer[0])

  var secret = ecdhRaw(h.host.seckey, pubkey)
  secret.data = secret.data xor h.initiatorNonce

  let signature = sign(h.ephemeral.seckey, SkMessage(secret.data))
  secret.clear()

  h.remoteHPubkey = pubkey
  header.signature = signature.toRaw()
  header.keyhash = keccak256.digest(h.ephemeral.pubkey.toRaw()).data
  header.pubkey = h.host.pubkey.toRaw()
  header.nonce = h.initiatorNonce
  header.flag = flag
  if encrypt:
    if len(output) < AuthMessageV4Length:
      return err(BufferOverrun)
    if eciesEncrypt(rng, buffer, output, h.remoteHPubkey).isErr:
      return err(EciesError)
    outlen = AuthMessageV4Length
  else:
    if len(output) < PlainAuthMessageV4Length:
      return err(BufferOverrun)
    copyMem(addr output[0], addr buffer[0], PlainAuthMessageV4Length)
    outlen = PlainAuthMessageV4Length

  ok()

proc authMessageEIP8(h: var Handshake,
                     rng: var BrHmacDrbgContext,
                     pubkey: PublicKey,
                     output: var openArray[byte],
                     outlen: var int,
                     flag: byte = 0,
                     encrypt: bool = true): AuthResult[void] =
  ## Create EIP8 authentication message.
  var
    buffer: array[PlainAuthMessageMaxEIP8, byte]
    padsize: array[1, byte]

  doAssert(EIP8 in h.flags)
  outlen = 0

  var secret = ecdhRaw(h.host.seckey, pubkey)
  secret.data = secret.data xor h.initiatorNonce

  let signature = sign(h.ephemeral.seckey, SkMessage(secret.data))
  secret.clear()

  h.remoteHPubkey = pubkey
  var payload = rlp.encodeList(signature.toRaw(),
                               h.host.pubkey.toRaw(),
                               h.initiatorNonce,
                               [byte(h.version)])
  doAssert(len(payload) == PlainAuthMessageEIP8Length)
  let
    pencsize = eciesEncryptedLength(len(payload))

  while true:
    brHmacDrbgGenerate(rng, padsize)
    if int(padsize[0]) > (AuthMessageV4Length - (pencsize + 2)):
      break
  # It is possible to make packet size constant by uncommenting this line
  # padsize = 24
  let wosize = pencsize + int(padsize[0])
  let fullsize = wosize + 2
  brHmacDrbgGenerate(
    rng, toa(buffer, PlainAuthMessageEIP8Length, int(padsize[0])))
  if encrypt:
    copyMem(addr buffer[0], addr payload[0], len(payload))
    if len(output) < fullsize:
      return err(BufferOverrun)
    let wosizeBE = uint16(wosize).toBytesBE()
    output[0..<2] = wosizeBE
    if eciesEncrypt(rng, toa(buffer, 0, len(payload) + int(padsize[0])),
                    toa(output, 2, wosize), pubkey,
                    toa(output, 0, 2)).isErr:
      return err(EciesError)
    outlen = fullsize
  else:
    let plainsize = len(payload) + int(padsize[0])
    if len(output) < plainsize:
      return err(BufferOverrun)
    copyMem(addr output[0], addr buffer[0], plainsize)
    outlen = plainsize

  ok()

proc ackMessagePreEIP8(h: var Handshake,
                       rng: var BrHmacDrbgContext,
                       output: var openArray[byte],
                       outlen: var int,
                       flag: byte = 0,
                       encrypt: bool = true): AuthResult[void] =
  ## Create plain pre-EIP8 authentication ack message.
  var buffer: array[PlainAckMessageV4Length, byte]
  outlen = 0
  let header = cast[ptr AckMessageV4](addr buffer[0])
  header.pubkey = h.ephemeral.pubkey.toRaw()
  header.nonce = h.responderNonce
  header.flag = flag
  if encrypt:
    if len(output) < AckMessageV4Length:
      return err(BufferOverrun)
    if eciesEncrypt(rng, buffer, output, h.remoteHPubkey).isErr:
      return err(EciesError)
    outlen = AckMessageV4Length
  else:
    if len(output) < PlainAckMessageV4Length:
      return err(BufferOverrun)
    copyMem(addr output[0], addr buffer[0], PlainAckMessageV4Length)
    outlen = PlainAckMessageV4Length

  ok()

proc ackMessageEIP8(h: var Handshake,
                    rng: var BrHmacDrbgContext,
                    output: var openArray[byte],
                    outlen: var int,
                    flag: byte = 0,
                    encrypt: bool = true): AuthResult[void] =
  ## Create EIP8 authentication ack message.
  var
    buffer: array[PlainAckMessageMaxEIP8, byte]
    padsize: array[1, byte]
  doAssert(EIP8 in h.flags)
  var payload = rlp.encodeList(h.ephemeral.pubkey.toRaw(),
                               h.responderNonce,
                               [byte(h.version)])
  doAssert(len(payload) == PlainAckMessageEIP8Length)
  outlen = 0
  let pencsize = eciesEncryptedLength(len(payload))
  while true:
    brHmacDrbgGenerate(rng, padsize)
    if int(padsize[0]) > (AckMessageV4Length - (pencsize + 2)):
      break
  # It is possible to make packet size constant by uncommenting this line
  # padsize = 0
  let wosize = pencsize + int(padsize[0])
  let fullsize = wosize + 2
  if int(padsize[0]) > 0:
    brHmacDrbgGenerate(
      rng, toa(buffer, PlainAckMessageEIP8Length, int(padsize[0])))

  copyMem(addr buffer[0], addr payload[0], len(payload))
  if encrypt:
    if len(output) < fullsize:
      return err(BufferOverrun)
    output[0..<2] = uint16(wosize).toBytesBE()
    if eciesEncrypt(rng, toa(buffer, 0, len(payload) + int(padsize[0])),
                    toa(output, 2, wosize), h.remoteHPubkey,
                    toa(output, 0, 2)).isErr:
      return err(EciesError)
    outlen = fullsize
  else:
    let plainsize = len(payload) + int(padsize[0])
    if len(output) < plainsize:
      return err(BufferOverrun)
    copyMem(addr output[0], addr buffer[0], plainsize)
    outlen = plainsize

  ok()

template authSize*(h: Handshake, encrypt: bool = true): int =
  ## Get number of bytes needed to store AuthMessage.
  if EIP8 in h.flags:
    if encrypt: (AuthMessageMaxEIP8) else: (PlainAuthMessageMaxEIP8)
  else:
    if encrypt: (AuthMessageV4Length) else: (PlainAuthMessageV4Length)

template ackSize*(h: Handshake, encrypt: bool = true): int =
  ## Get number of bytes needed to store AckMessage.
  if EIP8 in h.flags:
    if encrypt: (AckMessageMaxEIP8) else: (PlainAckMessageMaxEIP8)
  else:
    if encrypt: (AckMessageV4Length) else: (PlainAckMessageV4Length)

proc authMessage*(h: var Handshake, rng: var BrHmacDrbgContext,
                  pubkey: PublicKey,
                  output: var openArray[byte],
                  outlen: var int, flag: byte = 0,
                  encrypt: bool = true): AuthResult[void] =
  ## Create new AuthMessage for specified `pubkey` and store it inside
  ## of `output`, size of generated AuthMessage will stored in `outlen`.
  if EIP8 in h.flags:
    authMessageEIP8(h, rng, pubkey, output, outlen, flag, encrypt)
  else:
    authMessagePreEIP8(h, rng, pubkey, output, outlen, flag, encrypt)

proc ackMessage*(h: var Handshake, rng: var BrHmacDrbgContext,
                 output: var openArray[byte],
                 outlen: var int, flag: byte = 0,
                 encrypt: bool = true): AuthResult[void] =
  ## Create new AckMessage and store it inside of `output`, size of generated
  ## AckMessage will stored in `outlen`.
  if EIP8 in h.flags:
    ackMessageEIP8(h, rng, output, outlen, flag, encrypt)
  else:
    ackMessagePreEIP8(h, rng, output, outlen, flag, encrypt)

proc decodeAuthMessageV4(h: var Handshake, m: openArray[byte]): AuthResult[void] =
  ## Decodes V4 AuthMessage.
  var
    buffer: array[PlainAuthMessageV4Length, byte]

  doAssert(Responder in h.flags)
  if eciesDecrypt(m, buffer, h.host.seckey).isErr:
    return err(EciesError)

  let
    header = cast[ptr AuthMessageV4](addr buffer[0])
    pubkey = ? PublicKey.fromRaw(header.pubkey).mapErrTo(InvalidPubKey)
    signature = ? Signature.fromRaw(header.signature).mapErrTo(SignatureError)

  var secret = ecdhRaw(h.host.seckey, pubkey)
  secret.data = secret.data xor header.nonce

  var recovered = recover(signature, SkMessage(secret.data))
  secret.clear()

  h.remoteEPubkey = ? recovered.mapErrTo(SignatureError)
  h.initiatorNonce = header.nonce
  h.remoteHPubkey = pubkey

  ok()

proc decodeAuthMessageEIP8(h: var Handshake, m: openArray[byte]): AuthResult[void] =
  ## Decodes EIP-8 AuthMessage.
  let size = uint16.fromBytesBE(m)
  h.expectedLength = int(size) + 2
  if h.expectedLength > len(m):
    return err(IncompleteError)
  var buffer = newSeq[byte](eciesDecryptedLength(int(size)))
  if eciesDecrypt(toa(m, 2, int(size)), buffer, h.host.seckey,
                  toa(m, 0, 2)).isErr:
    return err(EciesError)
  try:
    var reader = rlpFromBytes(buffer)
    if not reader.isList() or reader.listLen() < 4:
      return err(InvalidAuth)
    if reader.listElem(0).blobLen != RawSignatureSize:
      return err(InvalidAuth)
    if reader.listElem(1).blobLen != RawPublicKeySize:
      return err(InvalidAuth)
    if reader.listElem(2).blobLen != KeyLength:
      return err(InvalidAuth)
    if reader.listElem(3).blobLen != 1:
      return err(InvalidAuth)
    let
      signatureBr = reader.listElem(0).toBytes()
      pubkeyBr = reader.listElem(1).toBytes()
      nonceBr = reader.listElem(2).toBytes()
      versionBr = reader.listElem(3).toBytes()

    let
      signature = ? Signature.fromRaw(signatureBr).mapErrTo(SignatureError)
      pubkey = ? PublicKey.fromRaw(pubkeyBr).mapErrTo(InvalidPubKey)
      nonce = toArray(KeyLength, nonceBr)

    var secret = ecdhRaw(h.host.seckey, pubkey)
    secret.data = secret.data xor nonce

    let recovered = recover(signature, SkMessage(secret.data))
    secret.clear()

    h.remoteEPubkey = ? recovered.mapErrTo(SignatureError)
    h.initiatorNonce = nonce
    h.remoteHPubkey = pubkey
    h.version = versionBr[0]
    ok()
  except CatchableError:
    err(RlpError)

proc decodeAckMessageEIP8*(h: var Handshake, m: openArray[byte]): AuthResult[void] =
  ## Decodes EIP-8 AckMessage.
  let size = uint16.fromBytesBE(m)

  h.expectedLength = 2 + int(size)
  if h.expectedLength > len(m):
    return err(IncompleteError)
  var buffer = newSeq[byte](eciesDecryptedLength(int(size)))
  if eciesDecrypt(toa(m, 2, int(size)), buffer, h.host.seckey,
                  toa(m, 0, 2)).isErr:
    return err(EciesError)
  try:
    var reader = rlpFromBytes(buffer)
    if not reader.isList() or reader.listLen() < 3:
      return err(InvalidAck)
    if reader.listElem(0).blobLen != RawPublicKeySize:
      return err(InvalidAck)
    if reader.listElem(1).blobLen != KeyLength:
      return err(InvalidAck)
    if reader.listElem(2).blobLen != 1:
      return err(InvalidAck)
    let
      pubkeyBr = reader.listElem(0).toBytes()
      nonceBr = reader.listElem(1).toBytes()
      versionBr = reader.listElem(2).toBytes()

    h.remoteEPubkey = ? PublicKey.fromRaw(pubkeyBr).mapErrTo(InvalidPubKey)
    h.responderNonce = toArray(KeyLength, nonceBr)
    h.version = versionBr[0]

    ok()
  except CatchableError:
    err(RlpError)

proc decodeAckMessageV4(h: var Handshake, m: openArray[byte]): AuthResult[void] =
  ## Decodes V4 AckMessage.
  var
    buffer: array[PlainAckMessageV4Length, byte]
  doAssert(Initiator in h.flags)

  if eciesDecrypt(m, buffer, h.host.seckey).isErr:
    return err(EciesError)
  var header = cast[ptr AckMessageV4](addr buffer[0])

  h.remoteEPubkey = ? PublicKey.fromRaw(header.pubkey).mapErrTo(InvalidPubKey)
  h.responderNonce = header.nonce

  ok()

proc decodeAuthMessage*(h: var Handshake, input: openArray[byte]): AuthResult[void] =
  ## Decodes AuthMessage from `input`.
  if len(input) < AuthMessageV4Length:
    return err(IncompleteError)

  if len(input) == AuthMessageV4Length:
    let res = h.decodeAuthMessageV4(input)
    if res.isOk(): return res

  let res = h.decodeAuthMessageEIP8(input)
  if res.isOk():
    h.flags.incl(EIP8)
  res

proc decodeAckMessage*(h: var Handshake, input: openArray[byte]): AuthResult[void] =
  ## Decodes AckMessage from `input`.
  if len(input) < AckMessageV4Length:
    return err(IncompleteError)
  if len(input) == AckMessageV4Length:
    let res = h.decodeAckMessageV4(input)
    if res.isOk(): return res

  let res = h.decodeAckMessageEIP8(input)
  if res.isOk(): h.flags.incl(EIP8)
  res

proc getSecrets*(
  h: Handshake, authmsg: openArray[byte],
  ackmsg: openArray[byte]): ConnectionSecret =
  ## Derive secrets from handshake `h` using encrypted AuthMessage `authmsg` and
  ## encrypted AckMessage `ackmsg`.
  var
    ctx0: keccak256
    ctx1: keccak256
    mac1: MDigest[256]
    secret: ConnectionSecret

  # ecdhe-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
  var shsec = ecdhRaw(h.ephemeral.seckey, h.remoteEPubkey)

  # shared-secret = keccak(ecdhe-secret || keccak(nonce || initiator-nonce))
  ctx0.init()
  ctx1.init()
  ctx1.update(h.responderNonce)
  ctx1.update(h.initiatorNonce)
  mac1 = ctx1.finish()
  ctx1.clear()
  ctx0.update(shsec.data)
  ctx0.update(mac1.data)
  mac1 = ctx0.finish()

  # aes-secret = keccak(ecdhe-secret || shared-secret)
  ctx0.init()
  ctx0.update(shsec.data)
  ctx0.update(mac1.data)
  mac1 = ctx0.finish()

  # mac-secret = keccak(ecdhe-secret || aes-secret)
  ctx0.init()
  ctx0.update(shsec.data)
  ctx0.update(mac1.data)
  secret.aesKey = mac1.data
  mac1 = ctx0.finish()
  secret.macKey = mac1.data

  clear(shsec)

  # egress-mac = keccak256(mac-secret ^ recipient-nonce || auth-sent-init)

  var xornonce = mac1.data xor h.responderNonce
  ctx0.init()
  ctx0.update(xornonce)
  ctx0.update(authmsg)

  # ingress-mac = keccak256(mac-secret ^ initiator-nonce || auth-recvd-ack)
  xornonce = secret.macKey xor h.initiatorNonce

  ctx1.init()
  ctx1.update(xornonce)
  ctx1.update(ackmsg)
  burnMem(xornonce)

  if Initiator in h.flags:
    secret.egressMac = ctx0
    secret.ingressMac = ctx1
  else:
    secret.ingressMac = ctx0
    secret.egressMac = ctx1

  ctx0.clear()
  ctx1.clear()

  secret
