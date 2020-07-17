import
  std/[tables, options],
  nimcrypto, stint, chronicles, stew/results, bearssl,
  eth/[rlp, keys], types, node, enr, hkdf

export keys

{.push raises: [Defect].}

const
  idNoncePrefix = "discovery-id-nonce"
  keyAgreementPrefix = "discovery v5 key agreement"
  authSchemeName* = "gcm"
  gcmNonceSize* = 12
  gcmTagSize* = 16
  tagSize* = 32 ## size of the tag where each message (except whoareyou) starts
  ## with

type
  PacketTag* = array[tagSize, byte]

  AuthResponse = object
    version: int
    signature: array[64, byte]
    record: Option[enr.Record]

  Codec* = object
    localNode*: Node
    privKey*: PrivateKey
    db*: Database
    handshakes*: Table[HandShakeKey, Whoareyou]

  HandshakeSecrets = object
    writeKey: AesKey
    readKey: AesKey
    authRespKey: AesKey

  AuthHeader* = object
    auth*: AuthTag
    idNonce*: IdNonce
    scheme*: string
    ephemeralKey*: array[64, byte]
    response*: seq[byte]

  DecodeError* = enum
    HandshakeError = "discv5: handshake failed"
    PacketError = "discv5: invalid packet"
    DecryptError = "discv5: decryption failed"
    UnsupportedMessage = "discv5: unsupported message"

  DecodeResult*[T] = Result[T, DecodeError]
  EncodeResult*[T] = Result[T, cstring]

proc mapErrTo[T, E](r: Result[T, E], v: static DecodeError):
    DecodeResult[T] =
  r.mapErr(proc (e: E): DecodeError = v)

proc idNonceHash(nonce, ephkey: openarray[byte]): MDigest[256] =
  var ctx: sha256
  ctx.init()
  ctx.update(idNoncePrefix)
  ctx.update(nonce)
  ctx.update(ephkey)
  result = ctx.finish()
  ctx.clear()

proc signIDNonce*(privKey: PrivateKey, idNonce, ephKey: openarray[byte]):
    SignatureNR =
  signNR(privKey, SkMessage(idNonceHash(idNonce, ephKey).data))

proc deriveKeys(n1, n2: NodeID, priv: PrivateKey, pub: PublicKey,
    idNonce: openarray[byte]): HandshakeSecrets =
  let eph = ecdhRawFull(priv, pub)

  var info = newSeqOfCap[byte](idNoncePrefix.len + 32 * 2)
  for i, c in keyAgreementPrefix: info.add(byte(c))
  info.add(n1.toByteArrayBE())
  info.add(n2.toByteArrayBE())

  var secrets: HandshakeSecrets
  static: assert(sizeof(secrets) == aesKeySize * 3)
  var res = cast[ptr UncheckedArray[byte]](addr secrets)
  hkdf(sha256, eph.data, idNonce, info, toOpenArray(res, 0, sizeof(secrets) - 1))
  secrets

proc encryptGCM*(key, nonce, pt, authData: openarray[byte]): seq[byte] =
  var ectx: GCM[aes128]
  ectx.init(key, nonce, authData)
  result = newSeq[byte](pt.len + gcmTagSize)
  ectx.encrypt(pt, result)
  ectx.getTag(result.toOpenArray(pt.len, result.high))
  ectx.clear()

proc encodeAuthHeader*(rng: var BrHmacDrbgContext,
                      c: Codec,
                      toId: NodeID,
                      nonce: array[gcmNonceSize, byte],
                      challenge: Whoareyou):
                      (seq[byte], HandshakeSecrets) =
  ## Encodes the auth-header, which is required for the packet in response to a
  ## WHOAREYOU packet. Requires the id-nonce and the enr-seq that were in the
  ## WHOAREYOU packet, and the public key of the node sending it.
  var resp = AuthResponse(version: 5)
  let ln = c.localNode

  if challenge.recordSeq < ln.record.seqNum:
    resp.record = some(ln.record)
  else:
    resp.record = none(enr.Record)

  let ephKeys = KeyPair.random(rng)
  let signature = signIDNonce(c.privKey, challenge.idNonce,
    ephKeys.pubkey.toRaw)
  resp.signature = signature.toRaw

  # Calling `encodePacket` for handshake should always be with a challenge
  # with the pubkey of the node we are targetting.
  doAssert(challenge.pubKey.isSome())
  let secrets = deriveKeys(ln.id, toId, ephKeys.seckey, challenge.pubKey.get(),
    challenge.idNonce)

  let respRlp = rlp.encode(resp)

  var zeroNonce: array[gcmNonceSize, byte]
  let respEnc = encryptGCM(secrets.authRespKey, zeroNonce, respRlp, [])

  let header = AuthHeader(auth: nonce, idNonce: challenge.idNonce,
    scheme: authSchemeName, ephemeralKey: ephKeys.pubkey.toRaw,
    response: respEnc)
  (rlp.encode(header), secrets)

proc `xor`[N: static[int], T](a, b: array[N, T]): array[N, T] =
  for i in 0 .. a.high:
    result[i] = a[i] xor b[i]

proc packetTag(destNode, srcNode: NodeID): PacketTag =
  let
    destId = destNode.toByteArrayBE()
    srcId = srcNode.toByteArrayBE()
    destidHash = sha256.digest(destId)
  result = srcId xor destidHash.data

proc encodePacket*(
    rng: var BrHmacDrbgContext,
    c: Codec,
    toId: NodeID,
    toAddr: Address,
    message: openarray[byte],
    challenge: Whoareyou):
    (seq[byte], array[gcmNonceSize, byte]) =
  ## Encode a packet. This can be a regular packet or a packet in response to a
  ## WHOAREYOU packet. The latter is the case when the `challenge` parameter is
  ## provided.
  var nonce: array[gcmNonceSize, byte]
  brHmacDrbgGenerate(rng, nonce)

  let tag = packetTag(toId, c.localNode.id)
  var packet: seq[byte]
  packet.add(tag)

  if challenge.isNil:
    # Message packet or random packet
    let headEnc = rlp.encode(nonce)
    packet.add(headEnc)

    # TODO: Should we change API to get just the key we need?
    var writeKey, readKey: AesKey
    # We might not have the node's keys if the handshake hasn't been performed
    # yet. That's fine, we will be responded with whoareyou.
    if c.db.loadKeys(toId, toAddr, readKey, writeKey):
      packet.add(encryptGCM(writeKey, nonce, message, tag))
    else:
      # We might not have the node's keys if the handshake hasn't been performed
      # yet. That's fine, we send a random-packet and we will be responded with
      # a WHOAREYOU packet.
      var randomData: array[44, byte]
      brHmacDrbgGenerate(rng, randomData)
      packet.add(randomData)

  else:
    # Handshake
    let (headEnc, secrets) = encodeAuthHeader(rng, c, toId, nonce, challenge)
    packet.add(headEnc)

    if not c.db.storeKeys(toId, toAddr, secrets.readKey, secrets.writeKey):
      warn "Storing of keys for session failed, will have to redo a handshake"

    packet.add(encryptGCM(secrets.writeKey, nonce, message, tag))

  (packet, nonce)

proc decryptGCM*(key: AesKey, nonce, ct, authData: openarray[byte]):
    Option[seq[byte]] =
  if ct.len <= gcmTagSize:
    debug "cipher is missing tag", len = ct.len
    return

  var dctx: GCM[aes128]
  dctx.init(key, nonce, authData)
  var res = newSeq[byte](ct.len - gcmTagSize)
  var tag: array[gcmTagSize, byte]
  dctx.decrypt(ct.toOpenArray(0, ct.high - gcmTagSize), res)
  dctx.getTag(tag)
  dctx.clear()

  if tag != ct.toOpenArray(ct.len - gcmTagSize, ct.high):
    return

  return some(res)

proc decodeMessage(body: openarray[byte]): DecodeResult[Message] =
  ## Decodes to the specific `Message` type.
  if body.len < 1:
    return err(PacketError)

  if body[0] < MessageKind.low.byte or body[0] > MessageKind.high.byte:
    return err(PacketError)

  # This cast is covered by the above check (else we could get enum with invalid
  # data!). However, can't we do this in a cleaner way?
  let kind = cast[MessageKind](body[0])
  var message = Message(kind: kind)
  var rlp = rlpFromBytes(body.toOpenArray(1, body.high))
  if rlp.enterList:
    try:
      message.reqId = rlp.read(RequestId)
    except RlpError:
      return err(PacketError)

    proc decode[T](rlp: var Rlp, v: var T)
        {.inline, nimcall, raises:[RlpError, ValueError, Defect].} =
      for k, v in v.fieldPairs:
        v = rlp.read(typeof(v))

    try:
      case kind
      of unused: return err(PacketError)
      of ping: rlp.decode(message.ping)
      of pong: rlp.decode(message.pong)
      of findNode: rlp.decode(message.findNode)
      of nodes: rlp.decode(message.nodes)
      of regtopic, ticket, regconfirmation, topicquery:
        # TODO: Implement support for topic advertisement
        return err(UnsupportedMessage)
    except RlpError, ValueError:
      return err(PacketError)

    ok(message)
  else:
    err(PacketError)

proc decodeAuthResp*(c: Codec, fromId: NodeId, head: AuthHeader,
    challenge: Whoareyou, newNode: var Node): DecodeResult[HandshakeSecrets] =
  ## Decrypts and decodes the auth-response, which is part of the auth-header.
  ## Requires the id-nonce from the WHOAREYOU packet that was send.
  ## newNode can be nil in case node was already known (no was ENR send).
  if head.scheme != authSchemeName:
    warn "Unknown auth scheme"
    return err(HandshakeError)

  let ephKey = ? PublicKey.fromRaw(head.ephemeralKey).mapErrTo(HandshakeError)

  let secrets =
    deriveKeys(fromId, c.localNode.id, c.privKey, ephKey, challenge.idNonce)

  var zeroNonce: array[gcmNonceSize, byte]
  let respData = decryptGCM(secrets.authRespKey, zeroNonce, head.response, [])
  if respData.isNone():
    return err(HandshakeError)

  var authResp: AuthResponse
  try:
    # Signature check of record happens in decode.
    authResp = rlp.decode(respData.get(), AuthResponse)
  except RlpError, ValueError:
    return err(HandshakeError)

  var pubKey: PublicKey
  if authResp.record.isSome():
    # Node returned might not have an address or not a valid address.
    newNode = ? newNode(authResp.record.get()).mapErrTo(HandshakeError)
    if newNode.id != fromId:
      return err(HandshakeError)

    pubKey = newNode.pubKey
  else:
    if challenge.pubKey.isSome():
      pubKey = challenge.pubKey.get()
    else:
      # We should have received a Record in this case.
      return err(HandshakeError)

  # Verify the id-nonce-sig
  let sig = ? SignatureNR.fromRaw(authResp.signature).mapErrTo(HandshakeError)
  let h = idNonceHash(head.idNonce, head.ephemeralKey)
  if verify(sig, SkMessage(h.data), pubkey):
    ok(secrets)
  else:
    err(HandshakeError)

proc decodePacket*(c: var Codec,
                      fromId: NodeID,
                      fromAddr: Address,
                      input: openArray[byte],
                      authTag: var AuthTag,
                      newNode: var Node): DecodeResult[Message] =
  ## Decode a packet. This can be a regular packet or a packet in response to a
  ## WHOAREYOU packet. In case of the latter a `newNode` might be provided.
  var r = rlpFromBytes(input.toOpenArray(tagSize, input.high))
  var auth: AuthHeader

  var readKey: AesKey
  logScope: sender = $fromAddr

  if r.isList:
    # Handshake - rlp list indicates auth-header
    try:
      auth = r.read(AuthHeader)
    except RlpError:
      return err(PacketError)
    authTag = auth.auth

    let key = HandShakeKey(nodeId: fromId, address: $fromAddr)
    let challenge = c.handshakes.getOrDefault(key)
    if challenge.isNil:
      trace "Decoding failed (no challenge)"
      return err(HandshakeError)

    if auth.idNonce != challenge.idNonce:
      trace "Decoding failed (different nonce)"
      return err(HandshakeError)

    let secrets = c.decodeAuthResp(fromId, auth, challenge, newNode)
    if secrets.isErr:
      trace "Decoding failed (invalid auth response)"
      return err(HandshakeError)
    var sec = secrets[]

    c.handshakes.del(key)

    # Swap keys to match remote
    swap(sec.readKey, sec.writeKey)
    if not c.db.storeKeys(fromId, fromAddr, sec.readKey, sec.writeKey):
      warn "Storing of keys for session failed, will have to redo a handshake"
    readKey = sec.readKey
  else:
    # Message packet or random packet - rlp bytes (size 12) indicates auth-tag
    try:
      authTag = r.read(AuthTag)
    except RlpError:
      return err(PacketError)
    auth.auth = authTag
    # TODO: Should we change API to get just the key we need?
    var writeKey: AesKey
    if not c.db.loadKeys(fromId, fromAddr, readKey, writeKey):
      trace "Decoding failed (no keys)"
      return err(DecryptError)

  let headSize = tagSize + r.position

  let message = decryptGCM(
    readKey, auth.auth,
    input.toOpenArray(headSize, input.high),
    input.toOpenArray(0, tagSize - 1))
  if message.isNone():
    discard c.db.deleteKeys(fromId, fromAddr)
    return err(DecryptError)

  decodeMessage(message.get())

proc init*(T: type RequestId, rng: var BrHmacDrbgContext): T =
  var buf: array[sizeof(T), byte]
  brHmacDrbgGenerate(rng, buf)
  var id: T
  copyMem(addr id, addr buf[0], sizeof(id))
  id

proc numFields(T: typedesc): int =
  for k, v in fieldPairs(default(T)): inc result

proc encodeMessage*[T: SomeMessage](p: T, reqId: RequestId): seq[byte] =
  result = newSeqOfCap[byte](64)
  result.add(messageKind(T).ord)

  const sz = numFields(T)
  var writer = initRlpList(sz + 1)
  writer.append(reqId)
  for k, v in fieldPairs(p):
    writer.append(v)
  result.add(writer.finish())
