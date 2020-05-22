import
  std/[tables, options], nimcrypto, stint, chronicles, chronos, stew/results,
  types, node, enr, hkdf, eth/[rlp, keys]

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
    record: Record

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
    HandshakeError = "discv5: handshake failed",
    PacketError = "discv5: invalid packet",
    DecryptError = "discv5: decryption failed",
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
  ctx.finish()

proc signIDNonce*(privKey: PrivateKey, idNonce, ephKey: openarray[byte]):
    Result[SignatureNR, cstring] =
  signNR(privKey, idNonceHash(idNonce, ephKey))

proc deriveKeys(n1, n2: NodeID, priv: PrivateKey, pub: PublicKey,
    idNonce: openarray[byte]): Result[HandshakeSecrets, cstring] =
  let eph = ? ecdhRawFull(priv, pub)

  var info = newSeqOfCap[byte](idNoncePrefix.len + 32 * 2)
  for i, c in keyAgreementPrefix: info.add(byte(c))
  info.add(n1.toByteArrayBE())
  info.add(n2.toByteArrayBE())

  var secrets: HandshakeSecrets
  static: assert(sizeof(secrets) == aesKeySize * 3)
  var res = cast[ptr UncheckedArray[byte]](addr secrets)
  hkdf(sha256, eph.data, idNonce, info, toOpenArray(res, 0, sizeof(secrets) - 1))
  ok(secrets)

proc encryptGCM*(key, nonce, pt, authData: openarray[byte]): seq[byte] =
  var ectx: GCM[aes128]
  ectx.init(key, nonce, authData)
  result = newSeq[byte](pt.len + gcmTagSize)
  ectx.encrypt(pt, result)
  ectx.getTag(result.toOpenArray(pt.len, result.high))
  ectx.clear()

proc encodeAuthHeader(c: Codec,
                      toId: NodeID,
                      nonce: array[gcmNonceSize, byte],
                      challenge: Whoareyou):
                      EncodeResult[(seq[byte], HandshakeSecrets)] =
  var resp = AuthResponse(version: 5)
  let ln = c.localNode

  # TODO: What goes over the wire now in case of no updated ENR?
  if challenge.recordSeq < ln.record.seqNum:
    resp.record = ln.record

  let ephKeys = ? KeyPair.random()
  let signature = ? signIDNonce(c.privKey, challenge.idNonce,
    ephKeys.pubkey.toRaw)
  resp.signature = signature.toRaw

  let secrets = ? deriveKeys(ln.id, toId, ephKeys.seckey, challenge.pubKey,
    challenge.idNonce)

  let respRlp = rlp.encode(resp)

  var zeroNonce: array[gcmNonceSize, byte]
  let respEnc = encryptGCM(secrets.authRespKey, zeroNonce, respRLP, [])

  let header = AuthHeader(auth: nonce, idNonce: challenge.idNonce,
    scheme: authSchemeName, ephemeralKey: ephKeys.pubkey.toRaw,
    response: respEnc)
  ok((rlp.encode(header), secrets))

proc `xor`[N: static[int], T](a, b: array[N, T]): array[N, T] =
  for i in 0 .. a.high:
    result[i] = a[i] xor b[i]

proc packetTag(destNode, srcNode: NodeID): PacketTag =
  let
    destId = destNode.toByteArrayBE()
    srcId = srcNode.toByteArrayBE()
    destidHash = sha256.digest(destId)
  result = srcId xor destidHash.data

proc encodePacket*(c: Codec,
                      toId: NodeID,
                      toAddr: Address,
                      message: openarray[byte],
                      challenge: Whoareyou):
                      EncodeResult[(seq[byte], array[gcmNonceSize, byte])] =
  var nonce: array[gcmNonceSize, byte]
  if randomBytes(nonce) != nonce.len:
    return err("Could not randomize bytes")

  var headEnc: seq[byte]

  var writeKey: AesKey

  if challenge.isNil:
    headEnc = rlp.encode(nonce)
    var readKey: AesKey

    # We might not have the node's keys if the handshake hasn't been performed
    # yet. That's fine, we will be responded with whoareyou.
    discard c.db.loadKeys(toId, toAddr, readKey, writeKey)
  else:
    var secrets: HandshakeSecrets
    (headEnc, secrets) = ? c.encodeAuthHeader(toId, nonce, challenge)

    writeKey = secrets.writeKey
    # TODO: is it safe to ignore the error here?
    discard c.db.storeKeys(toId, toAddr, secrets.readKey, secrets.writeKey)

  let tag = packetTag(toId, c.localNode.id)

  var packet = newSeqOfCap[byte](tag.len + headEnc.len)
  packet.add(tag)
  packet.add(headEnc)
  packet.add(encryptGCM(writeKey, nonce, message, tag))
  ok((packet, nonce))

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

proc decodeMessage(body: openarray[byte]):
    DecodeResult[Message] {.raises:[Defect].} =
  if body.len < 1:
    return err(PacketError)

  if body[0] < MessageKind.low.byte or body[0] > MessageKind.high.byte:
    return err(PacketError)

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

proc decodeAuthResp(c: Codec, fromId: NodeId, head: AuthHeader,
    challenge: Whoareyou, secrets: var HandshakeSecrets, newNode: var Node):
    DecodeResult[void] {.raises:[Defect].} =
  if head.scheme != authSchemeName:
    warn "Unknown auth scheme"
    return err(HandshakeError)

  let ephKey = ? PublicKey.fromRaw(head.ephemeralKey).mapErrTo(HandshakeError)

  secrets = ? deriveKeys(fromId, c.localNode.id, c.privKey, ephKey,
    challenge.idNonce).mapErrTo(HandshakeError)

  var zeroNonce: array[gcmNonceSize, byte]
  let respData = decryptGCM(secrets.authRespKey, zeroNonce, head.response, [])
  if respData.isNone():
    return err(HandshakeError)

  var authResp: AuthResponse
  try:
    authResp = rlp.decode(respData.get(), AuthResponse)
  except RlpError, ValueError:
    return err(HandshakeError)
  # TODO:
  # 1. Should allow for not having an ENR included, solved for now by sending
  # whoareyou with always recordSeq of 0
  # 2. Should verify ENR and check for correct id in case an ENR is included
  # 3. Should verify id nonce signature

  # Node returned might not have an address or not a valid address
  newNode = ? newNode(authResp.record).mapErrTo(HandshakeError)
  ok()

proc decodePacket*(c: var Codec,
                      fromId: NodeID,
                      fromAddr: Address,
                      input: openArray[byte],
                      authTag: var AuthTag,
                      newNode: var Node): DecodeResult[Message] =
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

    var sec: HandshakeSecrets
    if c.decodeAuthResp(fromId, auth, challenge, sec, newNode).isErr:
      trace "Decoding failed (bad auth)"
      return err(HandshakeError)

    c.handshakes.del(key)

    # Swap keys to match remote
    swap(sec.readKey, sec.writeKey)
    # TODO: is it safe to ignore the error here?
    discard c.db.storeKeys(fromId, fromAddr, sec.readKey, sec.writeKey)
    readKey = sec.readKey
  else:
    # Message packet or random packet - rlp bytes (size 12) indicates auth-tag
    try:
      authTag = r.read(AuthTag)
    except RlpError:
      return err(PacketError)
    auth.auth = authTag
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

proc newRequestId*(): Result[RequestId, cstring] =
  var id: RequestId
  if randomBytes(addr id, sizeof(id)) != sizeof(id):
    err("Could not randomize bytes")
  else:
    ok(id)

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
