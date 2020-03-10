import
  std/[tables, options], nimcrypto, stint, chronicles,
  types, node, enr, hkdf, ../enode, eth/[rlp, keys]

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

  RandomSourceDepleted* = object of CatchableError

  DecodeStatus* = enum
    Success,
    HandshakeError,
    PacketError,
    DecryptError

proc randomBytes*(v: var openarray[byte]) =
  if nimcrypto.randomBytes(v) != v.len:
    raise newException(RandomSourceDepleted, "Could not randomize bytes")

proc idNonceHash(nonce, ephkey: openarray[byte]): array[32, byte] =
  var ctx: sha256
  ctx.init()
  ctx.update(idNoncePrefix)
  ctx.update(nonce)
  ctx.update(ephkey)
  ctx.finish().data

proc signIDNonce*(c: Codec, idNonce, ephKey: openarray[byte]): SignatureNR =
  if signRawMessage(idNonceHash(idNonce, ephKey), c.privKey, result) != EthKeysStatus.Success:
    raise newException(EthKeysException, "Could not sign idNonce")

proc deriveKeys(n1, n2: NodeID, priv: PrivateKey, pub: PublicKey,
    idNonce: openarray[byte], result: var HandshakeSecrets) =
  var eph: SharedSecretFull
  if ecdhAgree(priv, pub, eph) != EthKeysStatus.Success:
    raise newException(EthKeysException, "ecdhAgree failed")

  # TODO: Unneeded allocation here
  var info = newSeqOfCap[byte](idNoncePrefix.len + 32 * 2)
  for i, c in keyAgreementPrefix: info.add(byte(c))
  info.add(n1.toByteArrayBE())
  info.add(n2.toByteArrayBE())

  # echo "EPH: ", eph.data.toHex, " idNonce: ", challenge.idNonce.toHex, "info: ", info.toHex

  static: assert(sizeof(result) == aesKeySize * 3)
  var res = cast[ptr UncheckedArray[byte]](addr result)
  hkdf(sha256, eph.data, idNonce, info, toOpenArray(res, 0, sizeof(result) - 1))

proc encryptGCM*(key, nonce, pt, authData: openarray[byte]): seq[byte] =
  var ectx: GCM[aes128]
  ectx.init(key, nonce, authData)
  result = newSeq[byte](pt.len + gcmTagSize)
  ectx.encrypt(pt, result)
  ectx.getTag(result.toOpenArray(pt.len, result.high))
  ectx.clear()

proc makeAuthHeader(c: Codec, toNode: Node, nonce: array[gcmNonceSize, byte],
                    handshakeSecrets: var HandshakeSecrets,
                    challenge: Whoareyou): seq[byte] =
  var resp = AuthResponse(version: 5)
  let ln = c.localNode

  if challenge.recordSeq < ln.record.seqNum:
    resp.record = ln.record

  let ephKey = newPrivateKey()
  let ephPubkey = ephKey.getPublicKey().getRaw

  resp.signature = c.signIDNonce(challenge.idNonce, ephPubkey).getRaw

  deriveKeys(ln.id, toNode.id, ephKey, toNode.node.pubKey, challenge.idNonce,
    handshakeSecrets)

  let respRlp = rlp.encode(resp)

  var zeroNonce: array[gcmNonceSize, byte]
  let respEnc = encryptGCM(handshakeSecrets.authRespKey, zeroNonce, respRLP, [])

  let header = AuthHeader(auth: nonce, idNonce: challenge.idNonce,
    scheme: authSchemeName, ephemeralKey: ephPubkey, response: respEnc)
  rlp.encode(header)

proc `xor`[N: static[int], T](a, b: array[N, T]): array[N, T] =
  for i in 0 .. a.high:
    result[i] = a[i] xor b[i]

proc packetTag(destNode, srcNode: NodeID): PacketTag =
  let destId = destNode.toByteArrayBE()
  let srcId = srcNode.toByteArrayBE()
  let destidHash = sha256.digest(destId)
  result = srcId xor destidHash.data

proc encodeEncrypted*(c: Codec,
                      toNode: Node,
                      packetData: seq[byte],
                      challenge: Whoareyou):
                      (seq[byte], array[gcmNonceSize, byte]) =
  var nonce: array[gcmNonceSize, byte]
  randomBytes(nonce)
  var headEnc: seq[byte]

  var writeKey: AesKey

  if challenge.isNil:
    headEnc = rlp.encode(nonce)
    var readKey: AesKey

    # We might not have the node's keys if the handshake hasn't been performed
    # yet. That's fine, we will be responded with whoareyou.
    discard c.db.loadKeys(toNode.id, toNode.address, readKey, writeKey)
  else:
    var sec: HandshakeSecrets
    headEnc = c.makeAuthHeader(toNode, nonce, sec, challenge)

    writeKey = sec.writeKey
    # TODO: is it safe to ignore the error here?
    discard c.db.storeKeys(toNode.id, toNode.address, sec.readKey, sec.writeKey)

  var body = packetData
  let tag = packetTag(toNode.id, c.localNode.id)

  var headBuf = newSeqOfCap[byte](tag.len + headEnc.len)
  headBuf.add(tag)
  headBuf.add(headEnc)

  headBuf.add(encryptGCM(writeKey, nonce, body, tag))
  return (headBuf, nonce)

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

type
  DecodePacketResult = enum
    decodingSuccessful
    invalidPacketPayload
    invalidPacketType
    unsupportedPacketType

proc decodePacketBody(typ: byte,
                      body: openarray[byte],
                      res: var Packet): DecodePacketResult =
  if typ < PacketKind.low.byte or typ > PacketKind.high.byte:
    return invalidPacketType

  let kind = cast[PacketKind](typ)
  res = Packet(kind: kind)
  var rlp = rlpFromBytes(@body.toRange)
  if rlp.enterList:
    res.reqId = rlp.read(RequestId)

    proc decode[T](rlp: var Rlp, v: var T) {.inline, nimcall.} =
      for k, v in v.fieldPairs:
        v = rlp.read(typeof(v))

    case kind
    of unused: return invalidPacketPayload
    of ping: rlp.decode(res.ping)
    of pong: rlp.decode(res.pong)
    of findNode: rlp.decode(res.findNode)
    of nodes: rlp.decode(res.nodes)
    of regtopic, ticket, regconfirmation, topicquery:
      # TODO Implement these packet types
      return unsupportedPacketType

    return decodingSuccessful
  else:
    return invalidPacketPayload

proc decodeAuthResp(c: Codec, fromId: NodeId, head: AuthHeader,
    challenge: Whoareyou, secrets: var HandshakeSecrets, newNode: var Node): bool =
  if head.scheme != authSchemeName:
    warn "Unknown auth scheme"
    return false

  var ephKey: PublicKey
  if recoverPublicKey(head.ephemeralKey, ephKey) != EthKeysStatus.Success:
    return false

  deriveKeys(fromId, c.localNode.id, c.privKey, ephKey, challenge.idNonce,
    secrets)

  var zeroNonce: array[gcmNonceSize, byte]
  let respData = decryptGCM(secrets.authRespKey, zeroNonce, head.response, [])
  if respData.isNone():
    return false

  let authResp = rlp.decode(respData.get(), AuthResponse)
  # TODO:
  # 1. Should allow for not having an ENR included, solved for now by sending
  # whoareyou with always recordSeq of 0
  # 2. Should verify ENR and check for correct id in case an ENR is included
  # 3. Should verify id nonce signature

  newNode = newNode(authResp.record)
  return true

proc decodeEncrypted*(c: var Codec,
                      fromId: NodeID,
                      fromAddr: Address,
                      input: seq[byte],
                      authTag: var AuthTag,
                      newNode: var Node,
                      packet: var Packet): DecodeStatus =
  let input = input.toRange
  var r = rlpFromBytes(input[tagSize .. ^1])
  var auth: AuthHeader

  var readKey: AesKey
  logScope: sender = $fromAddr

  if r.isList:
    # Handshake - rlp list indicates auth-header
    auth = r.read(AuthHeader)
    authTag = auth.auth

    let key = HandShakeKey(nodeId: fromId, address: $fromAddr)
    let challenge = c.handshakes.getOrDefault(key)
    if challenge.isNil:
      trace "Decoding failed (no challenge)"
      return HandshakeError

    if auth.idNonce != challenge.idNonce:
      trace "Decoding failed (different nonce)"
      return HandshakeError

    var sec: HandshakeSecrets
    if not c.decodeAuthResp(fromId, auth, challenge, sec, newNode):
      trace "Decoding failed (bad auth)"
      return HandshakeError
    c.handshakes.del(key)

    # Swap keys to match remote
    swap(sec.readKey, sec.writeKey)
    # TODO: is it safe to ignore the error here?
    discard c.db.storeKeys(fromId, fromAddr, sec.readKey, sec.writeKey)
    readKey = sec.readKey

  else:
    # Message packet or random packet - rlp bytes (size 12) indicates auth-tag
    authTag = r.read(AuthTag)
    auth.auth = authTag
    var writeKey: AesKey
    if not c.db.loadKeys(fromId, fromAddr, readKey, writeKey):
      trace "Decoding failed (no keys)"
      return DecryptError
      # doAssert(false, "TODO: HANDLE ME!")

  let headSize = tagSize + r.position
  let bodyEnc = input[headSize .. ^1]

  let body = decryptGCM(readKey, auth.auth, bodyEnc.toOpenArray,
    input[0 .. tagSize - 1].toOpenArray)
  if body.isNone():
    discard c.db.deleteKeys(fromId, fromAddr)
    return DecryptError

  let packetData = body.get()
  if packetData.len > 1:
    let status = decodePacketBody(packetData[0],
      packetData.toOpenArray(1, packetData.high), packet)
    if status == decodingSuccessful:
      return Success
    else:
      debug "Failed to decode discovery packet", reason = status
      return PacketError
  else:
    return PacketError

proc newRequestId*(): RequestId =
  if randomBytes(addr result, sizeof(result)) != sizeof(result):
    raise newException(RandomSourceDepleted, "Could not randomize bytes")

proc numFields(T: typedesc): int =
  for k, v in fieldPairs(default(T)): inc result

proc encodePacket*[T: SomePacket](p: T, reqId: RequestId): seq[byte] =
  result = newSeqOfCap[byte](64)
  result.add(packetKind(T).ord)
  # result.add(rlp.encode(p))

  const sz = numFields(T)
  var writer = initRlpList(sz + 1)
  writer.append(reqId)
  for k, v in fieldPairs(p):
    writer.append(v)
  result.add(writer.finish())

proc encodePacket*[T: SomePacket](p: T): seq[byte] =
  encodePacket(p, newRequestId())
