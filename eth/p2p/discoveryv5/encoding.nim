import tables
import types, node, enr, hkdf, ../enode, eth/[rlp, keys], nimcrypto, stint

const
  idNoncePrefix = "discovery-id-nonce"
  gcmNonceSize* = 12
  keyAgreementPrefix = "discovery v5 key agreement"
  authSchemeName = "gcm"

type
  AuthResponse = object
    version: int
    signature: array[64, byte]
    record: Record

  Codec* = object
    localNode*: Node
    privKey*: PrivateKey
    db*: Database
    handshakes*: Table[string, Whoareyou] # TODO: Implement hash for NodeID

  HandshakeSecrets = object
    writeKey: array[16, byte]
    readKey: array[16, byte]
    authRespKey: array[16, byte]

  AuthHeader = object
    auth: array[12, byte]
    idNonce: array[32, byte]
    scheme: string
    ephemeralKey: array[64, byte]
    response: seq[byte]


const
  gcmTagSize = 16

proc randomBytes(v: var openarray[byte]) =
  if nimcrypto.randomBytes(v) != v.len:
    raise newException(Exception, "Could not randomize bytes") # TODO:

proc idNonceHash(nonce, ephkey: openarray[byte]): array[32, byte] =
  var ctx: sha256
  ctx.init()
  ctx.update(idNoncePrefix)
  ctx.update(nonce)
  ctx.update(ephkey)
  ctx.finish().data

proc signIDNonce(c: Codec, idNonce, ephKey: openarray[byte]): SignatureNR =
  if signRawMessage(idNonceHash(idNonce, ephKey), c.privKey, result) != EthKeysStatus.Success:
    raise newException(Exception, "Could not sign idNonce")

proc deriveKeys(n1, n2: NodeID, priv: PrivateKey, pub: PublicKey, challenge: Whoareyou, result: var HandshakeSecrets) =
  var eph: SharedSecretFull
  if ecdhAgree(priv, pub, eph) != EthKeysStatus.Success:
    raise newException(Exception, "ecdhAgree failed")

  # TODO: Unneeded allocation here
  var info = newSeqOfCap[byte](idNoncePrefix.len + 32 * 2)
  for i, c in keyAgreementPrefix: info.add(byte(c))
  info.add(n1.toByteArrayBE())
  info.add(n2.toByteArrayBE())

  # echo "EPH: ", eph.data.toHex, " idNonce: ", challenge.idNonce.toHex, "info: ", info.toHex

  static: assert(sizeof(result) == 16 * 3)
  var res = cast[ptr UncheckedArray[byte]](addr result)
  hkdf(sha256, eph.data, challenge.idNonce, info, toOpenArray(res, 0, sizeof(result) - 1))

proc encryptGCM(key, nonce, pt, authData: openarray[byte]): seq[byte] =
  var ectx: GCM[aes128]
  ectx.init(key, nonce, authData)
  result = newSeq[byte](pt.len + gcmTagSize)
  ectx.encrypt(pt, result)
  ectx.getTag(result.toOpenArray(pt.len, result.high))
  ectx.clear()

proc makeAuthHeader(c: Codec, toNode: Node, nonce: array[gcmNonceSize, byte],
                    handhsakeSecrets: var HandshakeSecrets, challenge: Whoareyou): seq[byte] =
  var resp = AuthResponse(version: 5)
  let ln = c.localNode

  if challenge.recordSeq < ln.record.sequenceNumber:
    resp.record = ln.record

  var remotePubkey: PublicKey
  if not toNode.record.get(remotePubkey):
    raise newException(Exception, "Could not get public key from remote ENR") # Should not happen!

  let ephKey = newPrivateKey()
  let ephPubkey = ephKey.getPublicKey().getRaw

  resp.signature = c.signIDNonce(challenge.idNonce, ephPubkey).getRaw

  deriveKeys(ln.id, toNode.id, ephKey, remotePubkey, challenge, handhsakeSecrets)

  let respRlp = rlp.encode(resp)

  var zeroNonce: array[gcmNonceSize, byte]
  let respEnc = encryptGCM(handhsakeSecrets.authRespKey, zeroNonce, respRLP, [])

  let header = AuthHeader(auth: nonce, idNonce: challenge.idNonce, scheme: authSchemeName,
                            ephemeralKey: ephPubkey, response: respEnc)
  rlp.encode(header)

proc `xor`[N: static[int], T](a, b: array[N, T]): array[N, T] =
  for i in 0 .. a.high:
    result[i] = a[i] xor b[i]

proc packetTag(destNode, srcNode: NodeID): array[32, byte] =
  let destId = destNode.toByteArrayBE()
  let srcId = srcNode.toByteArrayBE()
  let destidHash = sha256.digest(destId)
  result = srcId xor destidHash.data

proc encodeEncrypted*(c: Codec, toNode: Node, packetData: seq[byte], challenge: Whoareyou): (seq[byte], array[gcmNonceSize, byte]) =
  var nonce: array[gcmNonceSize, byte]
  randomBytes(nonce)
  var headEnc: seq[byte]

  var writeKey: array[16, byte]

  if challenge.isNil:
    headEnc = rlp.encode(nonce)
    var readKey: array[16, byte]

    # We might not have the node's keys if the handshake hasn't been performed
    # yet. That's fine, we will be responded with whoareyou.
    discard c.db.loadKeys(toNode.id, toNode.address, readKey, writeKey)
  else:
    var sec: HandshakeSecrets
    headEnc = c.makeAuthHeader(toNode, nonce, sec, challenge)

    writeKey = sec.writeKey

    c.db.storeKeys(toNode.id, toNode.address, sec.readKey, sec.writeKey)

  var body = packetData
  let tag = packetTag(toNode.id, c.localNode.id)

  var headBuf = newSeqOfCap[byte](tag.len + headEnc.len)
  headBuf.add(tag)
  headBuf.add(headEnc)

  headBuf.add(encryptGCM(writeKey, nonce, body, tag))
  return (headBuf, nonce)

proc decryptGCM(key: array[16, byte], nonce, ct, authData: openarray[byte]): seq[byte] =
  var dctx: GCM[aes128]
  dctx.init(key, nonce, authData)
  result = newSeq[byte](ct.len - gcmTagSize)
  var tag: array[gcmTagSize, byte]
  dctx.decrypt(ct.toOpenArray(0, ct.high - gcmTagSize), result)
  dctx.getTag(tag)
  if tag != ct.toOpenArray(ct.len - gcmTagSize, ct.high):
    result = @[]
  dctx.clear()

proc decodePacketBody(typ: byte, body: openarray[byte], res: var Packet): bool =
  if typ >= PacketKind.low.byte and typ <= PacketKind.high.byte:
    let kind = cast[PacketKind](typ)
    res = Packet(kind: kind)
    var rlp = rlpFromBytes(@body.toRange)
    rlp.enterList()
    res.reqId = rlp.read(RequestId)

    proc decode[T](rlp: var Rlp, v: var T) {.inline, nimcall.} =
      for k, v in v.fieldPairs:
        v = rlp.read(typeof(v))

    template decode(k: untyped) =
      if k == kind:
        decode(rlp, res.k)
        result = true

    decode(ping)
    decode(pong)
    decode(findNode)
    decode(nodes)
  else:
    echo "unknown packet: ", typ

  return true

proc decodeAuthResp(c: Codec, fromId: NodeId, head: AuthHeader, challenge: Whoareyou, secrets: var HandshakeSecrets, newNode: var Node): bool =
  if head.scheme != authSchemeName:
    echo "Unknown auth scheme"
    return false

  var ephKey: PublicKey
  if recoverPublicKey(head.ephemeralKey, ephKey) != EthKeysStatus.Success:
    return false

  deriveKeys(fromId, c.localNode.id, c.privKey, ephKey, challenge, secrets)

  var zeroNonce: array[gcmNonceSize, byte]
  let respData = decryptGCM(secrets.authRespKey, zeroNonce, head.response, [])
  let authResp = rlp.decode(respData, AuthResponse)

  newNode = newNode(authResp.record)
  return true

proc decodeEncrypted*(c: var Codec, fromId: NodeID, fromAddr: Address, input: seq[byte], authTag: var array[12, byte], newNode: var Node, packet: var Packet): bool =
  let input = input.toRange
  var r = rlpFromBytes(input[32 .. ^1])
  let authEndPos = r.currentElemEnd
  var auth: AuthHeader
  var readKey: array[16, byte]
  if r.isList:
    # Handshake

    # TODO: Auth failure will result in resending whoareyou. Do we really want this?
    auth = r.read(AuthHeader)
    authTag = auth.auth

    let challenge = c.handshakes.getOrDefault($fromId)
    if challenge.isNil:
      return false

    if auth.idNonce != challenge.idNonce:
      return false

    var sec: HandshakeSecrets
    if not c.decodeAuthResp(fromId, auth, challenge, sec, newNode):
      return false
    c.handshakes.del($fromId)

    # Swap keys to match remote
    swap(sec.readKey, sec.writeKey)
    c.db.storeKeys(fromId, fromAddr, sec.readKey, sec.writeKey)
    readKey = sec.readKey

  else:
    authTag = r.read(array[12, byte])
    auth.auth = authTag
    var writeKey: array[16, byte]
    if not c.db.loadKeys(fromId, fromAddr, readKey, writeKey):
      return false
      # doAssert(false, "TODO: HANDLE ME!")

  let headSize = 32 + r.position
  let bodyEnc = input[headSize .. ^1]

  let body = decryptGCM(readKey, auth.auth, bodyEnc.toOpenArray, input[0 .. 31].toOpenArray)
  if body.len > 1:
    result = decodePacketBody(body[0], body.toOpenArray(1, body.high), packet)

proc newRequestId*(): RequestId =
  randomBytes(result)

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

proc makePingPacket*(enrSeq: uint64): seq[byte] =
  encodePacket(PingPacket(enrSeq: enrSeq))

proc makeFindnodePacket*(distance: uint32): seq[byte] =
  encodePacket(FindNodePacket(distance: distance))
