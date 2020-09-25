import
  std/[tables, options],
  nimcrypto, stint, chronicles, stew/results, bearssl, stew/byteutils,
  eth/[rlp, keys], typesv1, node, enr, hkdf, sessions

export keys

{.push raises: [Defect].}

const
  version: uint8 = 1
  idNoncePrefix = "discovery-id-nonce"
  keyAgreementPrefix = "discovery v5 key agreement"
  protocolIdStr = "discv5  "
  protocolId = toBytes(protocolIdStr)
  gcmNonceSize* = 12
  idNonceSize* = 32
  gcmTagSize* = 16
  ivSize = 16
  staticHeaderSize = protocolId.len + sizeof(NodeId) + 1 + 2
  authdataHeadSize = 1 + gcmNonceSize + 1 + 1

type
  AESGCMNonce* = array[gcmNonceSize, byte]
  IdNonce* = array[idNonceSize, byte]

  WhoareyouData* = object
    requestNonce*: AESGCMNonce
    idNonce*: IdNonce
    recordSeq*: uint64

  Challenge* = object
    whoareyouData*: WhoareyouData
    pubkey*: Option[PublicKey]

  StaticHeader* = object
    srcId: NodeId
    flag: Flag
    authdataSize: uint16

  HandshakeSecrets* = object
    writeKey*: AesKey
    readKey*: AesKey

  Flag* = enum
    OrdinaryMessage = 0x00
    Whoareyou = 0x01
    HandshakeMessage = 0x02

  Packet* = object
    case flag*: Flag
    of OrdinaryMessage:
      messageOpt*: Option[Message]
      requestNonce*: AESGCMNonce
    of Whoareyou:
      whoareyou*: WhoareyouData
    of HandshakeMessage:
      message*: Message # In a handshake we expect to always be able to decrypt
      # TODO record or node immediately?
      node*: Option[Node]
    srcId*: NodeId

  Codec* = object
    localNode*: Node
    privKey*: PrivateKey
    handshakes*: Table[HandShakeKey, Challenge]
    sessions*: Sessions

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

proc deriveKeys*(n1, n2: NodeID, priv: PrivateKey, pub: PublicKey,
    idNonce: openarray[byte]): HandshakeSecrets =
  let eph = ecdhRawFull(priv, pub)

  var info = newSeqOfCap[byte](keyAgreementPrefix.len + 32 * 2)
  for i, c in keyAgreementPrefix: info.add(byte(c))
  info.add(n1.toByteArrayBE())
  info.add(n2.toByteArrayBE())

  var secrets: HandshakeSecrets
  static: assert(sizeof(secrets) == aesKeySize * 2)
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

proc encryptHeader*(id: NodeId, iv, header: openarray[byte]): seq[byte] =
  var ectx: CTR[aes128]
  ectx.init(id.toByteArrayBE().toOpenArray(0, 15), iv)
  result = newSeq[byte](header.len)
  ectx.encrypt(header, result)
  ectx.clear()

proc encodeStaticHeader*(srcId: NodeId, flag: Flag, authSize: int): seq[byte] =
  result.add(protocolId)
  result.add(srcId.toByteArrayBE())
  result.add(byte(flag))
  # TODO: assert on authSize of > 2^16?
  result.add((uint16(authSize)).toBytesBE())

proc encodeMessagePacket*(rng: var BrHmacDrbgContext, c: var Codec,
    toId: NodeID, toAddr: Address, message: openarray[byte]):
    (seq[byte], AESGCMNonce) =
  var authdata: AESGCMNonce
  brHmacDrbgGenerate(rng, authdata) # Random AESGCM nonce

  # static-header
  let staticHeader = encodeStaticHeader(c.localNode.id, Flag.OrdinaryMessage,
    authdata.len())
  # header = static-header || authdata
  var header: seq[byte]
  header.add(staticHeader)
  header.add(authdata)

  # message
  var messageEncrypted: seq[byte]
  var writeKey, readKey: AesKey
  if c.sessions.load(toId, toAddr, readKey, writeKey):
    messageEncrypted = encryptGCM(writeKey, authdata, message, header)
  else:
    # We might not have the node's keys if the handshake hasn't been performed
    # yet. That's fine, we send a random-packet and we will be responded with
    # a WHOAREYOU packet.
    # TODO: What is minimum size of an encrypted message that we should provided
    # here?
    var randomData: array[44, byte]
    brHmacDrbgGenerate(rng, randomData)
    messageEncrypted.add(randomData)

  var iv: array[ivSize, byte]
  brHmacDrbgGenerate(rng, iv) # Random IV

  let maskedHeader = encryptHeader(toId, iv, header)

  var packet: seq[byte]
  packet.add(iv)
  packet.add(maskedHeader)
  packet.add(messageEncrypted)

  return (packet, authdata)

proc encodeWhoareyouPacket*(rng: var BrHmacDrbgContext, c: var Codec,
    toId: NodeID, requestNonce: AESGCMNonce, idNonce: IdNonce, enrSeq: uint64):
    seq[byte] =
  # authdata
  var authdata: seq[byte]
  authdata.add(requestNonce)
  authdata.add(idNonce)
  authdata.add(enrSeq.tobytesBE)

  # static-header
  let staticHeader = encodeStaticHeader(c.localNode.id, Flag.Whoareyou,
    authdata.len()) # authdata will always be 52 bytes

  # header = static-header || authdata
  var header: seq[byte]
  header.add(staticHeader)
  header.add(authdata)

  var iv: array[ivSize, byte]
  brHmacDrbgGenerate(rng, iv) # Random IV

  let maskedHeader = encryptHeader(toId, iv, header)

  var packet: seq[byte]
  packet.add(iv)
  packet.add(maskedHeader)

  return packet

proc encodeHandshakePacket*(rng: var BrHmacDrbgContext, c: var Codec,
    toId: NodeID, toAddr: Address, message: openarray[byte], idNonce: IdNonce,
    enrSeq: uint64, pubkey: PublicKey): seq[byte] =
  var header: seq[byte]
  var nonce: AESGCMNonce
  brHmacDrbgGenerate(rng, nonce)

  var authdata: seq[byte]
  var authdataHead: seq[byte]
  authdataHead.add(version)
  authdataHead.add(nonce)
  authdataHead.add(64'u8) # sig-size: 64
  authdataHead.add(33'u8) # eph-key-size: 33
  authdata.add(authdataHead)

  let ephKeys = KeyPair.random(rng)
  let signature = signIDNonce(c.privKey, idNonce,
    ephKeys.pubkey.toRawCompressed())

  authdata.add(signature.toRaw())
  # compressed pub key format (33 bytes)
  authdata.add(ephKeys.pubkey.toRawCompressed())

  # Add ENR of sequence number is newer
  if enrSeq < c.localNode.record.seqNum:
    authdata.add(encode(c.localNode.record))

  let secrets = deriveKeys(c.localNode.id, toId, ephKeys.seckey, pubkey,
    idNonce)

  # Header
  let staticHeader = encodeStaticHeader(c.localNode.id, Flag.HandshakeMessage,
    authdata.len())

  header.add(staticHeader)
  header.add(authdata)

  c.sessions.store(toId, toAddr, secrets.readKey, secrets.writeKey)
  let messageEncrypted = encryptGCM(secrets.writeKey, nonce, message, header)

  var iv: array[ivSize, byte]
  brHmacDrbgGenerate(rng, iv) # Random IV

  let maskedHeader = encryptHeader(toId, iv, header)

  var packet: seq[byte]
  packet.add(iv)
  packet.add(maskedHeader)
  packet.add(messageEncrypted)

  return packet

proc decodeHeader*(id: NodeId, iv, maskedHeader: openarray[byte]):
    DecodeResult[(StaticHeader, seq[byte])] =
  # Smallest header is staticHeader + gcm nonce for a ordinary message
  let inputLen = maskedHeader.len
  if inputLen < staticHeaderSize + gcmNonceSize:
    return err(PacketError)

  var ectx: CTR[aes128]
  ectx.init(id.toByteArrayBE().toOpenArray(0, ivSize - 1), iv)
  # Decrypt static-header part of the header
  var staticHeader = newSeq[byte](staticHeaderSize)
  ectx.decrypt(maskedHeader.toOpenArray(0, staticHeaderSize - 1), staticHeader)

  # Check fields of the static-header
  if staticHeader.toOpenArray(0, protocolId.len - 1) != protocolId:
    return err(PacketError)

  let srcId = NodeId.fromBytesBE(staticHeader.toOpenArray(8, 39))

  if staticHeader[40] < Flag.low.byte or staticHeader[40] > Flag.high.byte:
    return err(PacketError)
  let flag = cast[Flag](staticHeader[40])

  let authdataSize = uint16.fromBytesBE(staticHeader.toOpenArray(41, 42))
  # Input should have minimum size of staticHeader + provided authdata size
  if inputLen < staticHeaderSize + int(authdataSize):
    return err(PacketError)

  var authdata = newSeq[byte](int(authdataSize))
  ectx.decrypt(maskedHeader.toOpenArray(staticHeaderSize,
    staticHeaderSize + int(authdataSize) - 1), authdata)
  ectx.clear()

  ok((StaticHeader(srcId: srcId, flag: flag, authdataSize: authdataSize),
    staticHeader & authdata))

proc decodeMessage*(body: openarray[byte]): DecodeResult[Message] =
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
      of talkreq, talkresp, regtopic, ticket, regconfirmation, topicquery:
        # TODO: Implement support for topic advertisement and talkreq/resp
        return err(UnsupportedMessage)
    except RlpError, ValueError:
      return err(PacketError)

    ok(message)
  else:
    err(PacketError)

proc decodeMessagePacket(c: var Codec, fromAddr: Address, srcId: NodeId,
    ct, header: openArray[byte]): DecodeResult[Packet] =
    # We now know the exact size that the header should be
    if header.len != staticHeaderSize + gcmNonceSize:
      return err(PacketError)

    var nonce: AESGCMNonce
    copyMem(addr nonce[0], unsafeAddr header[staticHeaderSize], gcmNonceSize)

    var writeKey, readKey: AesKey
    if not c.sessions.load(srcId, fromAddr, readKey, writeKey):
      # Don't consider this an error, simply haven't done a handshake yet or
      # the session got removed.
      trace "Decrypting failed (no keys)"
      return ok(Packet(flag: Flag.OrdinaryMessage, requestNonce: nonce,
        srcId: srcId))

    let pt = decryptGCM(readKey, nonce, ct, header)
    if pt.isNone():
      # Don't consider this an error, the session got probably removed at the
      # peer's side.
      trace "Decrypting failed (invalid keys)"
      c.sessions.del(srcId, fromAddr)
      return ok(Packet(flag: Flag.OrdinaryMessage, requestNonce: nonce,
        srcId: srcId))

    let message = ? decodeMessage(pt.get())

    return ok(Packet(flag: Flag.OrdinaryMessage,
      messageOpt: some(message), requestNonce: nonce, srcId: srcId))

proc decodeWhoareyouPacket(c: var Codec, srcId: NodeId,
    authdata: openArray[byte]): DecodeResult[Packet] =
  # We now know the exact size that the authdata should be
  if authdata.len != gcmNonceSize + idNonceSize + sizeof(uint64):
    return err(PacketError)

  var requestNonce: AESGCMNonce
  copyMem(addr requestNonce[0], unsafeAddr authdata[0], gcmNonceSize)
  var idNonce: IdNonce
  copyMem(addr idNonce[0], unsafeAddr authdata[gcmNonceSize], idNonceSize)
  let whoareyou = WhoareyouData(requestNonce: requestNonce, idNonce: idNonce,
    recordSeq: uint64.fromBytesBE(
      authdata.toOpenArray(gcmNonceSize + idNonceSize, authdata.high)))

  return ok(Packet(flag: Flag.Whoareyou, whoareyou: whoareyou,
    srcId: srcId))

proc decodeHandshakePacket(c: var Codec, fromAddr: Address, srcId: NodeId,
    ct, header: openArray[byte]): DecodeResult[Packet] =
  # Checking if there is enough data to decode authdata-head
  if header.len <= staticHeaderSize + authdataHeadSize:
    return err(PacketError)

  # check version
  let authData = header[staticHeaderSize..header.high()]
  if uint8(authData[0]) != version:
    return err(HandshakeError)

  let
    nonce = authdata[1..12]
    sigSize = uint8(authdata[13])
    ephKeySize = uint8(authdata[14])

  # If smaller, as it can be equal and bigger (in case it holds an enr)
  if header.len < staticHeaderSize + authdataHeadSize + int(sigSize) + int(ephKeySize):
    return err(PacketError)

  let key = HandShakeKey(nodeId: srcId, address: $fromAddr)
  var challenge: Challenge
  if not c.handshakes.pop(key, challenge):
    debug "Decoding failed (no previous stored handshake challenge)"
    return err(HandshakeError)

  # This should be the compressed public key. But as we use the provided
  # ephKeySize, it should also work with full sized key. However, the idNonce
  # signature verification will fail.
  let
    ephKeyPos = authdataHeadSize + int(sigSize)
    ephKeyRaw = authdata[ephKeyPos..<ephKeyPos + int(ephKeySize)]
    ephKey = ? PublicKey.fromRaw(ephKeyRaw).mapErrTo(HandshakeError)

  var record: Option[enr.Record]
  let recordPos = ephKeyPos + int(ephKeySize)
  if authdata.len() > recordPos:
    # There is possibly an ENR still
    try:
      # Signature check of record happens in decode.
      record = some(rlp.decode(authdata.toOpenArray(recordPos, authdata.high),
        enr.Record))
    except RlpError, ValueError:
      return err(HandshakeError)

  var pubKey: PublicKey
  var newNode: Option[Node]
  # TODO: Shall we return Node or Record? Record makes more sense, but we do
  # need the pubkey and the nodeid
  if record.isSome():
    # Node returned might not have an address or not a valid address.
    let node = ? newNode(record.get()).mapErrTo(HandshakeError)
    if node.id != srcId:
      return err(HandshakeError)

    pubKey = node.pubKey
    newNode = some(node)
  else:
    if challenge.pubkey.isSome():
      pubKey = challenge.pubkey.get()
    else:
      # We should have received a Record in this case.
      return err(HandshakeError)

  # Verify the id-nonce-sig
  let sig = ? SignatureNR.fromRaw(
    authdata.toOpenArray(authdataHeadSize,
      authdataHeadSize + int(sigSize) - 1)).mapErrTo(HandshakeError)

  let h = idNonceHash(challenge.whoareyouData.idNonce, ephKeyRaw)
  if not verify(sig, SkMessage(h.data), pubkey):
    return err(HandshakeError)

  # Do the key derivation step only after id-nonce-sig is verified!
  var secrets = deriveKeys(srcId, c.localNode.id, c.privKey,
    ephKey, challenge.whoareyouData.idNonce)

  swap(secrets.readKey, secrets.writeKey)
  c.sessions.store(srcId, fromAddr, secrets.readKey,
    secrets.writeKey)

  let pt = decryptGCM(secrets.readKey, nonce, ct, header)
  if pt.isNone():
    c.sessions.del(srcId, fromAddr)
    # Differently from an ordinary message, this is seen as an error as the
    # secrets just got negotiated in the handshake.
    return err(DecryptError)

  let message = ? decodeMessage(pt.get())

  return ok(Packet(flag: Flag.HandshakeMessage, message: message, srcId: srcId,
    node: newNode))

proc decodePacket*(c: var Codec, fromAddr: Address, input: openArray[byte]):
    DecodeResult[Packet] =
  ## Decode a packet. This can be a regular packet or a packet in response to a
  ## WHOAREYOU packet. In case of the latter a `newNode` might be provided.
  # TODO: First size check. Which size however?
  # IVSize + staticHeaderSize + 12 + ...? What is minimum message size?
  if input.len() <= ivSize + staticHeaderSize + gcmNonceSize:
    return err(PacketError)
  # TODO: Just pass in the full input? Makes more sense perhaps..
  let (staticHeader, header) = ? decodeHeader(c.localNode.id,
    input.toOpenArray(0, ivSize - 1), # IV
    # Don't know the size yet of the full header, so we pass all.
    input.toOpenArray(ivSize, input.high))

  case staticHeader.flag
  of OrdinaryMessage:
    # TODO: Extra size check on ct data?
    return decodeMessagePacket(c, fromAddr, staticHeader.srcId,
      input.toOpenArray(ivSize + header.len, input.high), header)

  of Whoareyou:
    # Header size got checked in decode header
    return decodeWhoareyouPacket(c, staticHeader.srcId,
      header.toOpenArray(staticHeaderSize, header.high()))

  of HandshakeMessage:
    # TODO: Extra size check on ct data?
    return decodeHandshakePacket(c, fromAddr, staticHeader.srcId,
      input.toOpenArray(ivSize + header.len, input.high), header)

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
