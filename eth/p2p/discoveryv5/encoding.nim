# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## Discovery v5 packet encoding as specified at
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#packet-encoding
## And handshake/sessions as specified at
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md#sessions
##

{.push raises: [].}

import
  std/[tables, options, hashes, net],
  nimcrypto/[bcmode, rijndael, sha2], stint, chronicles,
  stew/[results, byteutils, endians2], metrics,
  ".."/../[rlp, keys],
  "."/[messages_encoding, node, enr, hkdf, sessions]

from stew/objects import checkedEnumAssign

export keys

declareCounter discovery_session_lru_cache_hits, "Session LRU cache hits"
declareCounter discovery_session_lru_cache_misses, "Session LRU cache misses"
declareCounter discovery_session_decrypt_failures, "Session decrypt failures"

logScope:
  topics = "eth p2p discv5"

# Support overriding the default discv5 protocol version and protocol id
#  via compile time defines (e.g., '-d:discv5_protocol_id=d5waku')
const
  discv5_protocol_version {.intdefine.} : uint16 = 1
  discv5_protocol_id {.strdefine.} = "discv5"

const
  version = discv5_protocol_version
  protocolId = toBytes(discv5_protocol_id)
  idSignatureText  = "discovery v5 identity proof"
  keyAgreementPrefix = "discovery v5 key agreement"
  gcmNonceSize* = 12
  idNonceSize* = 16
  gcmTagSize* = 16
  ivSize* = 16
  staticHeaderSize = protocolId.len + 2 + 2 + 1 + gcmNonceSize
  authdataHeadSize = sizeof(NodeId) + 1 + 1
  whoareyouSize = ivSize + staticHeaderSize + idNonceSize + 8
  # It's mentioned in the specification that 1280 is the maximum size for the
  # discovery v5 packet, not for the UDP datagram. Thus this limit is applied on
  # the UDP payload and the UDP header is not taken into account.
  # https://github.com/ethereum/devp2p/blob/26e380b1f3a57db16fbdd4528dde82104c77fa38/discv5/discv5-wire.md#udp-communication
  maxDiscv5PacketSize* = 1280

type
  AESGCMNonce* = array[gcmNonceSize, byte]
  IdNonce* = array[idNonceSize, byte]

  WhoareyouData* = object
    requestNonce*: AESGCMNonce
    idNonce*: IdNonce # TODO: This data is also available in challengeData
    recordSeq*: uint64
    challengeData*: seq[byte]

  Challenge* = object
    whoareyouData*: WhoareyouData
    pubkey*: Option[PublicKey]

  StaticHeader* = object
    flag: Flag
    nonce: AESGCMNonce
    authdataSize: uint16

  HandshakeSecrets* = object
    initiatorKey*: AesKey
    recipientKey*: AesKey

  Flag* = enum
    OrdinaryMessage = 0x00
    Whoareyou = 0x01
    HandshakeMessage = 0x02

  Packet* = object
    case flag*: Flag
    of OrdinaryMessage:
      messageOpt*: Option[Message]
      requestNonce*: AESGCMNonce
      srcId*: NodeId
    of Whoareyou:
      whoareyou*: WhoareyouData
    of HandshakeMessage:
      message*: Message # In a handshake we expect to always be able to decrypt
      # TODO record or node immediately?
      node*: Option[Node]
      srcIdHs*: NodeId

  HandshakeKey* = object
    nodeId*: NodeId
    address*: Address

  Codec* = object
    localNode*: Node
    privKey*: PrivateKey
    handshakes*: Table[HandshakeKey, Challenge]
    sessions*: Sessions

  DecodeResult*[T] = Result[T, cstring]

func `==`*(a, b: HandshakeKey): bool =
  (a.nodeId == b.nodeId) and (a.address == b.address)

func hash*(key: HandshakeKey): Hash =
  result = key.nodeId.hash !& key.address.hash
  result = !$result

proc idHash(challengeData, ephkey: openArray[byte], nodeId: NodeId):
    MDigest[256] =
  var ctx: sha256
  ctx.init()
  ctx.update(idSignatureText)
  ctx.update(challengeData)
  ctx.update(ephkey)
  ctx.update(nodeId.toByteArrayBE())
  result = ctx.finish()
  ctx.clear()

proc createIdSignature*(privKey: PrivateKey, challengeData,
    ephKey: openArray[byte], nodeId: NodeId): SignatureNR =
  signNR(privKey, SkMessage(idHash(challengeData, ephKey, nodeId).data))

proc verifyIdSignature*(sig: SignatureNR, challengeData, ephKey: openArray[byte],
    nodeId: NodeId, pubkey: PublicKey): bool =
  let h = idHash(challengeData, ephKey, nodeId)
  verify(sig, SkMessage(h.data), pubkey)

proc deriveKeys*(n1, n2: NodeId, priv: PrivateKey, pub: PublicKey,
    challengeData: openArray[byte]): HandshakeSecrets =
  let eph = ecdhSharedSecretFull(priv, pub)

  var info = newSeqOfCap[byte](keyAgreementPrefix.len + 32 * 2)
  for i, c in keyAgreementPrefix: info.add(byte(c))
  info.add(n1.toByteArrayBE())
  info.add(n2.toByteArrayBE())

  var secrets: HandshakeSecrets
  static: assert(sizeof(secrets) == aesKeySize * 2)
  var res = cast[ptr UncheckedArray[byte]](addr secrets)

  hkdf(sha256, eph.data, challengeData, info,
    toOpenArray(res, 0, sizeof(secrets) - 1))
  secrets

proc encryptGCM*(key: AesKey, nonce, pt, authData: openArray[byte]): seq[byte] =
  var ectx: GCM[aes128]
  ectx.init(key, nonce, authData)
  result = newSeq[byte](pt.len + gcmTagSize)
  ectx.encrypt(pt, result)
  ectx.getTag(result.toOpenArray(pt.len, result.high))
  ectx.clear()

proc decryptGCM*(key: AesKey, nonce, ct, authData: openArray[byte]):
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

proc encryptHeader*(id: NodeId, iv, header: openArray[byte]): seq[byte] =
  var ectx: CTR[aes128]
  ectx.init(id.toByteArrayBE().toOpenArray(0, 15), iv)
  result = newSeq[byte](header.len)
  ectx.encrypt(header, result)
  ectx.clear()

proc hasHandshake*(c: Codec, key: HandshakeKey): bool =
  c.handshakes.hasKey(key)

proc encodeStaticHeader*(flag: Flag, nonce: AESGCMNonce, authSize: int):
    seq[byte] =
  result.add(protocolId)
  result.add(version.toBytesBE())
  result.add(byte(flag))
  result.add(nonce)
  # TODO: assert on authSize of > 2^16?
  result.add((uint16(authSize)).toBytesBE())

proc encodeMessagePacket*(rng: var HmacDrbgContext, c: var Codec,
    toId: NodeId, toAddr: Address, message: openArray[byte]):
    (seq[byte], AESGCMNonce) =
  let
    nonce = rng.generate(AESGCMNonce) # Random AESGCM nonce
    iv = rng.generate(array[ivSize, byte]) # Random IV

  # static-header
  let
    authdata = c.localNode.id.toByteArrayBE()
    staticHeader = encodeStaticHeader(Flag.OrdinaryMessage, nonce,
      authdata.len())

  # header = static-header || authdata
  var header: seq[byte]
  header.add(staticHeader)
  header.add(authdata)

  # message
  var messageEncrypted: seq[byte]
  var initiatorKey, recipientKey: AesKey
  if c.sessions.load(toId, toAddr, recipientKey, initiatorKey):
    messageEncrypted = encryptGCM(initiatorKey, nonce, message, @iv & header)
    discovery_session_lru_cache_hits.inc()
  else:
    # We might not have the node's keys if the handshake hasn't been performed
    # yet. That's fine, we send a random-packet and we will be responded with
    # a WHOAREYOU packet.
    # Select 20 bytes of random data, which is the smallest possible ping
    # message. 16 bytes for the gcm tag and 4 bytes for ping with requestId of
    # 1 byte (e.g "01c20101"). Could increase to 27 for 8 bytes requestId in
    # case this must not look like a random packet.
    let randomData = rng.generate(array[gcmTagSize + 4, byte])
    messageEncrypted.add(randomData)
    discovery_session_lru_cache_misses.inc()

  let maskedHeader = encryptHeader(toId, iv, header)

  var packet: seq[byte]
  packet.add(iv)
  packet.add(maskedHeader)
  packet.add(messageEncrypted)

  return (packet, nonce)

proc encodeWhoareyouPacket*(rng: var HmacDrbgContext, c: var Codec,
    toId: NodeId, toAddr: Address, requestNonce: AESGCMNonce, recordSeq: uint64,
    pubkey: Option[PublicKey]): seq[byte] =
  let
    idNonce = rng.generate(IdNonce)

  # authdata
  var authdata: seq[byte]
  authdata.add(idNonce)
  authdata.add(recordSeq.toBytesBE)

  # static-header
  let staticHeader = encodeStaticHeader(Flag.Whoareyou, requestNonce,
    authdata.len())

  # header = static-header || authdata
  var header: seq[byte]
  header.add(staticHeader)
  header.add(authdata)

  let
    iv = rng.generate(array[ivSize, byte]) # Random IV
    maskedHeader = encryptHeader(toId, iv, header)

  var packet: seq[byte]
  packet.add(iv)
  packet.add(maskedHeader)

  let
    whoareyouData = WhoareyouData(
      requestNonce: requestNonce,
      idNonce: idNonce,
      recordSeq: recordSeq,
      challengeData: @iv & header)
    challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
    key = HandshakeKey(nodeId: toId, address: toAddr)

  c.handshakes[key] = challenge

  return packet

proc encodeHandshakePacket*(rng: var HmacDrbgContext, c: var Codec,
    toId: NodeId, toAddr: Address, message: openArray[byte],
    whoareyouData: WhoareyouData, pubkey: PublicKey): seq[byte] =
  let
    nonce = rng.generate(AESGCMNonce)
    iv = rng.generate(array[ivSize, byte]) # Random IV

  var authdata: seq[byte]
  var authdataHead: seq[byte]

  authdataHead.add(c.localNode.id.toByteArrayBE())
  authdataHead.add(64'u8) # sig-size: 64
  authdataHead.add(33'u8) # eph-key-size: 33
  authdata.add(authdataHead)

  let ephKeys = KeyPair.random(rng)
  let signature = createIdSignature(c.privKey, whoareyouData.challengeData,
    ephKeys.pubkey.toRawCompressed(), toId)

  authdata.add(signature.toRaw())
  # compressed pub key format (33 bytes)
  authdata.add(ephKeys.pubkey.toRawCompressed())

  # Add ENR of sequence number is newer
  if whoareyouData.recordSeq < c.localNode.record.seqNum:
    authdata.add(encode(c.localNode.record))

  let secrets = deriveKeys(c.localNode.id, toId, ephKeys.seckey, pubkey,
    whoareyouData.challengeData)

  # Header
  let staticHeader = encodeStaticHeader(Flag.HandshakeMessage, nonce,
    authdata.len())

  var header: seq[byte]
  header.add(staticHeader)
  header.add(authdata)

  c.sessions.store(toId, toAddr, secrets.recipientKey, secrets.initiatorKey)
  let messageEncrypted = encryptGCM(secrets.initiatorKey, nonce, message,
    @iv & header)

  let maskedHeader = encryptHeader(toId, iv, header)

  var packet: seq[byte]
  packet.add(iv)
  packet.add(maskedHeader)
  packet.add(messageEncrypted)

  return packet

proc decodeHeader*(id: NodeId, iv, maskedHeader: openArray[byte]):
    DecodeResult[(StaticHeader, seq[byte])] =
  # No need to check staticHeader size as that is included in minimum packet
  # size check in decodePacket
  var ectx: CTR[aes128]
  ectx.init(id.toByteArrayBE().toOpenArray(0, aesKeySize - 1), iv)
  # Decrypt static-header part of the header
  var staticHeader = newSeq[byte](staticHeaderSize)
  ectx.decrypt(maskedHeader.toOpenArray(0, staticHeaderSize - 1), staticHeader)

  # Check fields of the static-header
  if staticHeader.toOpenArray(0, protocolId.len - 1) != protocolId:
    return err("Invalid protocol id")

  if uint16.fromBytesBE(staticHeader.toOpenArray(6, 7)) != version:
    return err("Invalid protocol version")

  var flag: Flag
  if not checkedEnumAssign(flag, staticHeader[8]):
    return err("Invalid packet flag")

  var nonce: AESGCMNonce
  copyMem(addr nonce[0], unsafeAddr staticHeader[9], gcmNonceSize)

  let authdataSize = uint16.fromBytesBE(staticHeader.toOpenArray(21,
    staticHeader.high))

  # Input should have minimum size of staticHeader + provided authdata size
  # Can be larger as there can come a message after.
  if maskedHeader.len < staticHeaderSize + int(authdataSize):
    return err("Authdata is smaller than authdata-size indicates")

  var authdata = newSeq[byte](int(authdataSize))
  ectx.decrypt(maskedHeader.toOpenArray(staticHeaderSize,
    staticHeaderSize + int(authdataSize) - 1), authdata)
  ectx.clear()

  ok((StaticHeader(authdataSize: authdataSize, flag: flag, nonce: nonce),
    staticHeader & authdata))

proc decodeMessagePacket(c: var Codec, fromAddr: Address, nonce: AESGCMNonce,
    iv, header, ct: openArray[byte]): DecodeResult[Packet] =
  # We now know the exact size that the header should be
  if header.len != staticHeaderSize + sizeof(NodeId):
    return err("Invalid header length for ordinary message packet")

  # Need to have at minimum the gcm tag size for the message.
  if ct.len < gcmTagSize:
    return err("Invalid message length for ordinary message packet")

  let srcId = NodeId.fromBytesBE(header.toOpenArray(staticHeaderSize,
    header.high))

  var initiatorKey, recipientKey: AesKey
  if not c.sessions.load(srcId, fromAddr, recipientKey, initiatorKey):
    # Don't consider this an error, simply haven't done a handshake yet or
    # the session got removed.
    trace "Decrypting failed (no keys)"
    discovery_session_lru_cache_misses.inc()
    return ok(Packet(flag: Flag.OrdinaryMessage, requestNonce: nonce,
      srcId: srcId))

  discovery_session_lru_cache_hits.inc()

  let pt = decryptGCM(recipientKey, nonce, ct, @iv & @header)
  if pt.isNone():
    # Don't consider this an error, the session got probably removed at the
    # peer's side and a random message is send.
    trace "Decrypting failed (invalid keys)"
    c.sessions.del(srcId, fromAddr)
    discovery_session_decrypt_failures.inc()
    return ok(Packet(flag: Flag.OrdinaryMessage, requestNonce: nonce,
      srcId: srcId))

  let message = ? decodeMessage(pt.get())

  return ok(Packet(flag: Flag.OrdinaryMessage,
    messageOpt: some(message), requestNonce: nonce, srcId: srcId))

proc decodeWhoareyouPacket(c: var Codec, nonce: AESGCMNonce,
    iv, header, ct: openArray[byte]): DecodeResult[Packet] =
  # TODO improve this
  let authdata = header[staticHeaderSize..header.high()]
  # We now know the exact size that the authdata should be
  if authdata.len != idNonceSize + sizeof(uint64):
    return err("Invalid header length for whoareyou packet")

  # The `message` part of WHOAREYOU packets is always empty.
  if ct.len != 0:
    return err("Invalid message length for whoareyou packet")

  var idNonce: IdNonce
  copyMem(addr idNonce[0], unsafeAddr authdata[0], idNonceSize)
  let whoareyou = WhoareyouData(requestNonce: nonce, idNonce: idNonce,
    recordSeq: uint64.fromBytesBE(
      authdata.toOpenArray(idNonceSize, authdata.high)),
    challengeData: @iv & @header)

  return ok(Packet(flag: Flag.Whoareyou, whoareyou: whoareyou))

proc decodeHandshakePacket(c: var Codec, fromAddr: Address, nonce: AESGCMNonce,
    iv, header, ct: openArray[byte]): DecodeResult[Packet] =
  # Checking if there is enough data to decode authdata-head
  if header.len <= staticHeaderSize + authdataHeadSize:
    return err("Invalid header for handshake message packet: no authdata-head")

  # Need to have at minimum the gcm tag size for the message.
  # TODO: And actually, as we should be able to decrypt it, it should also be
  # a valid message and thus we could increase here to the size of the smallest
  # message possible.
  if ct.len < gcmTagSize:
    return err("Invalid message length for handshake message packet")

  let
    authdata = header[staticHeaderSize..header.high()]
    srcId = NodeId.fromBytesBE(authdata.toOpenArray(0, 31))
    sigSize = uint8(authdata[32])
    ephKeySize = uint8(authdata[33])

  # If smaller, as it can be equal and bigger (in case it holds an enr)
  if header.len < staticHeaderSize + authdataHeadSize + int(sigSize) + int(ephKeySize):
    return err("Invalid header for handshake message packet")

  let key = HandshakeKey(nodeId: srcId, address: fromAddr)
  var challenge: Challenge
  if not c.handshakes.pop(key, challenge):
    return err("No challenge found: timed out or unsolicited packet")

  # This should be the compressed public key. But as we use the provided
  # ephKeySize, it should also work with full sized key. However, the idNonce
  # signature verification will fail.
  let
    ephKeyPos = authdataHeadSize + int(sigSize)
    ephKeyRaw = authdata[ephKeyPos..<ephKeyPos + int(ephKeySize)]
    ephKey = ? PublicKey.fromRaw(ephKeyRaw)

  var record: Option[enr.Record]
  let recordPos = ephKeyPos + int(ephKeySize)
  if authdata.len() > recordPos:
    # There is possibly an ENR still
    try:
      # Signature check of record happens in decode.
      record = some(rlp.decode(authdata.toOpenArray(recordPos, authdata.high),
        enr.Record))
    except RlpError, ValueError:
      return err("Invalid encoded ENR")

  var pubkey: PublicKey
  var newNode: Option[Node]
  # TODO: Shall we return Node or Record? Record makes more sense, but we do
  # need the pubkey and the nodeid
  if record.isSome():
    # Node returned might not have an address or not a valid address.
    let node = ? newNode(record.get())
    if node.id != srcId:
      return err("Invalid node id: does not match node id of ENR")

    # Note: Not checking if the record seqNum is higher than the one we might
    # have stored as it comes from this node directly.
    pubkey = node.pubkey
    newNode = some(node)
  else:
    # TODO: Hmm, should we still verify node id of the ENR of this node?
    if challenge.pubkey.isSome():
      pubkey = challenge.pubkey.get()
    else:
      # We should have received a Record in this case.
      return err("Missing ENR in handshake packet")

  # Verify the id-signature
  let sig = ? SignatureNR.fromRaw(
    authdata.toOpenArray(authdataHeadSize, authdataHeadSize + int(sigSize) - 1))
  if not verifyIdSignature(sig, challenge.whoareyouData.challengeData,
      ephKeyRaw, c.localNode.id, pubkey):
    return err("Invalid id-signature")

  # Do the key derivation step only after id-signature is verified as this is
  # costly.
  var secrets = deriveKeys(srcId, c.localNode.id, c.privKey,
    ephKey, challenge.whoareyouData.challengeData)

  swap(secrets.recipientKey, secrets.initiatorKey)

  let pt = decryptGCM(secrets.recipientKey, nonce, ct, @iv & @header)
  if pt.isNone():
    c.sessions.del(srcId, fromAddr)
    # Differently from an ordinary message, this is seen as an error as the
    # secrets just got negotiated in the handshake and thus decryption should
    # always work. We do not send a new Whoareyou on these as it probably means
    # there is a compatibility issue and we might loop forever in failed
    # handshakes with this peer.
    return err("Decryption of message failed in handshake packet")

  let message = ? decodeMessage(pt.get())

  # Only store the session secrets in case decryption was successful and also
  # in case the message can get decoded.
  c.sessions.store(srcId, fromAddr, secrets.recipientKey, secrets.initiatorKey)

  return ok(Packet(flag: Flag.HandshakeMessage, message: message,
    srcIdHs: srcId, node: newNode))

proc decodePacket*(c: var Codec, fromAddr: Address, input: openArray[byte]):
    DecodeResult[Packet] =
  ## Decode a packet. This can be a regular packet or a packet in response to a
  ## WHOAREYOU packet. In case of the latter a `newNode` might be provided.
  # Smallest packet is Whoareyou packet so that is the minimum size
  if input.len() < whoareyouSize:
    return err("Packet size too small")

  if input.len() > maxDiscv5PacketSize:
    return err("Packet size too big")

  # TODO: Just pass in the full input? Makes more sense perhaps.
  let (staticHeader, header) = ? decodeHeader(c.localNode.id,
    input.toOpenArray(0, ivSize - 1), # IV
    # Don't know the size yet of the full header, so we pass all.
    input.toOpenArray(ivSize, input.high))

  case staticHeader.flag
  of OrdinaryMessage:
    return decodeMessagePacket(c, fromAddr, staticHeader.nonce,
      input.toOpenArray(0, ivSize - 1), header,
      input.toOpenArray(ivSize + header.len, input.high))

  of Whoareyou:
    return decodeWhoareyouPacket(c, staticHeader.nonce,
      input.toOpenArray(0, ivSize - 1), header,
      input.toOpenArray(ivSize + header.len, input.high))

  of HandshakeMessage:
    return decodeHandshakePacket(c, fromAddr, staticHeader.nonce,
      input.toOpenArray(0, ivSize - 1), header,
      input.toOpenArray(ivSize + header.len, input.high))
