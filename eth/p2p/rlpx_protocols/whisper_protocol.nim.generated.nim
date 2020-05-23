
## Generated at line 119
type
  Whisper* = object
template State*(PROTO: type Whisper): type =
  ref[WhisperPeer:ObjectType]

template NetworkState*(PROTO: type Whisper): type =
  ref[WhisperNetwork:ObjectType]

type
  statusObj* = object
    protocolVersion*: uint
    powConverted*: uint64
    bloom*: seq[byte]
    isLightNode*: bool

template status*(PROTO: type Whisper): type =
  statusObj

template msgProtocol*(MSG: type statusObj): type =
  Whisper

template RecType*(MSG: type statusObj): untyped =
  statusObj

template msgId*(MSG: type statusObj): int =
  0

type
  messagesObj* = object
    envelopes*: seq[Envelope]

template messages*(PROTO: type Whisper): type =
  messagesObj

template msgProtocol*(MSG: type messagesObj): type =
  Whisper

template RecType*(MSG: type messagesObj): untyped =
  messagesObj

template msgId*(MSG: type messagesObj): int =
  1

type
  powRequirementObj* = object
    value*: uint64

template powRequirement*(PROTO: type Whisper): type =
  powRequirementObj

template msgProtocol*(MSG: type powRequirementObj): type =
  Whisper

template RecType*(MSG: type powRequirementObj): untyped =
  powRequirementObj

template msgId*(MSG: type powRequirementObj): int =
  2

type
  bloomFilterExchangeObj* = object
    bloom*: seq[byte]

template bloomFilterExchange*(PROTO: type Whisper): type =
  bloomFilterExchangeObj

template msgProtocol*(MSG: type bloomFilterExchangeObj): type =
  Whisper

template RecType*(MSG: type bloomFilterExchangeObj): untyped =
  bloomFilterExchangeObj

template msgId*(MSG: type bloomFilterExchangeObj): int =
  3

type
  p2pRequestObj* = object
    envelope*: Envelope

template p2pRequest*(PROTO: type Whisper): type =
  p2pRequestObj

template msgProtocol*(MSG: type p2pRequestObj): type =
  Whisper

template RecType*(MSG: type p2pRequestObj): untyped =
  p2pRequestObj

template msgId*(MSG: type p2pRequestObj): int =
  126

type
  p2pMessageObj* = object
    envelope*: Envelope

template p2pMessage*(PROTO: type Whisper): type =
  p2pMessageObj

template msgProtocol*(MSG: type p2pMessageObj): type =
  Whisper

template RecType*(MSG: type p2pMessageObj): untyped =
  p2pMessageObj

template msgId*(MSG: type p2pMessageObj): int =
  127

type
  batchAcknowledgedObj* = object
  
template batchAcknowledged*(PROTO: type Whisper): type =
  batchAcknowledgedObj

template msgProtocol*(MSG: type batchAcknowledgedObj): type =
  Whisper

template RecType*(MSG: type batchAcknowledgedObj): untyped =
  batchAcknowledgedObj

template msgId*(MSG: type batchAcknowledgedObj): int =
  11

type
  messageResponseObj* = object
  
template messageResponse*(PROTO: type Whisper): type =
  messageResponseObj

template msgProtocol*(MSG: type messageResponseObj): type =
  Whisper

template RecType*(MSG: type messageResponseObj): untyped =
  messageResponseObj

template msgId*(MSG: type messageResponseObj): int =
  12

type
  p2pSyncResponseObj* = object
  
template p2pSyncResponse*(PROTO: type Whisper): type =
  p2pSyncResponseObj

template msgProtocol*(MSG: type p2pSyncResponseObj): type =
  Whisper

template RecType*(MSG: type p2pSyncResponseObj): untyped =
  p2pSyncResponseObj

template msgId*(MSG: type p2pSyncResponseObj): int =
  124

type
  p2pSyncRequestObj* = object
  
template p2pSyncRequest*(PROTO: type Whisper): type =
  p2pSyncRequestObj

template msgProtocol*(MSG: type p2pSyncRequestObj): type =
  Whisper

template RecType*(MSG: type p2pSyncRequestObj): untyped =
  p2pSyncRequestObj

template msgId*(MSG: type p2pSyncRequestObj): int =
  123

type
  p2pRequestCompleteObj* = object
  
template p2pRequestComplete*(PROTO: type Whisper): type =
  p2pRequestCompleteObj

template msgProtocol*(MSG: type p2pRequestCompleteObj): type =
  Whisper

template RecType*(MSG: type p2pRequestCompleteObj): untyped =
  p2pRequestCompleteObj

template msgId*(MSG: type p2pRequestCompleteObj): int =
  125

var WhisperProtocolObj = initProtocol("shh", 6, createPeerState[Peer,
    ref[WhisperPeer:ObjectType]], createNetworkState[EthereumNode,
    ref[WhisperNetwork:ObjectType]])
var WhisperProtocol = addr WhisperProtocolObj
template protocolInfo*(P`gensym85175079: type Whisper): auto =
  WhisperProtocol

proc statusRawSender(peerOrResponder: Peer; protocolVersion: uint;
                    powConverted: uint64; bloom: seq[byte]; isLightNode: bool;
                    timeout: Duration = milliseconds(10000'i64)): Future[void] {.
    gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 0
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 0)
  append(writer, perPeerMsgId)
  startList(writer, 4)
  append(writer, protocolVersion)
  append(writer, powConverted)
  append(writer, bloom)
  append(writer, isLightNode)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

template status*(peerOrResponder: Peer; protocolVersion: uint; powConverted: uint64;
                bloom: seq[byte]; isLightNode: bool;
                timeout: Duration = milliseconds(10000'i64)): Future[statusObj] =
  let peer = peerOrResponder
  let sendingFuture`gensym85175056 = statusRawSender(peer, protocolVersion,
      powConverted, bloom, isLightNode)
  handshakeImpl(peer, sendingFuture`gensym85175056, nextMsg(peer, statusObj),
                timeout)

proc messages*(peerOrResponder: Peer; envelopes: openarray[Envelope]): Future[void] {.
    gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 1
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 1)
  append(writer, perPeerMsgId)
  append(writer, envelopes)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc powRequirement*(peerOrResponder: Peer; value: uint64): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 2
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 2)
  append(writer, perPeerMsgId)
  append(writer, value)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc bloomFilterExchange*(peerOrResponder: Peer; bloom: openArray[byte]): Future[void] {.
    gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 3
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 3)
  append(writer, perPeerMsgId)
  append(writer, bloom)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc p2pRequest*(peerOrResponder: Peer; envelope: Envelope): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 126
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 126)
  append(writer, perPeerMsgId)
  append(writer, envelope)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc p2pMessage*(peerOrResponder: Peer; envelope: Envelope): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 127
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 127)
  append(writer, perPeerMsgId)
  append(writer, envelope)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc batchAcknowledged*(peerOrResponder: Peer): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 11
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 11)
  append(writer, perPeerMsgId)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc messageResponse*(peerOrResponder: Peer): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 12
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 12)
  append(writer, perPeerMsgId)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc p2pSyncResponse*(peerOrResponder: ResponderWithId[p2pSyncResponseObj]): Future[
    void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 124
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 124)
  append(writer, perPeerMsgId)
  append(writer, peerOrResponder.reqId)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

template send*(r`gensym85175073: ResponderWithId[p2pSyncResponseObj];
              args`gensym85175074: varargs[untyped]): auto =
  p2pSyncResponse(r`gensym85175073, args`gensym85175074)

proc p2pSyncRequest*(peerOrResponder: Peer;
                    timeout: Duration = milliseconds(10000'i64)): Future[
    Option[p2pSyncResponseObj]] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 123
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 123)
  append(writer, perPeerMsgId)
  initFuture result
  let reqId = registerRequest(peer, timeout, result, perPeerMsgId + 1)
  append(writer, reqId)
  let msgBytes = finish(writer)
  linkSendFailureToReqFuture(sendMsg(peer, msgBytes), result)

proc p2pRequestComplete*(peerOrResponder: Peer): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 125
  let perPeerMsgId = perPeerMsgIdImpl(peer, WhisperProtocol, 125)
  append(writer, perPeerMsgId)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc messagesUserHandler(peer: Peer; envelopes: seq[Envelope]) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 1
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  if not peer.state.initialized:
    warn "Handshake not completed yet, discarding messages"
    return
  for envelope in envelopes:
    if not envelope.valid():
      warn "Expired or future timed envelope", peer
      continue
    let msg = initMessage(envelope)
    if not msg.allowed(peer.networkState.config):
      continue
    if peer.state.received.containsOrIncl(msg.hash):
      dropped_duplicate_envelopes.inc()
      trace "Peer sending duplicate messages", peer, hash = $msg.hash
      continue
    if peer.networkState.queue[].add(msg):
      peer.networkState.filters.notify(msg)

proc powRequirementUserHandler(peer: Peer; value: uint64) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 2
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  if not peer.state.initialized:
    warn "Handshake not completed yet, discarding powRequirement"
    return
  peer.state.powRequirement = cast[float64](value)

proc bloomFilterExchangeUserHandler(peer: Peer; bloom: seq[byte]) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 3
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  if not peer.state.initialized:
    warn "Handshake not completed yet, discarding bloomFilterExchange"
    return
  if bloom.len == bloomSize:
    peer.state.bloom.bytesCopy(bloom)

proc p2pRequestUserHandler(peer: Peer; envelope: Envelope) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 126
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  discard

proc p2pMessageUserHandler(peer: Peer; envelope: Envelope) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 127
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  if peer.state.trusted:
    let msg = Message(env: envelope, isP2P: true)
    peer.networkState.filters.notify(msg)

proc batchAcknowledgedUserHandler(peer: Peer) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 11
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  discard

proc messageResponseUserHandler(peer: Peer) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 12
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  discard

proc p2pSyncResponseUserHandler(peer: Peer; reqId: int) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 124
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  discard

proc p2pSyncRequestUserHandler(peer: Peer; reqId: int) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 123
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  var response = init(ResponderWithId[p2pSyncResponseObj], peer, reqId)
  discard

proc p2pRequestCompleteUserHandler(peer: Peer) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  const
    perProtocolMsgId = 125
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  discard

proc statusThunk(peer: Peer; _`gensym85175033: int; data`gensym85175034: Rlp) {.async,
    gcsafe.} =
  var rlp = data`gensym85175034
  var msg {.noinit.}: statusObj
  tryEnterList(rlp)
  msg.protocolVersion = checkedRlpRead(peer, rlp, uint)
  msg.powConverted = checkedRlpRead(peer, rlp, uint64)
  msg.bloom = checkedRlpRead(peer, rlp, seq[byte])
  msg.isLightNode = checkedRlpRead(peer, rlp, bool)
  
proc messagesThunk(peer: Peer; _`gensym85175057: int; data`gensym85175058: Rlp) {.
    async, gcsafe.} =
  var rlp = data`gensym85175058
  var msg {.noinit.}: messagesObj
  msg.envelopes = checkedRlpRead(peer, rlp, openarray[Envelope])
  await(messagesUserHandler(peer, msg.envelopes))
  
proc powRequirementThunk(peer: Peer; _`gensym85175059: int; data`gensym85175060: Rlp) {.
    async, gcsafe.} =
  var rlp = data`gensym85175060
  var msg {.noinit.}: powRequirementObj
  msg.value = checkedRlpRead(peer, rlp, uint64)
  await(powRequirementUserHandler(peer, msg.value))
  
proc bloomFilterExchangeThunk(peer: Peer; _`gensym85175061: int;
                             data`gensym85175062: Rlp) {.async, gcsafe.} =
  var rlp = data`gensym85175062
  var msg {.noinit.}: bloomFilterExchangeObj
  msg.bloom = checkedRlpRead(peer, rlp, openArray[byte])
  await(bloomFilterExchangeUserHandler(peer, msg.bloom))
  
proc p2pRequestThunk(peer: Peer; _`gensym85175063: int; data`gensym85175064: Rlp) {.
    async, gcsafe.} =
  var rlp = data`gensym85175064
  var msg {.noinit.}: p2pRequestObj
  msg.envelope = checkedRlpRead(peer, rlp, Envelope)
  await(p2pRequestUserHandler(peer, msg.envelope))
  
proc p2pMessageThunk(peer: Peer; _`gensym85175065: int; data`gensym85175066: Rlp) {.
    async, gcsafe.} =
  var rlp = data`gensym85175066
  var msg {.noinit.}: p2pMessageObj
  msg.envelope = checkedRlpRead(peer, rlp, Envelope)
  await(p2pMessageUserHandler(peer, msg.envelope))
  
proc batchAcknowledgedThunk(peer: Peer; _`gensym85175067: int;
                           data`gensym85175068: Rlp) {.async, gcsafe.} =
  var rlp = data`gensym85175068
  var msg {.noinit.}: batchAcknowledgedObj
  await(batchAcknowledgedUserHandler(peer))
  
proc messageResponseThunk(peer: Peer; _`gensym85175069: int; data`gensym85175070: Rlp) {.
    async, gcsafe.} =
  var rlp = data`gensym85175070
  var msg {.noinit.}: messageResponseObj
  await(messageResponseUserHandler(peer))
  
proc p2pSyncResponseThunk(peer: Peer; _`gensym85175071: int; data`gensym85175072: Rlp) {.
    async, gcsafe.} =
  var rlp = data`gensym85175072
  var msg {.noinit.}: p2pSyncResponseObj
  let reqId = read(rlp, int)
  await(p2pSyncResponseUserHandler(peer, reqId))
  resolveResponseFuture(peer, perPeerMsgId(peer, p2pSyncResponseObj), addr(msg),
                        reqId)

proc p2pSyncRequestThunk(peer: Peer; _`gensym85175075: int; data`gensym85175076: Rlp) {.
    async, gcsafe.} =
  var rlp = data`gensym85175076
  var msg {.noinit.}: p2pSyncRequestObj
  let reqId = read(rlp, int)
  await(p2pSyncRequestUserHandler(peer, reqId))
  
proc p2pRequestCompleteThunk(peer: Peer; _`gensym85175077: int;
                            data`gensym85175078: Rlp) {.async, gcsafe.} =
  var rlp = data`gensym85175078
  var msg {.noinit.}: p2pRequestCompleteObj
  await(p2pRequestCompleteUserHandler(peer))
  
registerMsg(WhisperProtocol, 0, "status", statusThunk, messagePrinter[statusObj],
            requestResolver[statusObj], nextMsgResolver[statusObj])
registerMsg(WhisperProtocol, 1, "messages", messagesThunk,
            messagePrinter[messagesObj], requestResolver[messagesObj],
            nextMsgResolver[messagesObj])
registerMsg(WhisperProtocol, 2, "powRequirement", powRequirementThunk,
            messagePrinter[powRequirementObj],
            requestResolver[powRequirementObj],
            nextMsgResolver[powRequirementObj])
registerMsg(WhisperProtocol, 3, "bloomFilterExchange", bloomFilterExchangeThunk,
            messagePrinter[bloomFilterExchangeObj],
            requestResolver[bloomFilterExchangeObj],
            nextMsgResolver[bloomFilterExchangeObj])
registerMsg(WhisperProtocol, 126, "p2pRequest", p2pRequestThunk,
            messagePrinter[p2pRequestObj], requestResolver[p2pRequestObj],
            nextMsgResolver[p2pRequestObj])
registerMsg(WhisperProtocol, 127, "p2pMessage", p2pMessageThunk,
            messagePrinter[p2pMessageObj], requestResolver[p2pMessageObj],
            nextMsgResolver[p2pMessageObj])
registerMsg(WhisperProtocol, 11, "batchAcknowledged", batchAcknowledgedThunk,
            messagePrinter[batchAcknowledgedObj],
            requestResolver[batchAcknowledgedObj],
            nextMsgResolver[batchAcknowledgedObj])
registerMsg(WhisperProtocol, 12, "messageResponse", messageResponseThunk,
            messagePrinter[messageResponseObj],
            requestResolver[messageResponseObj],
            nextMsgResolver[messageResponseObj])
registerMsg(WhisperProtocol, 124, "p2pSyncResponse", p2pSyncResponseThunk,
            messagePrinter[p2pSyncResponseObj],
            requestResolver[p2pSyncResponseObj],
            nextMsgResolver[p2pSyncResponseObj])
registerMsg(WhisperProtocol, 123, "p2pSyncRequest", p2pSyncRequestThunk,
            messagePrinter[p2pSyncRequestObj],
            requestResolver[p2pSyncRequestObj],
            nextMsgResolver[p2pSyncRequestObj])
registerMsg(WhisperProtocol, 125, "p2pRequestComplete", p2pRequestCompleteThunk,
            messagePrinter[p2pRequestCompleteObj],
            requestResolver[p2pRequestCompleteObj],
            nextMsgResolver[p2pRequestCompleteObj])
proc WhisperPeerConnected(peer: Peer) {.gcsafe, async.} =
  type
    CurrentProtocol = Whisper
  template state(peer: Peer): ref[WhisperPeer:ObjectType] =
    cast[ref[WhisperPeer:ObjectType]](getState(peer, WhisperProtocol))

  template networkState(peer: Peer): ref[WhisperNetwork:ObjectType] =
    cast[ref[WhisperNetwork:ObjectType]](getNetworkState(peer.network,
        WhisperProtocol))

  trace "onPeerConnected Whisper"
  let
    whisperNet = peer.networkState
    whisperPeer = peer.state
  let m = await peer.status(whisperVersion,
                        cast[uint64](whisperNet.config.powRequirement),
                        @(whisperNet.config.bloom),
                        whisperNet.config.isLightNode,
                        timeout = chronos.milliseconds(5000))
  if m.protocolVersion == whisperVersion:
    debug "Whisper peer", peer, whisperVersion
  else:
    raise newException(UselessPeerError, "Incompatible Whisper version")
  whisperPeer.powRequirement = cast[float64](m.powConverted)
  if m.bloom.len > 0:
    if m.bloom.len != bloomSize:
      raise newException(UselessPeerError, "Bloomfilter size mismatch")
    else:
      whisperPeer.bloom.bytesCopy(m.bloom)
  else:
    whisperPeer.bloom = fullBloom()
  whisperPeer.isLightNode = m.isLightNode
  if whisperPeer.isLightNode and whisperNet.config.isLightNode:
    raise newException(UselessPeerError, "Two light nodes connected")
  whisperPeer.received.init()
  whisperPeer.trusted = false
  whisperPeer.initialized = true
  if not whisperNet.config.isLightNode:
    traceAsyncErrors peer.run()
  debug "Whisper peer initialized", peer

setEventHandlers(WhisperProtocol, WhisperPeerConnected, nil)
registerProtocol(WhisperProtocol)