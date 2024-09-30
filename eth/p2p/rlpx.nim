# nim-eth
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at
#     https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at
#     https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

## This module implements the `RLPx` Transport Protocol defined at
## `RLPx <https://github.com/ethereum/devp2p/blob/master/rlpx.md>`_.
##
## Use NIM command line optipn `-d:p2pProtocolDebug` for dumping the
## generated driver code (just to have it stored somewhere lest one forgets.)
##
## Both, the message ID and the request/response ID are now unsigned. This goes
## along with the RLPx specs (see above) and the sub-protocol specs at
## `sub-proto <https://github.com/ethereum/devp2p/tree/master/caps>`_ plus the
## fact that RLP is defined for non-negative integers smaller than 2^64 only at
## `Yellow Paper <https://ethereum.github.io/yellowpaper/paper.pdf#appendix.B>`_,
## Appx B, clauses (195) ff and (199).
##

{.push raises: [].}

import
  std/[algorithm, deques, options, typetraits, os],
  stew/shims/macros, chronicles, nimcrypto/utils, chronos, metrics,
  ".."/[rlp, common, async_utils],
  ./private/p2p_types, "."/[kademlia, auth, rlpxcrypt, enode, p2p_protocol_dsl]

# TODO: This doesn't get enabled currently in any of the builds, so we send a
# devp2p protocol handshake message with version. Need to check if some peers
# drop us because of this.
when useSnappy:
  import snappy
  const devp2pSnappyVersion* = 5

# TODO: chronicles re-export here is added for the error
# "undeclared identifier: 'activeChroniclesStream'", when the code using p2p
# does not import chronicles. Need to resolve this properly.
export
  options, p2pProtocol, rlp, chronicles, metrics

declarePublicGauge rlpx_connected_peers,
  "Number of connected peers in the pool"

declarePublicCounter rlpx_connect_success,
  "Number of successfull rlpx connects"

declarePublicCounter rlpx_connect_failure,
  "Number of rlpx connects that failed", labels = ["reason"]

declarePublicCounter rlpx_accept_success,
  "Number of successful rlpx accepted peers"

declarePublicCounter rlpx_accept_failure,
  "Number of rlpx accept attempts that failed", labels = ["reason"]

logScope:
  topics = "eth p2p rlpx"

type
  ResponderWithId*[MsgType] = object
    peer*: Peer
    reqId*: uint64

  ResponderWithoutId*[MsgType] = distinct Peer

  # We need these two types in rlpx/devp2p as no parameters or single parameters
  # are not getting encoded in an rlp list.
  # TODO: we could generalize this in the protocol dsl but it would need an
  # `alwaysList` flag as not every protocol expects lists in these cases.
  EmptyList = object
  DisconnectionReasonList = object
    value: DisconnectionReason

  Address = enode.Address

proc read(rlp: var Rlp; T: type DisconnectionReasonList): T
    {.gcsafe, raises: [RlpError].} =
  ## Rlp mixin: `DisconnectionReasonList` parser

  if rlp.isList:
    # Be strict here: The expression `rlp.read(DisconnectionReasonList)`
    # accepts lists with at least one item. The array expression wants
    # exactly one item.
    if rlp.rawData.len < 3:
      # avoids looping through all items when parsing for an overlarge array
      return DisconnectionReasonList(
        value: rlp.read(array[1,DisconnectionReason])[0])

  # Also accepted: a single byte reason code. Is is typically used
  # by variants of the reference implementation `Geth`
  elif rlp.blobLen <= 1:
    return DisconnectionReasonList(
      value: rlp.read(DisconnectionReason))

  # Also accepted: a blob of a list (aka object) of reason code. It is
  # used by `bor`, a `geth` fork
  elif rlp.blobLen < 4:
    var subList = rlp.toBytes.rlpFromBytes
    if subList.isList:
      # Ditto, see above.
      return DisconnectionReasonList(
        value: subList.read(array[1,DisconnectionReason])[0])

  raise newException(RlpTypeMismatch, "Single entry list expected")


const
  devp2pVersion* = 4
  maxMsgSize = 1024 * 1024 * 10
  HandshakeTimeout = MessageTimeout

include p2p_tracing

when tracingEnabled:
  import
    eth/common/eth_types_json_serialization

  export
    # XXX: This is a work-around for a Nim issue.
    # See a more detailed comment in p2p_tracing.nim
    init, writeValue, getOutput

proc init*[MsgName](T: type ResponderWithId[MsgName],
                    peer: Peer, reqId: uint64): T =
  T(peer: peer, reqId: reqId)

proc init*[MsgName](T: type ResponderWithoutId[MsgName], peer: Peer): T =
  T(peer)

chronicles.formatIt(Peer): $(it.remote)
chronicles.formatIt(Opt[uint64]): (if it.isSome(): $it.value else: "-1")

include p2p_backends_helpers

proc requestResolver[MsgType](msg: pointer, future: FutureBase) {.gcsafe.} =
  var f = Future[Option[MsgType]](future)
  if not f.finished:
    if msg != nil:
      f.complete some(cast[ptr MsgType](msg)[])
    else:
      f.complete none(MsgType)
  else:
    # This future was already resolved, but let's do some sanity checks
    # here. The only reasonable explanation is that the request should
    # have timed out.
    if msg != nil:
      try:
        if f.read.isSome:
          doAssert false, "trying to resolve a request twice"
        else:
          doAssert false, "trying to resolve a timed out request with a value"
      except CatchableError as e:
        debug "Exception in requestResolver()", err = e.msg, errName = e.name
    else:
      try:
        if not f.read.isSome:
          doAssert false, "a request timed out twice"
      # This can except when the future still completes with an error.
      # E.g. the `sendMsg` fails because of an already closed transport or a
      # broken pipe
      except TransportOsError as e:
        # E.g. broken pipe
        trace "TransportOsError during request", err = e.msg, errName = e.name
      except TransportError:
        trace "Transport got closed during request"
      except CatchableError as e:
        debug "Exception in requestResolver()", err = e.msg, errName = e.name

proc linkSendFailureToReqFuture[S, R](sendFut: Future[S], resFut: Future[R]) =
  sendFut.addCallback() do (arg: pointer):
    # Avoiding potentially double future completions
    if not resFut.finished:
      if sendFut.failed:
        resFut.fail(sendFut.error)

proc messagePrinter[MsgType](msg: pointer): string {.gcsafe.} =
  result = ""
  # TODO: uncommenting the line below increases the compile-time
  # tremendously (for reasons not yet known)
  # result = $(cast[ptr MsgType](msg)[])

proc disconnect*(peer: Peer, reason: DisconnectionReason,
  notifyOtherPeer = false) {.async: (raises:[]).}

template raisePeerDisconnected(msg: string, r: DisconnectionReason) =
  var e = newException(PeerDisconnected, msg)
  e.reason = r
  raise e

proc disconnectAndRaise(peer: Peer,
                        reason: DisconnectionReason,
                        msg: string) {.async:
                          (raises: [PeerDisconnected]).} =
  let r = reason
  await peer.disconnect(r)
  raisePeerDisconnected(msg, r)

proc handshakeImpl[T](peer: Peer,
                      sendFut: Future[void],
                      responseFut: Future[T],
                      timeout: Duration): Future[T] {.async:
                        (raises: [PeerDisconnected, P2PInternalError]).} =
  sendFut.addCallback do (arg: pointer) {.gcsafe.}:
    if sendFut.failed:
      debug "Handshake message not delivered", peer

  doAssert timeout.milliseconds > 0

  try:
    let res = await responseFut.wait(timeout)
    return res
  except AsyncTimeoutError:
    # TODO: Really shouldn't disconnect and raise everywhere. In order to avoid
    # understanding what error occured where.
    # And also, incoming and outgoing disconnect errors should be seperated,
    # probably by seperating the actual disconnect call to begin with.
    await disconnectAndRaise(peer, HandshakeTimeout,
                             "Protocol handshake was not received in time.")
  except CatchableError as exc:
    raise newException(P2PInternalError, exc.msg)

# Dispatcher
#

proc `==`(lhs, rhs: Dispatcher): bool =
  lhs.activeProtocols == rhs.activeProtocols

proc describeProtocols(d: Dispatcher): string =
  result = ""
  for protocol in d.activeProtocols:
    if result.len != 0: result.add(',')
    for c in protocol.name: result.add(c)

proc numProtocols(d: Dispatcher): int =
  d.activeProtocols.len

proc getDispatcher(node: EthereumNode,
                   otherPeerCapabilities: openArray[Capability]): Dispatcher =
  # TODO: sub-optimal solution until progress is made here:
  # https://github.com/nim-lang/Nim/issues/7457
  # We should be able to find an existing dispatcher without allocating a new one

  new result
  newSeq(result.protocolOffsets, protocolCount())
  result.protocolOffsets.fill Opt.none(uint)

  var nextUserMsgId = 0x10u

  for localProtocol in node.protocols:
    let idx = localProtocol.index
    block findMatchingProtocol:
      for remoteCapability in otherPeerCapabilities:
        if localProtocol.name == remoteCapability.name and
           localProtocol.version == remoteCapability.version:
          result.protocolOffsets[idx] = Opt.some(nextUserMsgId)
          nextUserMsgId += localProtocol.messages.len.uint64
          break findMatchingProtocol

  template copyTo(src, dest; index: int) =
    for i in 0 ..< src.len:
      dest[index + i] = src[i]

  result.messages = newSeq[MessageInfo](nextUserMsgId)
  devp2pInfo.messages.copyTo(result.messages, 0)

  for localProtocol in node.protocols:
    let idx = localProtocol.index
    if result.protocolOffsets[idx].isSome:
      result.activeProtocols.add localProtocol
      localProtocol.messages.copyTo(result.messages,
                                    result.protocolOffsets[idx].value.int)

proc getMsgName*(peer: Peer, msgId: uint64): string =
  if not peer.dispatcher.isNil and
     msgId < peer.dispatcher.messages.len.uint64 and
     not peer.dispatcher.messages[msgId].isNil:
    return peer.dispatcher.messages[msgId].name
  else:
    return case msgId
           of 0: "hello"
           of 1: "disconnect"
           of 2: "ping"
           of 3: "pong"
           else: $msgId

proc getMsgMetadata*(peer: Peer, msgId: uint64): (ProtocolInfo, MessageInfo) =
  doAssert msgId >= 0

  let dpInfo = devp2pInfo()
  if msgId <= dpInfo.messages[^1].id:
    return (dpInfo, dpInfo.messages[msgId])

  if msgId < peer.dispatcher.messages.len.uint64:
    let numProtocol = protocolCount()
    for i in 0 ..< numProtocol:
      let protocol = getProtocol(i)
      let offset = peer.dispatcher.protocolOffsets[i]
      if offset.isSome and
         offset.value + protocol.messages[^1].id >= msgId:
        return (protocol, peer.dispatcher.messages[msgId])

# Protocol info objects
#

proc initProtocol(name: string, version: uint64,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer): ProtocolInfo =
  ProtocolInfo(
    name    : name,
    version : version,
    messages: @[],
    peerStateInitializer: peerInit,
    networkStateInitializer: networkInit
  )

proc setEventHandlers(p: ProtocolInfo,
                      handshake: HandshakeStep,
                      disconnectHandler: DisconnectionHandler) =
  p.handshake = handshake
  p.disconnectHandler = disconnectHandler

func asCapability*(p: ProtocolInfo): Capability =
  result.name = p.name
  result.version = p.version

proc cmp*(lhs, rhs: ProtocolInfo): int =
  return cmp(lhs.name, rhs.name)

proc nextMsgResolver[MsgType](msgData: Rlp, future: FutureBase)
    {.gcsafe, raises: [RlpError].} =
  var reader = msgData
  Future[MsgType](future).complete reader.readRecordType(MsgType,
    MsgType.rlpFieldsCount > 1)

proc registerMsg(protocol: ProtocolInfo,
                 msgId: uint64,
                 name: string,
                 thunk: ThunkProc,
                 printer: MessageContentPrinter,
                 requestResolver: RequestResolver,
                 nextMsgResolver: NextMsgResolver) =
  if protocol.messages.len.uint64 <= msgId:
    protocol.messages.setLen(msgId + 1)
  protocol.messages[msgId] = MessageInfo(
    id: msgId,
    name: name,
    thunk: thunk,
    printer: printer,
    requestResolver: requestResolver,
    nextMsgResolver: nextMsgResolver)

# Message composition and encryption
#

proc perPeerMsgIdImpl(peer: Peer, proto: ProtocolInfo, msgId: uint64): uint64 =
  result = msgId
  if not peer.dispatcher.isNil:
    result += peer.dispatcher.protocolOffsets[proto.index].value

template getPeer(peer: Peer): auto = peer
template getPeer(responder: ResponderWithId): auto = responder.peer
template getPeer(responder: ResponderWithoutId): auto = Peer(responder)

proc supports*(peer: Peer, proto: ProtocolInfo): bool =
  peer.dispatcher.protocolOffsets[proto.index].isSome

proc supports*(peer: Peer, Protocol: type): bool =
  ## Checks whether a Peer supports a particular protocol
  peer.supports(Protocol.protocolInfo)

template perPeerMsgId(peer: Peer, MsgType: type): uint64 =
  perPeerMsgIdImpl(peer, MsgType.msgProtocol.protocolInfo, MsgType.msgId)

proc invokeThunk*(peer: Peer, msgId: uint64, msgData: Rlp): Future[void]
    {.async: (raises: [rlp.RlpError, EthP2PError]).} =
  template invalidIdError: untyped =
    raise newException(UnsupportedMessageError,
      "RLPx message with an invalid id " & $msgId &
      " on a connection supporting " & peer.dispatcher.describeProtocols)

  # msgId can be negative as it has int as type and gets decoded from rlp
  if msgId >= peer.dispatcher.messages.len.uint64: invalidIdError()
  if peer.dispatcher.messages[msgId].isNil: invalidIdError()

  let thunk = peer.dispatcher.messages[msgId].thunk
  if thunk == nil: invalidIdError()

  await thunk(peer, msgId, msgData)

template compressMsg(peer: Peer, data: seq[byte]): seq[byte] =
  when useSnappy:
    if peer.snappyEnabled:
      snappy.encode(data)
    else: data
  else:
    data

proc sendMsg*(peer: Peer, data: seq[byte]) {.async.} =
  var cipherText = encryptMsg(peer.compressMsg(data), peer.secretsState)
  try:
    var res = await peer.transport.write(cipherText)
    if res != len(cipherText):
      # This is ECONNRESET or EPIPE case when remote peer disconnected.
      await peer.disconnect(TcpError)
      discard
  except CatchableError as e:
    await peer.disconnect(TcpError)
    raise e

proc send*[Msg](peer: Peer, msg: Msg): Future[void] =
  logSentMsg(peer, msg)

  var rlpWriter = initRlpWriter()
  rlpWriter.append perPeerMsgId(peer, Msg)
  rlpWriter.appendRecordType(msg, Msg.rlpFieldsCount > 1)
  peer.sendMsg rlpWriter.finish

proc registerRequest(peer: Peer,
                     timeout: Duration,
                     responseFuture: FutureBase,
                     responseMsgId: uint64): uint64 =
  result = if peer.lastReqId.isNone: 0u else: peer.lastReqId.value + 1u
  peer.lastReqId = Opt.some(result)

  let timeoutAt = Moment.fromNow(timeout)
  let req = OutstandingRequest(id: result,
                               future: responseFuture,
                               timeoutAt: timeoutAt)
  peer.outstandingRequests[responseMsgId].addLast req

  doAssert(not peer.dispatcher.isNil)
  let requestResolver = peer.dispatcher.messages[responseMsgId].requestResolver
  proc timeoutExpired(udata: pointer) {.gcsafe.} =
    requestResolver(nil, responseFuture)

  discard setTimer(timeoutAt, timeoutExpired, nil)

proc resolveResponseFuture(peer: Peer, msgId: uint64, msg: pointer) =
  ## This function is a split off from the previously combined version with
  ## the same name using optional request ID arguments. This here is the
  ## version without a request ID (there is the other part below.).
  ##
  ## Optional arguments for macro helpers seem easier to handle with
  ## polymorphic functions (than a `Opt[]` prototype argument.)
  ##
  logScope:
    msg = peer.dispatcher.messages[msgId].name
    msgContents = peer.dispatcher.messages[msgId].printer(msg)
    receivedReqId = -1
    remotePeer = peer.remote

  template resolve(future) =
    (peer.dispatcher.messages[msgId].requestResolver)(msg, future)

  template outstandingReqs: auto =
    peer.outstandingRequests[msgId]

  block: # no request ID
    # XXX: This is a response from an ETH-like protocol that doesn't feature
    # request IDs. Handling the response is quite tricky here because this may
    # be a late response to an already timed out request or a valid response
    # from a more recent one.
    #
    # We can increase the robustness by recording enough features of the
    # request so we can recognize the matching response, but this is not very
    # easy to do because our peers are allowed to send partial responses.
    #
    # A more generally robust approach is to maintain a set of the wanted
    # data items and then to periodically look for items that have been
    # requested long time ago, but are still missing. New requests can be
    # issues for such items potentially from another random peer.
    var expiredRequests = 0
    for req in outstandingReqs:
      if not req.future.finished: break
      inc expiredRequests
    outstandingReqs.shrink(fromFirst = expiredRequests)
    if outstandingReqs.len > 0:
      let oldestReq = outstandingReqs.popFirst
      resolve oldestReq.future
    else:
      trace "late or dup RPLx reply ignored", msgId

proc resolveResponseFuture(peer: Peer, msgId: uint64, msg: pointer, reqId: uint64) =
  ## Variant of `resolveResponseFuture()` for request ID argument.
  logScope:
    msg = peer.dispatcher.messages[msgId].name
    msgContents = peer.dispatcher.messages[msgId].printer(msg)
    receivedReqId = reqId
    remotePeer = peer.remote

  template resolve(future) =
    (peer.dispatcher.messages[msgId].requestResolver)(msg, future)

  template outstandingReqs: auto =
    peer.outstandingRequests[msgId]

  block: # have request ID
    # TODO: This is not completely sound because we are still using a global
    # `reqId` sequence (the problem is that we might get a response ID that
    # matches a request ID for a different type of request). To make the code
    # correct, we can use a separate sequence per response type, but we have
    # to first verify that the other Ethereum clients are supporting this
    # correctly (because then, we'll be reusing the same reqIds for different
    # types of requests). Alternatively, we can assign a separate interval in
    # the `reqId` space for each type of response.
    if peer.lastReqId.isNone or reqId > peer.lastReqId.value:
      debug "RLPx response without matching request", msgId, reqId
      return

    var idx = 0
    while idx < outstandingReqs.len:
      template req: auto = outstandingReqs()[idx]

      if req.future.finished:
        doAssert req.timeoutAt <= Moment.now()
        # Here we'll remove the expired request by swapping
        # it with the last one in the deque (if necessary):
        if idx != outstandingReqs.len - 1:
          req = outstandingReqs.popLast
          continue
        else:
          outstandingReqs.shrink(fromLast = 1)
          # This was the last item, so we don't have any
          # more work to do:
          return

      if req.id == reqId:
        resolve req.future
        # Here we'll remove the found request by swapping
        # it with the last one in the deque (if necessary):
        if idx != outstandingReqs.len - 1:
          req = outstandingReqs.popLast
        else:
          outstandingReqs.shrink(fromLast = 1)
        return

      inc idx

    trace "late or dup RPLx reply ignored"


proc recvMsg*(peer: Peer): Future[tuple[msgId: uint64, msgData: Rlp]] {.async.} =
  ##  This procs awaits the next complete RLPx message in the TCP stream

  var headerBytes: array[32, byte]
  await peer.transport.readExactly(addr headerBytes[0], 32)

  var msgSize: int
  var msgHeader: RlpxHeader
  if decryptHeaderAndGetMsgSize(peer.secretsState,
                                headerBytes, msgSize, msgHeader).isErr():
    await peer.disconnectAndRaise(BreachOfProtocol,
                                  "Cannot decrypt RLPx frame header")

  if msgSize > maxMsgSize:
    await peer.disconnectAndRaise(BreachOfProtocol,
                                  "RLPx message exceeds maximum size")

  let remainingBytes = encryptedLength(msgSize) - 32
  # TODO: Migrate this to a thread-local seq
  # JACEK:
  #  or pass it in, allowing the caller to choose - they'll likely be in a
  #  better position to decide if buffer should be reused or not. this will
  #  also be useful for chunked messages where part of the buffer may have
  #  been processed and needs filling in
  var encryptedBytes = newSeq[byte](remainingBytes)
  await peer.transport.readExactly(addr encryptedBytes[0], len(encryptedBytes))

  let decryptedMaxLength = decryptedLength(msgSize)
  var
    decryptedBytes = newSeq[byte](decryptedMaxLength)
    decryptedBytesCount = 0

  if decryptBody(peer.secretsState, encryptedBytes, msgSize,
                 decryptedBytes, decryptedBytesCount).isErr():
    await peer.disconnectAndRaise(BreachOfProtocol,
                                  "Cannot decrypt RLPx frame body")

  decryptedBytes.setLen(decryptedBytesCount)

  when useSnappy:
    if peer.snappyEnabled:
      decryptedBytes = snappy.decode(decryptedBytes, maxMsgSize)
      if decryptedBytes.len == 0:
        await peer.disconnectAndRaise(BreachOfProtocol,
                                      "Snappy uncompress encountered malformed data")

  # Check embedded header-data for start of an obsoleted chunked message.
  # Note that the check should come *before* the `msgId` is read. For
  # instance, if this is a malformed packet, then the `msgId` might be
  # random which in turn might try to access a `peer.dispatcher.messages[]`
  # slot with a `nil` entry.
  #
  # The current RLPx requirements need both tuuple entries be zero, see
  # github.com/ethereum/devp2p/blob/master/rlpx.md#framing
  #
  if (msgHeader[4] and 127) != 0 or # capability-id, now required to be zero
     (msgHeader[5] and 127) != 0:   # context-id, now required to be zero
    await peer.disconnectAndRaise(
      BreachOfProtocol, "Rejected obsoleted chunked message header")

  var rlp = rlpFromBytes(decryptedBytes)

  var msgId: uint32
  try:
    # uint32 as this seems more than big enough for the amount of msgIds
    msgId = rlp.read(uint32)
    result = (msgId.uint64, rlp)
  except RlpError:
    await peer.disconnectAndRaise(BreachOfProtocol,
                                  "Cannot read RLPx message id")


proc checkedRlpRead(peer: Peer, r: var Rlp, MsgType: type):
    auto {.raises: [RlpError].} =
  when defined(release):
    return r.read(MsgType)
  else:
    try:
      return r.read(MsgType)
    except rlp.RlpError as e:
      debug "Failed rlp.read",
            peer = peer,
            dataType = MsgType.name,
            err = e.msg,
            errName = e.name
            #, rlpData = r.inspect -- don't use (might crash)

      raise e

proc waitSingleMsg(peer: Peer, MsgType: type): Future[MsgType] {.async.} =
  let wantedId = peer.perPeerMsgId(MsgType)
  while true:
    var (nextMsgId, nextMsgData) = await peer.recvMsg()

    if nextMsgId == wantedId:
      try:
        result = checkedRlpRead(peer, nextMsgData, MsgType)
        logReceivedMsg(peer, result)
        return
      except rlp.RlpError:
        await peer.disconnectAndRaise(BreachOfProtocol,
                                      "Invalid RLPx message body")

    elif nextMsgId == 1: # p2p.disconnect
      # TODO: can still raise RlpError here...?
      let reasonList = nextMsgData.read(DisconnectionReasonList)
      let reason = reasonList.value
      await peer.disconnect(reason)
      trace "disconnect message received in waitSingleMsg", reason, peer
      raisePeerDisconnected("Unexpected disconnect", reason)
    else:
      debug "Dropped RLPX message",
        msg = peer.dispatcher.messages[nextMsgId].name
      # TODO: This is breach of protocol?

proc nextMsg*(peer: Peer, MsgType: type): Future[MsgType] =
  ## This procs awaits a specific RLPx message.
  ## Any messages received while waiting will be dispatched to their
  ## respective handlers. The designated message handler will also run
  ## to completion before the future returned by `nextMsg` is resolved.
  let wantedId = peer.perPeerMsgId(MsgType)
  let f = peer.awaitedMessages[wantedId]
  if not f.isNil:
    return Future[MsgType](f)

  initFuture result
  peer.awaitedMessages[wantedId] = result

# Known fatal errors are handled inside dispatchMessages.
# Errors we are currently unaware of are caught in the dispatchMessages
# callback. There they will be logged if CatchableError and quit on Defect.
# Non fatal errors such as the current CatchableError could be moved and
# handled a layer lower for clarity (and consistency), as also the actual
# message handler code as the TODO mentions already.
proc dispatchMessages*(peer: Peer) {.async.} =
  while peer.connectionState notin {Disconnecting, Disconnected}:
    var msgId: uint64
    var msgData: Rlp
    try:
      (msgId, msgData) = await peer.recvMsg()
    except TransportError:
      # Note: This will also catch TransportIncompleteError. TransportError will
      # here usually occur when a read is attempted when the transport is
      # already closed. TransportIncompleteError when the transport is closed
      # during read.
      case peer.connectionState
      of Connected:
        # Dropped connection, still need to cleanup the peer.
        # This could be seen as bad behaving peer.
        trace "Dropped connection", peer
        await peer.disconnect(ClientQuitting, false)
        return
      of Disconnecting, Disconnected:
        # Graceful disconnect, can still cause TransportIncompleteError as it
        # could be that this loop was waiting at recvMsg().
        return
      else:
        # Connection dropped while `Connecting` (in rlpxConnect/rlpxAccept).
        return
    except PeerDisconnected:
      return

    try:
      await peer.invokeThunk(msgId, msgData)
    except RlpError as e:
      debug "RlpError, ending dispatchMessages loop", peer,
        msg = peer.getMsgName(msgId), err = e.msg, errName = e.name
      await peer.disconnect(BreachOfProtocol, true)
      return
    except EthP2PError as e:
      debug "Error while handling RLPx message", peer,
        msg = peer.getMsgName(msgId), err = e.msg, errName = e.name

    # TODO: Hmm, this can be safely moved into the message handler thunk.
    # The documentation will need to be updated, explaining the fact that
    # nextMsg will be resolved only if the message handler has executed
    # successfully.
    if msgId < peer.awaitedMessages.len.uint64 and
       peer.awaitedMessages[msgId] != nil:
      let msgInfo = peer.dispatcher.messages[msgId]
      try:
        (msgInfo.nextMsgResolver)(msgData, peer.awaitedMessages[msgId])
      except CatchableError as e:
        # TODO: Handling errors here must be investigated more carefully.
        # They also are supposed to be handled at the call-site where
        # `nextMsg` is used.
        debug "nextMsg resolver failed, ending dispatchMessages loop", peer,
          msg = peer.getMsgName(msgId), err = e.msg
        await peer.disconnect(BreachOfProtocol, true)
        return
      peer.awaitedMessages[msgId] = nil

proc p2pProtocolBackendImpl*(protocol: P2PProtocol): Backend =
  let
    resultIdent = ident "result"
    Peer = bindSym "Peer"
    EthereumNode = bindSym "EthereumNode"

    initRlpWriter = bindSym "initRlpWriter"
    append = bindSym("append", brForceOpen)
    read = bindSym("read", brForceOpen)
    checkedRlpRead = bindSym "checkedRlpRead"
    startList = bindSym "startList"
    tryEnterList = bindSym "tryEnterList"
    finish = bindSym "finish"

    messagePrinter = bindSym "messagePrinter"
    nextMsgResolver = bindSym "nextMsgResolver"
    registerRequest = bindSym "registerRequest"
    requestResolver = bindSym "requestResolver"
    resolveResponseFuture = bindSym "resolveResponseFuture"
    sendMsg = bindSym "sendMsg"
    nextMsg = bindSym "nextMsg"
    initProtocol = bindSym"initProtocol"
    registerMsg = bindSym "registerMsg"
    perPeerMsgId = bindSym "perPeerMsgId"
    perPeerMsgIdImpl = bindSym "perPeerMsgIdImpl"
    linkSendFailureToReqFuture = bindSym "linkSendFailureToReqFuture"
    handshakeImpl = bindSym "handshakeImpl"

    ResponderWithId = bindSym "ResponderWithId"
    ResponderWithoutId = bindSym "ResponderWithoutId"

    isSubprotocol = protocol.rlpxName != "p2p"

  if protocol.rlpxName.len == 0: protocol.rlpxName = protocol.name
  # By convention, all Ethereum protocol names have at least 3 characters.
  doAssert protocol.rlpxName.len >= 3

  new result

  result.registerProtocol = bindSym "registerProtocol"
  result.setEventHandlers = bindSym "setEventHandlers"
  result.PeerType = Peer
  result.NetworkType = EthereumNode
  result.ResponderType = if protocol.useRequestIds: ResponderWithId
                         else: ResponderWithoutId

  result.implementMsg = proc (msg: Message) =
    # FIXME: Or is it already assured that `msgId` is available?
    doAssert msg.id.isSome

    var
      msgIdValue = msg.id.value
      msgIdent = msg.ident
      msgName = $msgIdent
      msgRecName = msg.recName
      responseMsgId = if msg.response.isNil: Opt.none(uint64) else: msg.response.id
      hasReqId = msg.hasReqId
      protocol = msg.protocol

      # variables used in the sending procs
      peerOrResponder = ident"peerOrResponder"
      rlpWriter = ident"writer"
      perPeerMsgIdVar  = ident"perPeerMsgId"

      # variables used in the receiving procs
      receivedRlp = ident"rlp"
      receivedMsg = ident"msg"

    var
      readParams = newNimNode(nnkStmtList)
      paramsToWrite = newSeq[NimNode](0)
      appendParams = newNimNode(nnkStmtList)

    if hasReqId:
      # Messages using request Ids
      readParams.add quote do:
        let `reqIdVar` = `read`(`receivedRlp`, uint64)

    case msg.kind
    of msgRequest:
      doAssert responseMsgId.isSome

      let reqToResponseOffset = responseMsgId.value - msgIdValue
      let responseMsgId = quote do: `perPeerMsgIdVar` + `reqToResponseOffset`

      # Each request is registered so we can resolve it when the response
      # arrives. There are two types of protocols: LES-like protocols use
      # explicit `reqId` sent over the wire, while the ETH wire protocol
      # assumes there is one outstanding request at a time (if there are
      # multiple requests we'll resolve them in FIFO order).
      let registerRequestCall = newCall(registerRequest, peerVar,
                                                         timeoutVar,
                                                         resultIdent,
                                                         responseMsgId)
      if hasReqId:
        appendParams.add quote do:
          initFuture `resultIdent`
          let `reqIdVar` = `registerRequestCall`
        paramsToWrite.add reqIdVar
      else:
        appendParams.add quote do:
          initFuture `resultIdent`
          discard `registerRequestCall`

    of msgResponse:
      if hasReqId:
        paramsToWrite.add newDotExpr(peerOrResponder, reqIdVar)

    of msgHandshake, msgNotification: discard

    for param, paramType in msg.procDef.typedParams(skip = 1):
      # This is a fragment of the sending proc that
      # serializes each of the passed parameters:
      paramsToWrite.add param

      # The received RLP data is deserialized to a local variable of
      # the message-specific type. This is done field by field here:
      readParams.add quote do:
        `receivedMsg`.`param` = `checkedRlpRead`(`peerVar`, `receivedRlp`, `paramType`)

    let
      paramCount = paramsToWrite.len
      readParamsPrelude = if paramCount > 1: newCall(tryEnterList, receivedRlp)
                          else: newStmtList()

    when tracingEnabled:
      readParams.add newCall(bindSym"logReceivedMsg", peerVar, receivedMsg)

    let callResolvedResponseFuture =
      if msg.kind != msgResponse:
        newStmtList()
      elif hasReqId:
        newCall(resolveResponseFuture,
                peerVar,
                newCall(perPeerMsgId, peerVar, msgRecName),
                newCall("addr", receivedMsg),
                reqIdVar)
      else:
        newCall(resolveResponseFuture,
                peerVar,
                newCall(perPeerMsgId, peerVar, msgRecName),
                newCall("addr", receivedMsg))

    var userHandlerParams = @[peerVar]
    if hasReqId: userHandlerParams.add reqIdVar

    let
      awaitUserHandler = msg.genAwaitUserHandler(receivedMsg, userHandlerParams)
      thunkName = ident(msgName & "Thunk")

    msg.defineThunk quote do:
      proc `thunkName`(`peerVar`: `Peer`, _: uint64, data: Rlp)
          # Fun error if you just use `RlpError` instead of `rlp.RlpError`:
          # "Error: type expected, but got symbol 'RlpError' of kind 'EnumField'"
          {.async: (raises: [rlp.RlpError, EthP2PError]).} =
        var `receivedRlp` = data
        var `receivedMsg` {.noinit.}: `msgRecName`
        `readParamsPrelude`
        `readParams`
        `awaitUserHandler`
        `callResolvedResponseFuture`

    var sendProc = msg.createSendProc(isRawSender = (msg.kind == msgHandshake))
    sendProc.def.params[1][0] = peerOrResponder

    let
      msgBytes = ident"msgBytes"
      finalizeRequest = quote do:
        let `msgBytes` = `finish`(`rlpWriter`)

    var sendCall = newCall(sendMsg, peerVar, msgBytes)
    let senderEpilogue = if msg.kind == msgRequest:
      # In RLPx requests, the returned future was allocated here and passed
      # to `registerRequest`. It's already assigned to the result variable
      # of the proc, so we just wait for the sending operation to complete
      # and we return in a normal way. (the waiting is done, so we can catch
      # any possible errors).
      quote: `linkSendFailureToReqFuture`(`sendCall`, `resultIdent`)
    else:
      # In normal RLPx messages, we are returning the future returned by the
      # `sendMsg` call.
      quote: return `sendCall`

    let perPeerMsgIdValue = if isSubprotocol:
      newCall(perPeerMsgIdImpl, peerVar, protocol.protocolInfo, newLit(msgIdValue))
    else:
      newLit(msgIdValue)

    if paramCount > 1:
      # In case there are more than 1 parameter,
      # the params must be wrapped in a list:
      appendParams = newStmtList(
        newCall(startList, rlpWriter, newLit(paramCount)),
        appendParams)

    for param in paramsToWrite:
      appendParams.add newCall(append, rlpWriter, param)

    let initWriter = quote do:
      var `rlpWriter` = `initRlpWriter`()
      const `perProtocolMsgIdVar` {.used.} = `msgIdValue`
      let `perPeerMsgIdVar` = `perPeerMsgIdValue`
      `append`(`rlpWriter`, `perPeerMsgIdVar`)

    when tracingEnabled:
      appendParams.add logSentMsgFields(peerVar, protocol, msgId, paramsToWrite)

    # let paramCountNode = newLit(paramCount)
    sendProc.setBody quote do:
      let `peerVar` = getPeer(`peerOrResponder`)
      `initWriter`
      `appendParams`
      `finalizeRequest`
      `senderEpilogue`

    if msg.kind == msgHandshake:
      discard msg.createHandshakeTemplate(sendProc.def.name, handshakeImpl, nextMsg)

    protocol.outProcRegistrations.add(
      newCall(registerMsg,
              protocolVar,
              newLit(msgIdValue),
              newLit(msgName),
              thunkName,
              newTree(nnkBracketExpr, messagePrinter, msgRecName),
              newTree(nnkBracketExpr, requestResolver, msgRecName),
              newTree(nnkBracketExpr, nextMsgResolver, msgRecName)))

  result.implementProtocolInit = proc (protocol: P2PProtocol): NimNode =
    return newCall(initProtocol,
                   newLit(protocol.rlpxName),
                   newLit(protocol.version),
                   protocol.peerInit, protocol.netInit)


p2pProtocol DevP2P(version = 5, rlpxName = "p2p"):
  proc hello(peer: Peer,
             version: uint64,
             clientId: string,
             capabilities: seq[Capability],
             listenPort: uint,
             nodeId: array[RawPublicKeySize, byte])

  proc sendDisconnectMsg(peer: Peer, reason: DisconnectionReasonList) =
    trace "disconnect message received", reason=reason.value, peer
    await peer.disconnect(reason.value, false)

  # Adding an empty RLP list as the spec defines.
  # The parity client specifically checks if there is rlp data.
  proc ping(peer: Peer, emptyList: EmptyList) =
    discard peer.pong(EmptyList())

  proc pong(peer: Peer, emptyList: EmptyList) =
    discard

proc removePeer(network: EthereumNode, peer: Peer) =
  # It is necessary to check if peer.remote still exists. The connection might
  # have been dropped already from the peers side.
  # E.g. when receiving a p2p.disconnect message from a peer, a race will happen
  # between which side disconnects first.
  if network.peerPool != nil and not peer.remote.isNil and
      peer.remote in network.peerPool.connectedNodes:
    network.peerPool.connectedNodes.del(peer.remote)
    rlpx_connected_peers.dec()

    # Note: we need to do this check as disconnect (and thus removePeer)
    # currently can get called before the dispatcher is initialized.
    if not peer.dispatcher.isNil:
      for observer in network.peerPool.observers.values:
        if not observer.onPeerDisconnected.isNil:
          if observer.protocol.isNil or peer.supports(observer.protocol):
            observer.onPeerDisconnected(peer)

proc callDisconnectHandlers(peer: Peer, reason: DisconnectionReason):
    Future[void] {.async: (raises: []).} =
  var futures = newSeqOfCap[Future[void]](protocolCount())

  for protocol in peer.dispatcher.activeProtocols:
    if protocol.disconnectHandler != nil:
      futures.add((protocol.disconnectHandler)(peer, reason))

  await noCancel allFutures(futures)

  for f in futures:
    doAssert(f.finished())
    if f.failed():
      trace "Disconnection handler ended with an error", err = f.error.msg

proc disconnect*(peer: Peer, reason: DisconnectionReason,
    notifyOtherPeer = false) {.async: (raises: []).} =
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    # Do this first so sub-protocols have time to clean up and stop sending
    # before this node closes transport to remote peer
    if not peer.dispatcher.isNil:
      # In case of `CatchableError` in any of the handlers, this will be logged.
      # Other handlers will still execute.
      # In case of `Defect` in any of the handlers, program will quit.
      await callDisconnectHandlers(peer, reason)

    if notifyOtherPeer and not peer.transport.closed:

      proc waitAndClose(peer: Peer, time: Duration) {.async.} =
        await sleepAsync(time)
        await peer.transport.closeWait()

      try:
        await peer.sendDisconnectMsg(DisconnectionReasonList(value: reason))
      except CatchableError as e:
        trace "Failed to deliver disconnect message", peer,
          err = e.msg, errName = e.name

      # Give the peer a chance to disconnect
      traceAsyncErrors peer.waitAndClose(2.seconds)
    elif not peer.transport.closed:
      peer.transport.close()

    logDisconnectedPeer peer
    peer.connectionState = Disconnected
    removePeer(peer.network, peer)

func validatePubKeyInHello(msg: DevP2P.hello, pubKey: PublicKey): bool =
  let pk = PublicKey.fromRaw(msg.nodeId)
  pk.isOk and pk[] == pubKey

func checkUselessPeer(peer: Peer) {.raises: [UselessPeerError].} =
  if peer.dispatcher.numProtocols == 0:
    # XXX: Send disconnect + UselessPeer
    raise newException(UselessPeerError, "Useless peer")

proc initPeerState*(peer: Peer, capabilities: openArray[Capability])
    {.raises: [UselessPeerError].} =
  peer.dispatcher = getDispatcher(peer.network, capabilities)
  checkUselessPeer(peer)

  # The dispatcher has determined our message ID sequence.
  # For each message ID, we allocate a potential slot for
  # tracking responses to requests.
  # (yes, some of the slots won't be used).
  peer.outstandingRequests.newSeq(peer.dispatcher.messages.len)
  for d in mitems(peer.outstandingRequests):
    d = initDeque[OutstandingRequest]()

  # Similarly, we need a bit of book-keeping data to keep track
  # of the potentially concurrent calls to `nextMsg`.
  peer.awaitedMessages.newSeq(peer.dispatcher.messages.len)
  peer.lastReqId = Opt.some(0u64)
  peer.initProtocolStates peer.dispatcher.activeProtocols

proc postHelloSteps(peer: Peer, h: DevP2P.hello) {.async.} =
  initPeerState(peer, h.capabilities)

  # Please note that the ordering of operations here is important!
  #
  # We must first start all handshake procedures and give them a
  # chance to send any initial packages they might require over
  # the network and to yield on their `nextMsg` waits.
  #
  var subProtocolsHandshakes = newSeqOfCap[Future[void]](protocolCount())
  for protocol in peer.dispatcher.activeProtocols:
    if protocol.handshake != nil:
      subProtocolsHandshakes.add((protocol.handshake)(peer))

  # The `dispatchMessages` loop must be started after this.
  # Otherwise, we risk that some of the handshake packets sent by
  # the other peer may arrive too early and be processed before
  # the handshake code got a change to wait for them.
  #
  var messageProcessingLoop = peer.dispatchMessages()

  let cb = proc(p: pointer) {.gcsafe.} =
    if messageProcessingLoop.failed:
      debug "Ending dispatchMessages loop", peer,
            err = messageProcessingLoop.error.msg
      traceAsyncErrors peer.disconnect(ClientQuitting)

  messageProcessingLoop.addCallback(cb)

  # The handshake may involve multiple async steps, so we wait
  # here for all of them to finish.
  #
  await allFutures(subProtocolsHandshakes)

  for handshake in subProtocolsHandshakes:
    doAssert(handshake.finished())
    if handshake.failed():
      raise handshake.error

  # This is needed as a peer might have already disconnected. In this case
  # we need to raise so that rlpxConnect/rlpxAccept fails.
  # Disconnect is done only to run the disconnect handlers. TODO: improve this
  # also TODO: Should we discern the type of error?
  if messageProcessingLoop.finished:
    await peer.disconnectAndRaise(ClientQuitting,
                                  "messageProcessingLoop ended while connecting")
  peer.connectionState = Connected

template `^`(arr): auto =
  # passes a stack array with a matching `arrLen`
  # variable as an open array
  arr.toOpenArray(0, `arr Len` - 1)

proc initSecretState(p: Peer, hs: Handshake, authMsg, ackMsg: openArray[byte]) =
  var secrets = hs.getSecrets(authMsg, ackMsg)
  initSecretState(secrets, p.secretsState)
  burnMem(secrets)

template setSnappySupport(peer: Peer, node: EthereumNode, handshake: Handshake) =
  when useSnappy:
    peer.snappyEnabled = node.protocolVersion >= devp2pSnappyVersion.uint64 and
                         handshake.version >= devp2pSnappyVersion.uint64

template getVersion(handshake: Handshake): uint64 =
  when useSnappy:
    handshake.version
  else:
    devp2pVersion

template baseProtocolVersion(node: EthereumNode): untyped =
  when useSnappy:
    node.protocolVersion
  else:
    devp2pVersion

template baseProtocolVersion(peer: Peer): uint64 =
  when useSnappy:
    if peer.snappyEnabled: devp2pSnappyVersion
    else: devp2pVersion
  else:
    devp2pVersion

type
  RlpxError* = enum
    TransportConnectError,
    RlpxHandshakeTransportError,
    RlpxHandshakeError,
    ProtocolError,
    P2PHandshakeError,
    P2PTransportError,
    InvalidIdentityError,
    UselessRlpxPeerError,
    PeerDisconnectedError,
    TooManyPeersError

proc rlpxConnect*(node: EthereumNode, remote: Node):
    Future[Result[Peer, RlpxError]] {.async.} =
  # TODO: Should we not set some timeouts on the `connect` and `readExactly`s?
  # Or should we have a general timeout on the whole rlpxConnect where it gets
  # called?
  # Now, some parts could potential hang until a tcp timeout is hit?
  initTracing(devp2pInfo, node.protocols)

  let peer = Peer(remote: remote, network: node)
  let ta = initTAddress(remote.node.address.ip, remote.node.address.tcpPort)
  var error = true

  defer:
    if error: # TODO: Not sure if I like this much
      if not isNil(peer.transport):
        if not peer.transport.closed:
          peer.transport.close()

  peer.transport =
    try:
      await connect(ta)
    except TransportError:
      return err(TransportConnectError)
    except CatchableError as e:
      # Aside from TransportOsError, seems raw CatchableError can also occur?
      trace "TCP connect with peer failed", err = $e.name, errMsg = $e.msg
      return err(TransportConnectError)

  # RLPx initial handshake
  var
    handshake = Handshake.init(
      node.rng[], node.keys, {Initiator, EIP8}, node.baseProtocolVersion)
    authMsg: array[AuthMessageMaxEIP8, byte]
    authMsgLen = 0
  # TODO: Rework this so we won't have to pass an array as parameter?
  authMessage(
    handshake, node.rng[], remote.node.pubkey, authMsg, authMsgLen).tryGet()

  let writeRes =
    try:
      await peer.transport.write(addr authMsg[0], authMsgLen)
    except TransportError:
      return err(RlpxHandshakeTransportError)
    except CatchableError as e: # TODO: Only TransportErrors can occur?
      raiseAssert($e.name & " " & $e.msg)
  if writeRes != authMsgLen:
    return err(RlpxHandshakeTransportError)

  let initialSize = handshake.expectedLength
  var ackMsg = newSeqOfCap[byte](1024)
  ackMsg.setLen(initialSize)

  try:
    await peer.transport.readExactly(addr ackMsg[0], len(ackMsg))
  except TransportError:
    return err(RlpxHandshakeTransportError)
  except CatchableError as e:
    raiseAssert($e.name & " " & $e.msg)

  let res = handshake.decodeAckMessage(ackMsg)
  if res.isErr and res.error == AuthError.IncompleteError:
    ackMsg.setLen(handshake.expectedLength)
    try:
      await peer.transport.readExactly(addr ackMsg[initialSize],
                                         len(ackMsg) - initialSize)
    except TransportError:
      return err(RlpxHandshakeTransportError)
    except CatchableError as e: # TODO: Only TransportErrors can occur?
      raiseAssert($e.name & " " & $e.msg)

    # TODO: Bullet 1 of https://github.com/status-im/nim-eth/issues/559
    let res = handshake.decodeAckMessage(ackMsg)
    if res.isErr():
      trace "rlpxConnect handshake error", error = res.error
      return err(RlpxHandshakeError)

  peer.setSnappySupport(node, handshake)
  peer.initSecretState(handshake, ^authMsg, ackMsg)

  logConnectedPeer peer

  # RLPx p2p capability handshake: After the initial handshake, both sides of
  # the connection must send either Hello or a Disconnect message.
  let
    sendHelloFut = peer.hello(
      handshake.getVersion(),
      node.clientId,
      node.capabilities,
      uint(node.address.tcpPort),
      node.keys.pubkey.toRaw())

    receiveHelloFut = peer.waitSingleMsg(DevP2P.hello)

    response =
      try:
        await peer.handshakeImpl(
          sendHelloFut,
          receiveHelloFut,
          10.seconds)
      except RlpError:
        return err(ProtocolError)
      except PeerDisconnected:
        return err(PeerDisconnectedError)
        # TODO: Strange compiler error
        # case e.reason:
        # of HandshakeTimeout:
        #   # Yeah, a bit odd but in this case PeerDisconnected comes from a
        #   # timeout on the P2P Hello message. TODO: Clean-up that handshakeImpl
        #   return err(P2PHandshakeError)
        # of TooManyPeers:
        #   return err(TooManyPeersError)
        # else:
        #   return err(PeerDisconnectedError)
      except TransportError:
        return err(P2PTransportError)
      except P2PInternalError:
        return err(P2PHandshakeError)
      except CatchableError as e:
        raiseAssert($e.name & " " & $e.msg)

  if not validatePubKeyInHello(response, remote.node.pubkey):
    trace "Wrong devp2p identity in Hello message"
    return err(InvalidIdentityError)

  trace "DevP2P handshake completed", peer = remote,
    clientId = response.clientId

  try:
    await postHelloSteps(peer, response)
  except RlpError:
    return err(ProtocolError)
  except PeerDisconnected as e:
    case e.reason:
    of TooManyPeers:
      return err(TooManyPeersError)
    else:
      return err(PeerDisconnectedError)
  except UselessPeerError:
    return err(UselessRlpxPeerError)
  except TransportError:
    return err(P2PTransportError)
  except EthP2PError:
    return err(ProtocolError)
  except CatchableError as e:
    raiseAssert($e.name & " " & $e.msg)

  debug "Peer fully connected", peer = remote, clientId = response.clientId

  error = false

  return ok(peer)

# TODO: rework rlpxAccept similar to rlpxConnect.
proc rlpxAccept*(
    node: EthereumNode, transport: StreamTransport): Future[Peer] {.async: (raises: []).} =
  initTracing(devp2pInfo, node.protocols)

  let peer = Peer(transport: transport, network: node)
  var handshake = Handshake.init(node.rng[], node.keys, {auth.Responder})
  var ok = false
  try:
    let initialSize = handshake.expectedLength
    var authMsg = newSeqOfCap[byte](1024)

    authMsg.setLen(initialSize)
    # TODO: Should we not set some timeouts on these `readExactly`s?
    await transport.readExactly(addr authMsg[0], len(authMsg))
    var ret = handshake.decodeAuthMessage(authMsg)
    if ret.isErr and ret.error == AuthError.IncompleteError:
      # Eip8 auth message is possible, but not likely
      authMsg.setLen(handshake.expectedLength)
      await transport.readExactly(addr authMsg[initialSize],
                                  len(authMsg) - initialSize)
      ret = handshake.decodeAuthMessage(authMsg)

    if ret.isErr():
      # It is likely that errors on the handshake Auth is just garbage arriving
      # on the TCP port as it is the first data on the incoming connection,
      # hence log them as trace.
      trace "rlpxAccept handshake error", error = ret.error
      if not isNil(peer.transport):
        peer.transport.close()

      rlpx_accept_failure.inc()
      rlpx_accept_failure.inc(labelValues = ["handshake_error"])
      return nil

    ret.get()

    peer.setSnappySupport(node, handshake)
    handshake.version = uint8(peer.baseProtocolVersion)

    var ackMsg: array[AckMessageMaxEIP8, byte]
    var ackMsgLen: int
    handshake.ackMessage(node.rng[], ackMsg, ackMsgLen).tryGet()
    var res = await transport.write(addr ackMsg[0], ackMsgLen)
    if res != ackMsgLen:
      raisePeerDisconnected("Unexpected disconnect while authenticating",
                            TcpError)

    peer.initSecretState(handshake, authMsg, ^ackMsg)

    let listenPort = transport.localAddress().port

    logAcceptedPeer peer

    var sendHelloFut = peer.hello(
      peer.baseProtocolVersion,
      node.clientId,
      node.capabilities,
      listenPort.uint,
      node.keys.pubkey.toRaw())

    var response = await peer.handshakeImpl(
      sendHelloFut,
      peer.waitSingleMsg(DevP2P.hello),
      10.seconds)

    trace "Received Hello", version=response.version, id=response.clientId

    if not validatePubKeyInHello(response, handshake.remoteHPubkey):
      trace "A Remote nodeId is not its public key" # XXX: Do we care?

    let remote = transport.remoteAddress()
    let address = Address(ip: remote.address, tcpPort: remote.port,
                          udpPort: remote.port)
    peer.remote = newNode(
      ENode(pubkey: handshake.remoteHPubkey, address: address))

    trace "devp2p handshake completed", peer = peer.remote,
      clientId = response.clientId

    # In case there is an outgoing connection started with this peer we give
    # precedence to that one and we disconnect here with `AlreadyConnected`
    if peer.remote in node.peerPool.connectedNodes or
        peer.remote in node.peerPool.connectingNodes:
      trace "Duplicate connection in rlpxAccept"
      raisePeerDisconnected("Peer already connecting or connected",
                            AlreadyConnected)

    node.peerPool.connectingNodes.incl(peer.remote)

    await postHelloSteps(peer, response)
    ok = true
    trace "Peer fully connected", peer = peer.remote, clientId = response.clientId
  except PeerDisconnected as e:
    case e.reason
      of AlreadyConnected, TooManyPeers, MessageTimeout:
        trace "RLPx disconnect", reason = e.reason, peer = peer.remote
      else:
        debug "RLPx disconnect unexpected", reason = e.reason,
          msg = e.msg, peer = peer.remote

    rlpx_accept_failure.inc(labelValues = [$e.reason])
  except TransportIncompleteError:
    trace "Connection dropped in rlpxAccept", remote = peer.remote
    rlpx_accept_failure.inc(labelValues = [$TransportIncompleteError])
  except UselessPeerError:
    trace "Disconnecting useless peer", peer = peer.remote
    rlpx_accept_failure.inc(labelValues = [$UselessPeerError])
  except RlpTypeMismatch as e:
    # Some peers report capabilities with names longer than 3 chars. We ignore
    # those for now. Maybe we should allow this though.
    trace "Rlp error in rlpxAccept", err = e.msg, errName = e.name
    rlpx_accept_failure.inc(labelValues = [$RlpTypeMismatch])
  except TransportOsError as e:
    if e.code == OSErrorCode(110):
      trace "RLPx timeout", err = e.msg, errName = e.name
      rlpx_accept_failure.inc(labelValues = ["tcp_timeout"])
    else:
      trace "TransportOsError", err = e.msg, errName = e.name
      rlpx_accept_failure.inc(labelValues = [$e.name])
  except CatchableError as e:
    trace "RLPx error", err = e.msg, errName = e.name
    rlpx_accept_failure.inc(labelValues = [$e.name])

  if not ok:
    if not isNil(peer.transport):
      peer.transport.close()

    rlpx_accept_failure.inc()
    return nil
  else:
    rlpx_accept_success.inc()
    return peer

when isMainModule:

  when false:
    # The assignments below can be used to investigate if the RLPx procs
    # are considered GcSafe. The short answer is that they aren't, because
    # they dispatch into user code that might use the GC.
    type
      GcSafeDispatchMsg = proc (peer: Peer, msgId: uint64, msgData: var Rlp)

      GcSafeRecvMsg = proc (peer: Peer):
        Future[tuple[msgId: uint64, msgData: Rlp]] {.gcsafe.}

      GcSafeAccept = proc (transport: StreamTransport, myKeys: KeyPair):
        Future[Peer] {.gcsafe.}

    var
      dispatchMsgPtr = invokeThunk
      recvMsgPtr: GcSafeRecvMsg = recvMsg
      acceptPtr: GcSafeAccept = rlpxAccept
