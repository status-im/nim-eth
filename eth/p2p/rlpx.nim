import
  macros, tables, algorithm, deques, hashes, options, typetraits,
  std_shims/macros_shim, chronicles, nimcrypto, chronos, eth/[rlp, common, keys],
  private/p2p_types, kademlia, auth, rlpxcrypt, enode

when useSnappy:
  import snappy
  const devp2pSnappyVersion* = 5

logScope:
  topics = "rlpx"

const
  devp2pVersion* = 4
  defaultReqTimeout = milliseconds(10000)
  maxMsgSize = 1024 * 1024

include p2p_tracing

when tracingEnabled:
  import
    eth/common/eth_types_json_serialization

  export
    # XXX: This is a work-around for a Nim issue.
    # See a more detailed comment in p2p_tracing.nim
    init, writeValue, getOutput

var
  gProtocols: seq[ProtocolInfo]
  gDevp2pInfo: ProtocolInfo

# The variables above are immutable RTTI information. We need to tell
# Nim to not consider them GcSafe violations:
template allProtocols*: auto = {.gcsafe.}: gProtocols
template devp2pInfo: auto = {.gcsafe.}: gDevp2pInfo

chronicles.formatIt(Peer): $(it.remote)

proc disconnect*(peer: Peer, reason: DisconnectionReason, notifyOtherPeer = false) {.gcsafe, async.}

template raisePeerDisconnected(msg: string, r: DisconnectionReason) =
  var e = newException(PeerDisconnected, msg)
  e.reason = r
  raise e

proc disconnectAndRaise(peer: Peer,
                        reason: DisconnectionReason,
                        msg: string) {.async.} =
  let r = reason
  await peer.disconnect(r)
  raisePeerDisconnected(msg, r)

# Dispatcher
#

proc hash(d: Dispatcher): int =
  hash(d.protocolOffsets)

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
                   otherPeerCapabilities: openarray[Capability]): Dispatcher =
  # TODO: sub-optimal solution until progress is made here:
  # https://github.com/nim-lang/Nim/issues/7457
  # We should be able to find an existing dispatcher without allocating a new one

  new result
  newSeq(result.protocolOffsets, allProtocols.len)
  result.protocolOffsets.fill -1

  var nextUserMsgId = 0x10

  for localProtocol in node.protocols:
    let idx = localProtocol.index
    block findMatchingProtocol:
      for remoteCapability in otherPeerCapabilities:
        if localProtocol.name == remoteCapability.name and
           localProtocol.version == remoteCapability.version:
          result.protocolOffsets[idx] = nextUserMsgId
          nextUserMsgId += localProtocol.messages.len
          break findMatchingProtocol

  template copyTo(src, dest; index: int) =
    for i in 0 ..< src.len:
      dest[index + i] = addr src[i]

  result.messages = newSeq[ptr MessageInfo](nextUserMsgId)
  devp2pInfo.messages.copyTo(result.messages, 0)

  for localProtocol in node.protocols:
    let idx = localProtocol.index
    if result.protocolOffsets[idx] != -1:
      result.activeProtocols.add localProtocol
      localProtocol.messages.copyTo(result.messages,
                                    result.protocolOffsets[idx])

proc getMsgName*(peer: Peer, msgId: int): string =
  if not peer.dispatcher.isNil and
     msgId < peer.dispatcher.messages.len:
    return peer.dispatcher.messages[msgId].name
  else:
    return case msgId
           of 0: "hello"
           of 1: "disconnect"
           of 2: "ping"
           of 3: "pong"
           else: $msgId

proc getMsgMetadata*(peer: Peer, msgId: int): (ProtocolInfo, ptr MessageInfo) =
  doAssert msgId >= 0

  if msgId <= devp2pInfo.messages[^1].id:
    return (devp2pInfo, addr devp2pInfo.messages[msgId])

  if msgId < peer.dispatcher.messages.len:
    for i in 0 ..< allProtocols.len:
      let offset = peer.dispatcher.protocolOffsets[i]
      if offset != -1 and
         offset + allProtocols[i].messages[^1].id >= msgId:
        return (allProtocols[i], peer.dispatcher.messages[msgId])

# Protocol info objects
#

proc initProtocol(name: string, version: int,
                  peerInit: PeerStateInitializer,
                  networkInit: NetworkStateInitializer): ProtocolInfoObj =
  result.name = name
  result.version = version
  result.messages = @[]
  result.peerStateInitializer = peerInit
  result.networkStateInitializer = networkInit

proc setEventHandlers(p: ProtocolInfo,
                      handshake: HandshakeStep,
                      disconnectHandler: DisconnectionHandler) =
  p.handshake = handshake
  p.disconnectHandler = disconnectHandler

func asCapability*(p: ProtocolInfo): Capability =
  result.name = p.name
  result.version = p.version

func nameStr*(p: ProtocolInfo): string =
  result = newStringOfCap(3)
  for c in p.name: result.add(c)

# XXX: this used to be inline, but inline procs
# cannot be passed to closure params
proc cmp*(lhs, rhs: ProtocolInfo): int =
  for i in 0..2:
    if lhs.name[i] != rhs.name[i]:
      return int16(lhs.name[i]) - int16(rhs.name[i])
  return 0

proc messagePrinter[MsgType](msg: pointer): string {.gcsafe.} =
  result = ""
  # TODO: uncommenting the line below increases the compile-time
  # tremendously (for reasons not yet known)
  # result = $(cast[ptr MsgType](msg)[])

proc nextMsgResolver[MsgType](msgData: Rlp, future: FutureBase) {.gcsafe.} =
  var reader = msgData
  Future[MsgType](future).complete reader.readRecordType(MsgType, MsgType.rlpFieldsCount > 1)

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
      if f.read.isSome:
        doAssert false, "trying to resolve a request twice"
      else:
        doAssert false, "trying to resolve a timed out request with a value"
    else:
      try:
        if not f.read.isSome:
          doAssert false, "a request timed out twice"
      except:
        debug "Exception in requestResolver()",
          exc = getCurrentException().name,
          err = getCurrentExceptionMsg()

proc registerMsg(protocol: ProtocolInfo,
                 id: int, name: string,
                 thunk: MessageHandler,
                 printer: MessageContentPrinter,
                 requestResolver: RequestResolver,
                 nextMsgResolver: NextMsgResolver) =
  if protocol.messages.len <= id:
    protocol.messages.setLen(id + 1)
  protocol.messages[id] = MessageInfo(id: id,
                                      name: name,
                                      thunk: thunk,
                                      printer: printer,
                                      requestResolver: requestResolver,
                                      nextMsgResolver: nextMsgResolver)

proc registerProtocol(protocol: ProtocolInfo) =
  # TODO: This can be done at compile-time in the future
  if protocol.version > 0:
    let pos = lowerBound(gProtocols, protocol)
    gProtocols.insert(protocol, pos)
    for i in 0 ..< gProtocols.len:
      gProtocols[i].index = i
  else:
    gDevp2pInfo = protocol

# Message composition and encryption
#

template protocolOffset(peer: Peer, Protocol: type): int =
  peer.dispatcher.protocolOffsets[Protocol.protocolInfo.index]

proc perPeerMsgIdImpl(peer: Peer, proto: ProtocolInfo, msgId: int): int {.inline.} =
  result = msgId
  if not peer.dispatcher.isNil:
    result += peer.dispatcher.protocolOffsets[proto.index]

template getPeer(peer: Peer): auto = peer
template getPeer(response: Response): auto = Peer(response)
template getPeer(response: ResponseWithId): auto = response.peer

proc supports*(peer: Peer, Protocol: type): bool {.inline.} =
  ## Checks whether a Peer supports a particular protocol
  peer.protocolOffset(Protocol) != -1

template perPeerMsgId(peer: Peer, MsgType: type): int =
  perPeerMsgIdImpl(peer, MsgType.msgProtocol.protocolInfo, MsgType.msgId)

proc writeMsgId(p: ProtocolInfo, msgId: int, peer: Peer,
                rlpOut: var RlpWriter) =
  let baseMsgId = peer.dispatcher.protocolOffsets[p.index]
  doAssert baseMsgId != -1
  rlpOut.append(baseMsgId + msgId)

proc invokeThunk*(peer: Peer, msgId: int, msgData: var Rlp): Future[void] =
  template invalidIdError: untyped =
    raise newException(ValueError,
      "RLPx message with an invalid id " & $msgId &
      " on a connection supporting " & peer.dispatcher.describeProtocols)

  if msgId >= peer.dispatcher.messages.len: invalidIdError()
  let thunk = peer.dispatcher.messages[msgId].thunk
  if thunk == nil: invalidIdError()

  return thunk(peer, msgId, msgData)

proc linkSendFailureToReqFuture[S, R](sendFut: Future[S], resFut: Future[R]) =
  sendFut.addCallback() do (arg: pointer):
    if not sendFut.error.isNil:
      resFut.fail(sendFut.error)

template compressMsg(peer: Peer, data: Bytes): Bytes =
  when useSnappy:
    if peer.snappyEnabled:
      snappy.compress(data)
    else: data
  else:
    data

proc sendMsg*(peer: Peer, data: Bytes) {.gcsafe, async.} =
  try:
    var cipherText = encryptMsg(peer.compressMsg(data), peer.secretsState)
    discard await peer.transport.write(cipherText)
  except:
    await peer.disconnect(TcpError)
    # this is usually a "(32) Broken pipe":
    # FIXME: this exception should be caught somewhere in addMsgHandler() and
    # sending should be retried a few times
    raise

proc send*[Msg](peer: Peer, msg: Msg): Future[void] =
  logSentMsg(peer, msg)

  var rlpWriter = initRlpWriter()
  rlpWriter.append perPeerMsgId(peer, Msg)
  rlpWriter.appendRecordType(msg, Msg.rlpFieldsCount > 1)
  peer.sendMsg rlpWriter.finish

proc registerRequest*(peer: Peer,
                      timeout: Duration,
                      responseFuture: FutureBase,
                      responseMsgId: int): int =
  inc peer.lastReqId
  result = peer.lastReqId

  let timeoutAt = Moment.fromNow(timeout)
  let req = OutstandingRequest(id: result,
                               future: responseFuture,
                               timeoutAt: timeoutAt)
  peer.outstandingRequests[responseMsgId].addLast req

  doAssert(not peer.dispatcher.isNil)
  let requestResolver = peer.dispatcher.messages[responseMsgId].requestResolver
  proc timeoutExpired(udata: pointer) = requestResolver(nil, responseFuture)

  addTimer(timeoutAt, timeoutExpired, nil)

proc resolveResponseFuture(peer: Peer, msgId: int, msg: pointer, reqId: int) =
  logScope:
    msg = peer.dispatcher.messages[msgId].name
    msgContents = peer.dispatcher.messages[msgId].printer(msg)
    receivedReqId = reqId
    remotePeer = peer.remote

  template resolve(future) =
    (peer.dispatcher.messages[msgId].requestResolver)(msg, future)

  template outstandingReqs: auto =
    peer.outstandingRequests[msgId]

  if reqId == -1:
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
      trace "late or duplicate reply for a RLPx request"
  else:
    # TODO: This is not completely sound because we are still using a global
    # `reqId` sequence (the problem is that we might get a response ID that
    # matches a request ID for a different type of request). To make the code
    # correct, we can use a separate sequence per response type, but we have
    # to first verify that the other Ethereum clients are supporting this
    # correctly (because then, we'll be reusing the same reqIds for different
    # types of requests). Alternatively, we can assign a separate interval in
    # the `reqId` space for each type of response.
    if reqId > peer.lastReqId:
      warn "RLPx response without a matching request"
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

    debug "late or duplicate reply for a RLPx request"

proc recvMsg*(peer: Peer): Future[tuple[msgId: int, msgData: Rlp]] {.async.} =
  ##  This procs awaits the next complete RLPx message in the TCP stream

  var headerBytes: array[32, byte]
  await peer.transport.readExactly(addr headerBytes[0], 32)

  var msgSize: int
  if decryptHeaderAndGetMsgSize(peer.secretsState,
                                headerBytes, msgSize) != RlpxStatus.Success:
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
  #  also be useuful for chunked messages where part of the buffer may have
  #  been processed and needs filling in
  var encryptedBytes = newSeq[byte](remainingBytes)
  await peer.transport.readExactly(addr encryptedBytes[0], len(encryptedBytes))

  let decryptedMaxLength = decryptedLength(msgSize)
  var
    decryptedBytes = newSeq[byte](decryptedMaxLength)
    decryptedBytesCount = 0

  if decryptBody(peer.secretsState, encryptedBytes, msgSize,
                 decryptedBytes, decryptedBytesCount) != RlpxStatus.Success:
    await peer.disconnectAndRaise(BreachOfProtocol,
                                  "Cannot decrypt RLPx frame body")

  decryptedBytes.setLen(decryptedBytesCount)

  when useSnappy:
    if peer.snappyEnabled:
      decryptedBytes = snappy.uncompress(decryptedBytes)
      if decryptedBytes.len == 0:
        await peer.disconnectAndRaise(BreachOfProtocol,
                                      "Snappy uncompress encountered malformed data")
  var rlp = rlpFromBytes(decryptedBytes.toRange)

  try:
    let msgid = rlp.read(int)
    return (msgId, rlp)
  except RlpError:
    await peer.disconnectAndRaise(BreachOfProtocol,
                                  "Cannot read RLPx message id")

proc checkedRlpRead(peer: Peer, r: var Rlp, MsgType: type): auto {.inline.} =
  let tmp = r
  when defined(release):
    return r.read(MsgType)
  else:
    try:
      return r.read(MsgType)
    except:
      # echo "Failed rlp.read:", tmp.inspect
      debug "Failed rlp.read",
            peer = peer,
            msg = MsgType.name,
            exception = getCurrentExceptionMsg()
            # dataHex = r.rawData.toSeq().toHex()

      raise

proc waitSingleMsg(peer: Peer, MsgType: type): Future[MsgType] {.async.} =
  let wantedId = peer.perPeerMsgId(MsgType)
  while true:
    var (nextMsgId, nextMsgData) = await peer.recvMsg()

    if nextMsgId == wantedId:
      try:
        result = checkedRlpRead(peer, nextMsgData, MsgType)
        logReceivedMsg(peer, result)
        return
      except RlpError:
        await peer.disconnectAndRaise(BreachOfProtocol,
                                      "Invalid RLPx message body")

    elif nextMsgId == 1: # p2p.disconnect
      let reason = DisconnectionReason nextMsgData.listElem(0).toInt(uint32)
      await peer.disconnect(reason)
      raisePeerDisconnected("Unexpected disconnect", reason)
    else:
      warn "Dropped RLPX message",
           msg = peer.dispatcher.messages[nextMsgId].name

include p2p_backends_helpers

proc nextMsg*(peer: Peer, MsgType: type): Future[MsgType] =
  ## This procs awaits a specific RLPx message.
  ## Any messages received while waiting will be dispatched to their
  ## respective handlers. The designated message handler will also run
  ## to completion before the future returned by `nextMsg` is resolved.
  let wantedId = peer.perPeerMsgId(MsgType)
  let f = peer.awaitedMessages[wantedId]
  if not f.isNil:
    return Future[MsgType](f)

  newFuture result
  peer.awaitedMessages[wantedId] = result

proc dispatchMessages*(peer: Peer) {.async.} =
  while true:
    var msgId: int
    var msgData: Rlp
    try:
      (msgId, msgData) = await peer.recvMsg()
    except TransportIncompleteError:
      trace "Connection dropped in dispatchMessages"
      # This can happen during the rlpx connection setup or at any point after.
      # Because this code does not know, a disconnect needs to be done.
      asyncDiscard peer.disconnect(ClientQuitting)
      return

    if msgId == 1: # p2p.disconnect
      await peer.transport.closeWait()
      let reason = msgData.listElem(0).toInt(uint32).DisconnectionReason
      await peer.disconnect(reason)
      break

    try:
      await peer.invokeThunk(msgId, msgData)
    except RlpError:
      debug "ending dispatchMessages loop", peer, err = getCurrentExceptionMsg()
      await peer.disconnect(BreachOfProtocol)
      return
    except CatchableError:
      warn "Error while handling RLPx message", peer,
        msg = peer.getMsgName(msgId),
        err = getCurrentExceptionMsg()

    # TODO: Hmm, this can be safely moved into the message handler thunk.
    # The documentation will need to be updated, explaning the fact that
    # nextMsg will be resolved only if the message handler has executed
    # successfully.
    if peer.awaitedMessages[msgId] != nil:
      let msgInfo = peer.dispatcher.messages[msgId]
      try:
        (msgInfo.nextMsgResolver)(msgData, peer.awaitedMessages[msgId])
      except:
        # TODO: Handling errors here must be investigated more carefully.
        # They also are supposed to be handled at the call-site where
        # `nextMsg` is used.
        debug "nextMsg resolver failed", err = getCurrentExceptionMsg()
        raise
      peer.awaitedMessages[msgId] = nil

macro p2pProtocolImpl(name: static[string],
                      version: static[uint],
                      body: untyped,
                      # TODO Nim can't handle a proper duration paramter here
                      timeout: static[int64] = defaultReqTimeout.milliseconds,
                      useRequestIds: static[bool] = true,
                      shortName: static[string] = "",
                      outgoingRequestDecorator: untyped = nil,
                      incomingRequestDecorator: untyped = nil,
                      incomingRequestThunkDecorator: untyped = nil,
                      incomingResponseDecorator: untyped = nil,
                      incomingResponseThunkDecorator: untyped = nil,
                      peerState = type(nil),
                      networkState = type(nil)): untyped =
  ## The macro used to defined RLPx sub-protocols. See README.
  var
    # XXX: deal with a Nim bug causing the macro params to be
    # zero when they are captured by a closure:
    outgoingRequestDecorator = outgoingRequestDecorator
    incomingRequestDecorator = incomingRequestDecorator
    incomingRequestThunkDecorator = incomingRequestThunkDecorator
    incomingResponseDecorator = incomingResponseDecorator
    incomingResponseThunkDecorator = incomingResponseThunkDecorator
    useRequestIds = useRequestIds
    version = version
    defaultTimeout = timeout

    nextId = 0
    protoName = name
    shortName = if shortName.len > 0: shortName else: protoName
    outTypes = newNimNode(nnkStmtList)
    outSendProcs = newNimNode(nnkStmtList)
    outRecvProcs = newNimNode(nnkStmtList)
    outProcRegistrations = newNimNode(nnkStmtList)
    protoNameIdent = ident(protoName)
    resultIdent = ident "result"
    perProtocolMsgId = ident"perProtocolMsgId"
    response = ident"response"
    currentProtocolSym = ident"CurrentProtocol"
    protocol = ident(protoName & "Protocol")
    isSubprotocol = version > 0'u
    peerState = verifyStateType peerState.getType
    networkState = verifyStateType networkState.getType
    handshake = newNilLit()
    disconnectHandler = newNilLit()
    Option = bindSym "Option"
    # XXX: Binding the int type causes instantiation failure for some reason
    # Int = bindSym "int"
    Int = ident "int"
    Peer = bindSym "Peer"
    Duration = bindSym "Duration"
    milliseconds = bindSym "milliseconds"
    createNetworkState = bindSym "createNetworkState"
    createPeerState = bindSym "createPeerState"
    finish = bindSym "finish"
    initRlpWriter = bindSym "initRlpWriter"
    enterList = bindSym "enterList"
    messagePrinter = bindSym "messagePrinter"
    initProtocol = bindSym "initProtocol"
    nextMsgResolver = bindSym "nextMsgResolver"
    append = bindSym("append", brForceOpen)
    read = bindSym("read", brForceOpen)
    registerRequest = bindSym "registerRequest"
    requestResolver = bindSym "requestResolver"
    resolveResponseFuture = bindSym "resolveResponseFuture"
    rlpFromBytes = bindSym "rlpFromBytes"
    checkedRlpRead = bindSym "checkedRlpRead"
    sendMsg = bindSym "sendMsg"
    startList = bindSym "startList"
    writeMsgId = bindSym "writeMsgId"
    getState = bindSym "getState"
    getNetworkState = bindSym "getNetworkState"
    perPeerMsgId = bindSym "perPeerMsgId"
    perPeerMsgIdImpl = bindSym "perPeerMsgIdImpl"
    linkSendFailureToReqFuture = bindSym "linkSendFailureToReqFuture"

  # By convention, all Ethereum protocol names must be abbreviated to 3 letters
  doAssert shortName.len == 3

  template applyDecorator(p: NimNode, decorator: NimNode) =
    if decorator.kind != nnkNilLit: p.addPragma decorator

  proc augmentUserHandler(userHandlerProc: NimNode,
                          msgId = -1,
                          msgKind = rlpxNotification,
                          extraDefinitions: NimNode = nil) =
    ## Turns a regular proc definition into an async proc and adds
    ## the helpers for accessing the peer and network protocol states.
    case msgKind
    of rlpxRequest:  userHandlerProc.applyDecorator incomingRequestDecorator
    of rlpxResponse: userHandlerProc.applyDecorator incomingResponseDecorator
    else: discard

    userHandlerProc.addPragma ident"gcsafe"
    userHandlerProc.addPragma ident"async"

    # We allow the user handler to use `openarray` params, but we turn
    # those into sequences to make the `async` pragma happy.
    for i in 1 ..< userHandlerProc.params.len:
      var param = userHandlerProc.params[i]
      param[^2] = chooseFieldType(param[^2])

    var userHandlerDefinitions = newStmtList()

    userHandlerDefinitions.add quote do:
      type `currentProtocolSym` = `protoNameIdent`

    if extraDefinitions != nil:
      userHandlerDefinitions.add extraDefinitions

    if msgId >= 0:
      userHandlerDefinitions.add quote do:
        const `perProtocolMsgId` = `msgId`

    # Define local accessors for the peer and the network protocol states
    # inside each user message handler proc (e.g. peer.state.foo = bar)
    if peerState != nil:
      userHandlerDefinitions.add quote do:
        template state(p: `Peer`): `peerState` =
          cast[`peerState`](`getState`(p, `protocol`))

    if networkState != nil:
      userHandlerDefinitions.add quote do:
        template networkState(p: `Peer`): `networkState` =
          cast[`networkState`](`getNetworkState`(p.network, `protocol`))

    userHandlerProc.body.insert 0, userHandlerDefinitions

  proc liftEventHandler(doBlock: NimNode, handlerName: string): NimNode =
    ## Turns a "named" do block to a regular async proc
    ## (e.g. onPeerConnected do ...)
    var fn = newTree(nnkProcDef)
    doBlock.copyChildrenTo(fn)
    result = genSym(nskProc, protoName & handlerName)
    fn.name = result
    augmentUserHandler fn
    outRecvProcs.add fn

  proc addMsgHandler(msgId: int, n: NimNode,
                     msgKind = rlpxNotification,
                     responseMsgId = -1,
                     responseRecord: NimNode = nil): NimNode =
    if n[0].kind == nnkPostfix:
      macros.error("p2pProcotol procs are public by default. " &
                   "Please remove the postfix `*`.", n)

    let
      msgIdent = n.name
      msgName = $n.name
      hasReqIds = useRequestIds and msgKind in {rlpxRequest, rlpxResponse}

    var
      userPragmas = n.pragma

      # variables used in the sending procs
      msgRecipient = ident"msgRecipient"
      sendTo = ident"sendTo"
      reqTimeout: NimNode
      rlpWriter = ident"writer"
      appendParams = newNimNode(nnkStmtList)
      paramsToWrite = newSeq[NimNode](0)
      reqId = ident"reqId"
      perPeerMsgIdVar  = ident"perPeerMsgId"

      # variables used in the receiving procs
      msgSender = ident"msgSender"
      receivedRlp = ident"rlp"
      receivedMsg = ident"msg"
      readParams = newNimNode(nnkStmtList)
      readParamsPrelude = newNimNode(nnkStmtList)
      callResolvedResponseFuture = newNimNode(nnkStmtList)

      # nodes to store the user-supplied message handling proc if present
      userHandlerProc: NimNode = nil
      userHandlerCall: NimNode = nil
      awaitUserHandler = newStmtList()

      # a record type associated with the message
      msgRecord = newIdentNode(msgName & "Obj")
      msgRecordFields = newTree(nnkRecList)
      msgRecordBody = newTree(nnkObjectTy,
                              newEmptyNode(),
                              newEmptyNode(),
                              msgRecordFields)

    result = msgRecord
    if hasReqIds:
      # Messages using request Ids
      readParams.add quote do:
        let `reqId` = `read`(`receivedRlp`, int)

    case msgKind
    of rlpxNotification: discard
    of rlpxRequest:
      # If the request proc has a default timeout specified, remove it from
      # the signature for now so we can generate the `thunk` proc without it.
      # The parameter will be added back later only for to the sender proc.
      # When the timeout is not specified, we use a default one.
      reqTimeout = popTimeoutParam(n)
      if reqTimeout == nil:
        reqTimeout = newTree(nnkIdentDefs,
                             ident"timeout",
                             Duration, newCall(milliseconds, newLit(defaultTimeout)))

      let reqToResponseOffset = responseMsgId - msgId
      let responseMsgId = quote do: `perPeerMsgIdVar` + `reqToResponseOffset`

      # Each request is registered so we can resolve it when the response
      # arrives. There are two types of protocols: LES-like protocols use
      # explicit `reqId` sent over the wire, while the ETH wire protocol
      # assumes there is one outstanding request at a time (if there are
      # multiple requests we'll resolve them in FIFO order).
      let registerRequestCall = newCall(registerRequest, msgRecipient,
                                                         reqTimeout[0],
                                                         resultIdent,
                                                         responseMsgId)
      if hasReqIds:
        appendParams.add quote do:
          newFuture `resultIdent`
          let `reqId` = `registerRequestCall`
        paramsToWrite.add reqId
      else:
        appendParams.add quote do:
          newFuture `resultIdent`
          discard `registerRequestCall`

    of rlpxResponse:
      let reqIdVal = if hasReqIds: `reqId` else: newLit(-1)
      callResolvedResponseFuture.add quote do:
        `resolveResponseFuture`(`msgSender`,
                                `perPeerMsgId`(`msgSender`, `msgRecord`),
                                 addr(`receivedMsg`),
                                 `reqIdVal`)
      if hasReqIds:
        paramsToWrite.add newDotExpr(sendTo, ident"id")

    if n.body.kind != nnkEmpty:
      # implement the receiving thunk proc that deserialzed the
      # message parameters and calls the user proc:
      userHandlerProc = n.copyNimTree
      userHandlerProc.name = genSym(nskProc, msgName)

      var extraDefs: NimNode
      if msgKind == rlpxRequest:
        let peer = userHandlerProc.params[1][0]
        if hasReqIds:
          extraDefs = quote do:
            let `response` = ResponseWithId[`responseRecord`](peer: `peer`, id: `reqId`)
        else:
          extraDefs = quote do:
            let `response` = Response[`responseRecord`](`peer`)

      augmentUserHandler userHandlerProc, msgId, msgKind, extraDefs

      # This is the call to the user supplied handled. Here we add only the
      # initial peer param, while the rest of the params will be added later.
      userHandlerCall = newCall(userHandlerProc.name, msgSender)

      if hasReqIds:
        userHandlerProc.params.insert(2, newIdentDefs(reqId, ident"int"))
        userHandlerCall.add reqId

      # When there is a user handler, it must be awaited in the thunk proc.
      # Above, by default `awaitUserHandler` is set to a no-op statement list.
      awaitUserHandler = newCall("await", userHandlerCall)

      outRecvProcs.add(userHandlerProc)

    for param, paramType in n.typedParams(skip = 1):
      # This is a fragment of the sending proc that
      # serializes each of the passed parameters:
      paramsToWrite.add param

      # Each message has a corresponding record type.
      # Here, we create its fields one by one:
      msgRecordFields.add newTree(nnkIdentDefs,
        newTree(nnkPostfix, ident("*"), param), # The fields are public
        chooseFieldType(paramType),             # some types such as openarray
                                                # are automatically remapped
        newEmptyNode())

      # The received RLP data is deserialized to a local variable of
      # the message-specific type. This is done field by field here:
      let msgNameLit = newLit(msgName)
      readParams.add quote do:
        `receivedMsg`.`param` = `checkedRlpRead`(`msgSender`, `receivedRlp`, `paramType`)

      # If there is user message handler, we'll place a call to it by
      # unpacking the fields of the received message:
      if userHandlerCall != nil:
        userHandlerCall.add newDotExpr(receivedMsg, param)

    let paramCount = paramsToWrite.len

    if paramCount > 1:
      readParamsPrelude.add newCall(enterList, receivedRlp)

    when tracingEnabled:
      readParams.add newCall(bindSym"logReceivedMsg", msgSender, receivedMsg)

    let thunkName = ident(msgName & "_thunk")
    var thunkProc = quote do:
      proc `thunkName`(`msgSender`: `Peer`, _: int, data: Rlp) {.gcsafe.} =
        var `receivedRlp` = data
        var `receivedMsg` {.noinit.}: `msgRecord`
        `readParamsPrelude`
        `readParams`
        `awaitUserHandler`
        `callResolvedResponseFuture`

    for p in userPragmas: thunkProc.addPragma p

    case msgKind
    of rlpxRequest:  thunkProc.applyDecorator incomingRequestThunkDecorator
    of rlpxResponse: thunkProc.applyDecorator incomingResponseThunkDecorator
    else: discard

    thunkProc.addPragma ident"async"

    outRecvProcs.add thunkProc

    outTypes.add quote do:
      # This is a type featuring a single field for each message param:
      type `msgRecord`* = `msgRecordBody`

      # Add a helper template for accessing the message type:
      # e.g. p2p.hello:
      template `msgIdent`*(T: type `protoNameIdent`): type = `msgRecord`

      # Add a helper template for obtaining the message Id for
      # a particular message type:
      template msgId*(T: type `msgRecord`): int = `msgId`
      template msgProtocol*(T: type `msgRecord`): type = `protoNameIdent`

    var msgSendProc = n
    let msgSendProcName = n.name
    outSendProcs.add msgSendProc

    # TODO: check that the first param has the correct type
    msgSendProc.params[1][0] = sendTo
    msgSendProc.addPragma ident"gcsafe"

    # Add a timeout parameter for all request procs
    case msgKind
    of rlpxRequest:
      msgSendProc.params.add reqTimeout
    of rlpxResponse:
      # A response proc must be called with a response object that originates
      # from a certain request. Here we change the Peer parameter at position
      # 1 to the correct strongly-typed ResponseType. The incoming procs still
      # gets the normal Peer paramter.
      let
        ResponseTypeHead = if useRequestIds: bindSym"ResponseWithId"
                           else: bindSym"Response"
        ResponseType = newTree(nnkBracketExpr, ResponseTypeHead, msgRecord)

      msgSendProc.params[1][1] = ResponseType

      outSendProcs.add quote do:
        template send*(r: `ResponseType`, args: varargs[untyped]): auto =
          `msgSendProcName`(r, args)
    else: discard

    # We change the return type of the sending proc to a Future.
    # If this is a request proc, the future will return the response record.
    let rt = if msgKind != rlpxRequest: ident"void"
             else: newTree(nnkBracketExpr, Option, responseRecord)
    msgSendProc.params[0] = newTree(nnkBracketExpr, ident("Future"), rt)

    let msgBytes = ident"msgBytes"

    let finalizeRequest = quote do:
      let `msgBytes` = `finish`(`rlpWriter`)

    var sendCall = newCall(sendMsg, msgRecipient, msgBytes)
    let senderEpilogue = if msgKind == rlpxRequest:
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
      newCall(perPeerMsgIdImpl, msgRecipient, protocol, newLit(msgId))
    else:
      newLit(msgId)

    if paramCount > 1:
      # In case there are more than 1 parameter,
      # the params must be wrapped in a list:
      appendParams = newStmtList(
        newCall(startList, rlpWriter, newLit(paramCount)),
        appendParams)

    for p in paramsToWrite:
      appendParams.add newCall(append, rlpWriter, p)

    # Make the send proc public
    msgSendProc.name = newTree(nnkPostfix, ident("*"), msgSendProc.name)

    let initWriter = quote do:
      var `rlpWriter` = `initRlpWriter`()
      const `perProtocolMsgId` = `msgId`
      let `perPeerMsgIdVar` = `perPeerMsgIdValue`
      `append`(`rlpWriter`, `perPeerMsgIdVar`)

    when tracingEnabled:
      appendParams.add logSentMsgFields(msgRecipient, protocol, msgId, paramsToWrite)

    # let paramCountNode = newLit(paramCount)
    msgSendProc.body = quote do:
      let `msgRecipient` = getPeer(`sendTo`)
      `initWriter`
      `appendParams`
      `finalizeRequest`
      `senderEpilogue`

    if msgKind == rlpxRequest:
      msgSendProc.applyDecorator outgoingRequestDecorator

    outProcRegistrations.add(
      newCall(bindSym("registerMsg"),
              protocol,
              newIntLitNode(msgId),
              newStrLitNode($n.name),
              thunkName,
              newTree(nnkBracketExpr, messagePrinter, msgRecord),
              newTree(nnkBracketExpr, requestResolver, msgRecord),
              newTree(nnkBracketExpr, nextMsgResolver, msgRecord)))

  outTypes.add quote do:
    # Create a type acting as a pseudo-object representing the protocol
    # (e.g. p2p)
    type `protoNameIdent`* = object

  if peerState != nil:
    outTypes.add quote do:
      template State*(P: type `protoNameIdent`): type = `peerState`

  if networkState != nil:
    outTypes.add quote do:
      template NetworkState*(P: type `protoNameIdent`): type = `networkState`

  for n in body:
    case n.kind
    of {nnkCall, nnkCommand}:
      if eqIdent(n[0], "nextID"):
        # By default message IDs are assigned in increasing order
        # `nextID` can be used to skip some of the numeric slots
        if n.len == 2 and n[1].kind == nnkIntLit:
          nextId = n[1].intVal.int
        else:
          macros.error("nextID expects a single int value", n)
      elif eqIdent(n[0], "requestResponse"):
        # `requestResponse` can be given a block of 2 or more procs.
        # The last one is considered to be a response message, while
        # all preceeding ones are requests triggering the response.
        # The system makes sure to automatically insert a hidden `reqId`
        # parameter used to discriminate the individual messages.
        block processReqResp:
          if n.len == 2 and n[1].kind == nnkStmtList:
            var procs = newSeq[NimNode](0)
            for def in n[1]:
              if def.kind == nnkProcDef:
                procs.add(def)
            if procs.len > 1:
              let responseMsgId = nextId + procs.len - 1
              let responseRecord = addMsgHandler(responseMsgId,
                                                 procs[^1],
                                                 msgKind = rlpxResponse)
              for i in 0 .. procs.len - 2:
                discard addMsgHandler(nextId + i, procs[i],
                                      msgKind = rlpxRequest,
                                      responseMsgId = responseMsgId,
                                      responseRecord = responseRecord)

              inc nextId, procs.len

              # we got all the way to here, so everything is fine.
              # break the block so it doesn't reach the error call below
              break processReqResp
          macros.error("requestResponse expects a block with at least two proc definitions")
      elif eqIdent(n[0], "onPeerConnected"):
        handshake = liftEventHandler(n[1], "Handshake")
      elif eqIdent(n[0], "onPeerDisconnected"):
        disconnectHandler = liftEventHandler(n[1], "PeerDisconnect")
      else:
        macros.error(repr(n) & " is not a recognized call in P2P protocol definitions", n)
    of nnkProcDef:
      discard addMsgHandler(nextId, n)
      inc nextId

    of nnkCommentStmt:
      discard

    else:
      macros.error("illegal syntax in a P2P protocol definition", n)

  let peerInit = if peerState == nil: newNilLit()
                 else: newTree(nnkBracketExpr, createPeerState, peerState)

  let netInit  = if networkState == nil: newNilLit()
                 else: newTree(nnkBracketExpr, createNetworkState, networkState)

  result = newNimNode(nnkStmtList)
  result.add outTypes
  result.add quote do:
    # One global variable per protocol holds the protocol run-time data
    var p = `initProtocol`(`shortName`, `version`, `peerInit`, `netInit`)
    var `protocol` = addr p

    # The protocol run-time data is available as a pseudo-field
    # (e.g. `p2p.protocolInfo`)
    template protocolInfo*(P: type `protoNameIdent`): ProtocolInfo = `protocol`

  result.add outSendProcs, outRecvProcs, outProcRegistrations
  result.add quote do:
    setEventHandlers(`protocol`, `handshake`, `disconnectHandler`)

  result.add newCall(bindSym("registerProtocol"), protocol)

  when defined(debugRlpxProtocol) or defined(debugMacros):
    echo repr(result)

macro p2pProtocol*(protocolOptions: untyped, body: untyped): untyped =
  let protoName = $(protocolOptions[0])
  result = protocolOptions
  result[0] = bindSym"p2pProtocolImpl"
  result.add(newTree(nnkExprEqExpr,
                     ident("name"),
                     newLit(protoName)))
  result.add(newTree(nnkExprEqExpr,
                     ident("body"),
                     body))

p2pProtocol devp2p(version = 0, shortName = "p2p"):
  proc hello(peer: Peer,
             version: uint,
             clientId: string,
             capabilities: seq[Capability],
             listenPort: uint,
             nodeId: array[RawPublicKeySize, byte])

  proc sendDisconnectMsg(peer: Peer, reason: DisconnectionReason)

  proc ping(peer: Peer) =
    discard peer.pong()

  proc pong(peer: Peer) =
    discard

proc removePeer(network: EthereumNode, peer: Peer) =
  # It is necessary to check if peer.remote still exists. The connection might
  # have been dropped already from the peers side.
  # E.g. when receiving a p2p.disconnect message from a peer, a race will happen
  # between which side disconnects first.
  if network.peerPool != nil and not peer.remote.isNil:
    network.peerPool.connectedNodes.del(peer.remote)

    for observer in network.peerPool.observers.values:
      if not observer.onPeerDisconnected.isNil:
        observer.onPeerDisconnected(peer)

proc callDisconnectHandlers(peer: Peer, reason: DisconnectionReason): Future[void] =
  var futures = newSeqOfCap[Future[void]](allProtocols.len)

  for protocol in peer.dispatcher.activeProtocols:
    if protocol.disconnectHandler != nil:
      futures.add((protocol.disconnectHandler)(peer, reason))

  return all(futures)

proc handshakeImpl[T](peer: Peer,
                      sendFut: Future[void],
                      responseFut: Future[T],
                      timeout: Duration): Future[T] {.async.} =
  sendFut.addCallback do (arg: pointer) {.gcsafe.}:
    if sendFut.failed:
      debug "Handshake message not delivered", peer

  doAssert timeout.milliseconds > 0
  yield responseFut or sleepAsync(timeout)
  if not responseFut.finished:
    discard disconnectAndRaise(peer, BreachOfProtocol,
                               "Protocol handshake was not received in time.")
  elif responseFut.failed:
    raise responseFut.error
  else:
    return responseFut.read

proc handshakeImpl(peer: Peer,
                   sendFut: Future[void],
                   timeout: Duration,
                   HandshakeType: type): Future[HandshakeType] =
  handshakeImpl(peer, sendFut, nextMsg(peer, HandshakeType), timeout)

macro handshake*(peer: Peer, timeout: untyped, sendCall: untyped): untyped =
  let
    msgName = $sendCall[0]
    msgType = newDotExpr(ident"CurrentProtocol", ident(msgName))

  sendCall.insert(1, peer)

  result = newCall(bindSym"handshakeImpl", peer, sendCall, timeout, msgType)

proc disconnect*(peer: Peer, reason: DisconnectionReason, notifyOtherPeer = false) {.async.} =
  if peer.connectionState notin {Disconnecting, Disconnected}:
    peer.connectionState = Disconnecting
    if notifyOtherPeer and not peer.transport.closed:
      var fut = peer.sendDisconnectMsg(reason)
      yield fut
      if fut.failed:
        debug "Failed to delived disconnect message", peer
    try:
      if not peer.dispatcher.isNil:
        await callDisconnectHandlers(peer, reason)
    finally:
      logDisconnectedPeer peer
      peer.connectionState = Disconnected
      removePeer(peer.network, peer)

proc validatePubKeyInHello(msg: devp2p.hello, pubKey: PublicKey): bool =
  var pk: PublicKey
  recoverPublicKey(msg.nodeId, pk) == EthKeysStatus.Success and pk == pubKey

proc checkUselessPeer(peer: Peer) {.inline.} =
  if peer.dispatcher.numProtocols == 0:
    # XXX: Send disconnect + UselessPeer
    raise newException(UselessPeerError, "Useless peer")

proc initPeerState*(peer: Peer, capabilities: openarray[Capability]) =
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

  peer.lastReqId = 0

  # Initialize all the active protocol states
  newSeq(peer.protocolStates, allProtocols.len)
  for protocol in peer.dispatcher.activeProtocols:
    let peerStateInit = protocol.peerStateInitializer
    if peerStateInit != nil:
      peer.protocolStates[protocol.index] = peerStateInit(peer)

proc postHelloSteps(peer: Peer, h: devp2p.hello) {.async.} =
  initPeerState(peer, h.capabilities)

  # Please note that the ordering of operations here is important!
  #
  # We must first start all handshake procedures and give them a
  # chance to send any initial packages they might require over
  # the network and to yield on their `nextMsg` waits.
  #
  var subProtocolsHandshakes = newSeqOfCap[Future[void]](allProtocols.len)
  for protocol in peer.dispatcher.activeProtocols:
    if protocol.handshake != nil:
      subProtocolsHandshakes.add((protocol.handshake)(peer))

  # The `dispatchMesssages` loop must be started after this.
  # Otherwise, we risk that some of the handshake packets sent by
  # the other peer may arrrive too early and be processed before
  # the handshake code got a change to wait for them.
  #
  var messageProcessingLoop = peer.dispatchMessages()

  messageProcessingLoop.callback = proc(p: pointer) {.gcsafe.} =
    if messageProcessingLoop.failed:
      debug "Ending dispatchMessages loop", peer,
            err = messageProcessingLoop.error.msg
      asyncDiscard peer.disconnect(ClientQuitting)

  # The handshake may involve multiple async steps, so we wait
  # here for all of them to finish.
  #
  await all(subProtocolsHandshakes)

  peer.connectionState = Connected

template `^`(arr): auto =
  # passes a stack array with a matching `arrLen`
  # variable as an open array
  arr.toOpenArray(0, `arr Len` - 1)

proc check(status: AuthStatus) =
  if status != AuthStatus.Success:
    raise newException(CatchableError, "Error: " & $status)

proc initSecretState(hs: var Handshake, authMsg, ackMsg: openarray[byte],
                     p: Peer) =
  var secrets: ConnectionSecret
  check hs.getSecrets(authMsg, ackMsg, secrets)
  initSecretState(secrets, p.secretsState)
  burnMem(secrets)

template checkSnappySupport(node: EthereumNode, handshake: Handshake, peer: Peer) =
  when useSnappy:
    peer.snappyEnabled = node.protocolVersion >= devp2pSnappyVersion.uint and
                         handshake.version >= devp2pSnappyVersion.uint

template getVersion(handshake: Handshake): uint =
  when useSnappy:
    handshake.version
  else:
    devp2pVersion

template baseProtocolVersion(node: EthereumNode): untyped =
  when useSnappy:
    node.protocolVersion
  else:
    devp2pVersion

template baseProtocolVersion(peer: Peer): uint =
  when useSnappy:
    if peer.snappyEnabled: devp2pSnappyVersion
    else: devp2pVersion
  else:
    devp2pVersion

proc rlpxConnect*(node: EthereumNode, remote: Node): Future[Peer] {.async.} =
  initTracing(devp2pInfo, node.protocols)

  new result
  result.network = node
  result.remote = remote

  let ta = initTAddress(remote.node.address.ip, remote.node.address.tcpPort)
  var ok = false
  try:
    result.transport = await connect(ta)
    var handshake = newHandshake({Initiator, EIP8}, int(node.baseProtocolVersion))
    handshake.host = node.keys

    var authMsg: array[AuthMessageMaxEIP8, byte]
    var authMsgLen = 0
    check authMessage(handshake, remote.node.pubkey, authMsg, authMsgLen)
    var res = result.transport.write(addr authMsg[0], authMsgLen)

    let initialSize = handshake.expectedLength
    var ackMsg = newSeqOfCap[byte](1024)
    ackMsg.setLen(initialSize)

    await result.transport.readExactly(addr ackMsg[0], len(ackMsg))

    var ret = handshake.decodeAckMessage(ackMsg)
    if ret == AuthStatus.IncompleteError:
      ackMsg.setLen(handshake.expectedLength)
      await result.transport.readExactly(addr ackMsg[initialSize],
                                         len(ackMsg) - initialSize)
      ret = handshake.decodeAckMessage(ackMsg)
    check ret

    node.checkSnappySupport(handshake, result)
    initSecretState(handshake, ^authMsg, ackMsg, result)

    # if handshake.remoteHPubkey != remote.node.pubKey:
    #   raise newException(Exception, "Remote pubkey is wrong")
    logConnectedPeer result

    var sendHelloFut = result.hello(
      handshake.getVersion(),
      node.clientId,
      node.capabilities,
      uint(node.address.tcpPort),
      node.keys.pubkey.getRaw())

    var response = await result.handshakeImpl(
      sendHelloFut,
      result.waitSingleMsg(devp2p.hello),
      10.seconds)

    if not validatePubKeyInHello(response, remote.node.pubKey):
      warn "Remote nodeId is not its public key" # XXX: Do we care?

    await postHelloSteps(result, response)
    ok = true
  except PeerDisconnected as e:
    if e.reason != TooManyPeers:
      debug "Unexpected disconnect during rlpxConnect", reason = e.reason
  except TransportIncompleteError:
    trace "Connection dropped in rlpxConnect", remote
  except UselessPeerError:
    trace "Disconnecting useless peer", peer = remote
  except RlpTypeMismatch:
    # Some peers report capabilities with names longer than 3 chars. We ignore
    # those for now. Maybe we should allow this though.
    debug "Rlp error in rlpxConnect"
  except TransportOsError:
    trace "TransportOsError", err = getCurrentExceptionMsg()
  except:
    error "Exception in rlpxConnect", remote,
          exc = getCurrentException().name,
          err = getCurrentExceptionMsg()
    result = nil
    raise

  if not ok:
    if not isNil(result.transport):
      result.transport.close()
    result = nil

proc rlpxAccept*(node: EthereumNode,
                 transport: StreamTransport): Future[Peer] {.async.} =
  initTracing(devp2pInfo, node.protocols)

  new result
  result.transport = transport
  result.network = node

  var handshake = newHandshake({Responder})
  handshake.host = node.keys

  var ok = false
  try:
    let initialSize = handshake.expectedLength
    var authMsg = newSeqOfCap[byte](1024)

    authMsg.setLen(initialSize)
    await transport.readExactly(addr authMsg[0], len(authMsg))
    var ret = handshake.decodeAuthMessage(authMsg)
    if ret == AuthStatus.IncompleteError: # Eip8 auth message is likely
      authMsg.setLen(handshake.expectedLength)
      await transport.readExactly(addr authMsg[initialSize],
                                  len(authMsg) - initialSize)
      ret = handshake.decodeAuthMessage(authMsg)
    check ret

    node.checkSnappySupport(handshake, result)
    handshake.version = uint8(result.baseProtocolVersion)

    var ackMsg: array[AckMessageMaxEIP8, byte]
    var ackMsgLen: int
    check handshake.ackMessage(ackMsg, ackMsgLen)
    var res = transport.write(addr ackMsg[0], ackMsgLen)

    initSecretState(handshake, authMsg, ^ackMsg, result)

    let listenPort = transport.localAddress().port

    logAcceptedPeer result

    var sendHelloFut = result.hello(
      result.baseProtocolVersion,
      node.clientId,
      node.capabilities,
      listenPort.uint,
      node.keys.pubkey.getRaw())

    var response = await result.handshakeImpl(
      sendHelloFut,
      result.waitSingleMsg(devp2p.hello),
      10.seconds)

    if not validatePubKeyInHello(response, handshake.remoteHPubkey):
      warn "A Remote nodeId is not its public key" # XXX: Do we care?

    let remote = transport.remoteAddress()
    let address = Address(ip: remote.address, tcpPort: remote.port,
                          udpPort: remote.port)
    result.remote = newNode(initEnode(handshake.remoteHPubkey, address))

    await postHelloSteps(result, response)
    ok = true
  except PeerDisconnected as e:
    if e.reason == AlreadyConnected:
      trace "Disconnect during rlpxAccept", reason = e.reason
    else:
      debug "Unexpected disconnect during rlpxAccept", reason = e.reason
  except TransportIncompleteError:
    trace "Connection dropped in rlpxAccept", remote = result.remote
  except UselessPeerError:
    trace "Disconnecting useless peer", peer = result.remote
  except:
    error "Exception in rlpxAccept",
          err = getCurrentExceptionMsg(),
          stackTrace = getCurrentException().getStackTrace()

  if not ok:
    if not isNil(result.transport):
      result.transport.close()
    result = nil
    raise

when isMainModule:

  when false:
    # The assignments below can be used to investigate if the RLPx procs
    # are considered GcSafe. The short answer is that they aren't, because
    # they dispatch into user code that might use the GC.
    type
      GcSafeDispatchMsg = proc (peer: Peer, msgId: int, msgData: var Rlp)

      GcSafeRecvMsg = proc (peer: Peer):
        Future[tuple[msgId: int, msgData: Rlp]] {.gcsafe.}

      GcSafeAccept = proc (transport: StreamTransport, myKeys: KeyPair):
        Future[Peer] {.gcsafe.}

    var
      dispatchMsgPtr = invokeThunk
      recvMsgPtr: GcSafeRecvMsg = recvMsg
      acceptPtr: GcSafeAccept = rlpxAccept
