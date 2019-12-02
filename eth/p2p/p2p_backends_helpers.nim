var
  gProtocols: seq[ProtocolInfo]

# The variables above are immutable RTTI information. We need to tell
# Nim to not consider them GcSafe violations:
template allProtocols*: auto = {.gcsafe.}: gProtocols

proc getState*(peer: Peer, proto: ProtocolInfo): RootRef =
  peer.protocolStates[proto.index]

template state*(peer: Peer, Protocol: type): untyped =
  ## Returns the state object of a particular protocol for a
  ## particular connection.
  mixin State
  bind getState
  cast[Protocol.State](getState(peer, Protocol.protocolInfo))

proc getNetworkState*(node: EthereumNode, proto: ProtocolInfo): RootRef =
  node.protocolStates[proto.index]

template protocolState*(node: EthereumNode, Protocol: type): untyped =
  mixin NetworkState
  bind getNetworkState
  cast[Protocol.NetworkState](getNetworkState(node, Protocol.protocolInfo))

template networkState*(connection: Peer, Protocol: type): untyped =
  ## Returns the network state object of a particular protocol for a
  ## particular connection.
  protocolState(connection.network, Protocol)

proc initProtocolState*[T](state: T, x: Peer|EthereumNode) {.gcsafe.} = discard

proc initProtocolStates(peer: Peer, protocols: openarray[ProtocolInfo]) =
  # Initialize all the active protocol states
  newSeq(peer.protocolStates, allProtocols.len)
  for protocol in protocols:
    let peerStateInit = protocol.peerStateInitializer
    if peerStateInit != nil:
      peer.protocolStates[protocol.index] = peerStateInit(peer)

proc resolveFuture[MsgType](msg: pointer, future: FutureBase) {.gcsafe.} =
  var f = Future[MsgType](future)
  doAssert(not f.finished())
  f.complete(cast[ptr MsgType](msg)[])

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
      # This can except when the future still completes with an error.
      # E.g. the `sendMsg` fails because of an already closed transport or a
      # broken pipe
      except TransportOsError as e:
        # E.g. broken pipe
        trace "TransportOsError during request", err = e.msg
      except TransportError:
        trace "Transport got closed during request"
      except Exception as e:
        debug "Exception in requestResolver()", exc = e.name, err = e.msg
        raise

proc linkSendFailureToReqFuture[S, R](sendFut: Future[S], resFut: Future[R]) =
  sendFut.addCallback() do (arg: pointer):
    if not sendFut.error.isNil:
      resFut.fail(sendFut.error)

proc messagePrinter[MsgType](msg: pointer): string {.gcsafe.} =
  result = ""
  # TODO: uncommenting the line below increases the compile-time
  # tremendously (for reasons not yet known)
  # result = $(cast[ptr MsgType](msg)[])

proc disconnectAndRaise(peer: Peer,
                        reason: DisconnectionReason,
                        msg: string) {.async.}

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
    await disconnectAndRaise(peer, HandshakeTimeout,
                             "Protocol handshake was not received in time.")
  elif responseFut.failed:
    raise responseFut.error
  else:
    return responseFut.read

