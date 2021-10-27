import
  std/[hashes],
  chronos, chronicles,
  ../p2p/discoveryv5/[protocol, node],
  ./utp_router,
  ../keys

type UtpDiscv5Protocol* = ref object of TalkProtocol
  prot: protocol.Protocol
  router: UtpRouter[Node]

proc hash(x: UtpSocketKey[Node]): Hash =
  var h = 0
  h = h !& x.remoteAddress.hash
  h = h !& x.rcvId.hash
  !$h

proc initSendCallback(t: protocol.Protocol, subProtocolName: seq[byte]): SendCallback[Node] =
  return (
    proc (to: Node, data: seq[byte]): Future[void] = 
      let fut = newFuture[void]()
      # TODO In discvoveryv5 each talkreq wait for talkresp, but here we would really
      # like the fire and forget semantics (similar to udp).
      # For now start talkreq/response in background, and discard its result.
      # That way we also lose information about any possible errors.
      # Cosider adding talkreq proc which does not wait for response,
      discard t.talkreq(to, subProtocolName, data)
      fut.complete()
      return fut
  )

proc messageHandler*(protocol: TalkProtocol, request: seq[byte],
    srcId: NodeId, srcUdpAddress: Address): seq[byte] =
    let p = UtpDiscv5Protocol(protocol)
    let maybeSender = p.prot.getNode(srcId)

    if maybeSender.isSome():
      let sender =  maybeSender.unsafeGet()
      # processIncomingBytes may respond to remote by using talkreq requests
      asyncSpawn p.router.processIncomingBytes(request, sender)
      # We always sending empty response as discv5 spec requires that talkreq always
      # receive talkresp
      @[]
    else:
      @[]
    
proc new*(
  T: type UtpDiscv5Protocol,
  p: protocol.Protocol,
  subProtocolName: seq[byte],
  acceptConnectionCb: AcceptConnectionCallback[Node], 
  socketConfig: SocketConfig = SocketConfig.init(),
  rng = newRng()): UtpDiscv5Protocol {.raises: [Defect, CatchableError].} =
  doAssert(not(isNil(acceptConnectionCb)))

  let router = UtpRouter[Node].new(
    acceptConnectionCb,
    socketConfig,
    rng
  )
  router.sendCb = initSendCallback(p, subProtocolName)

  let prot = UtpDiscv5Protocol(
    protocolHandler: messageHandler,
    prot: p,
    router: router
  )

  p.registerTalkProtocol(subProtocolName, prot).expect(
    "Only one protocol should have this id"
  )
  prot

proc connectTo*(r: UtpDiscv5Protocol, address: Node): Future[UtpSocket[Node]]=
  return r.router.connectTo(address)
