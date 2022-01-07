# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[hashes],
  chronos, chronicles,
  ../p2p/discoveryv5/protocol,
  ./utp_router,
  ../keys

export utp_router, protocol

type UtpDiscv5Protocol* = ref object of TalkProtocol
  prot: protocol.Protocol
  router: UtpRouter[Node]

proc hash(x: UtpSocketKey[Node]): Hash =
  var h = 0
  h = h !& x.remoteAddress.hash
  h = h !& x.rcvId.hash
  !$h

func `$`*(x: UtpSocketKey[Node]): string =
  "(remoteId: " & $x.remoteAddress.id &
  ", remoteAddress: " & $x.remoteAddress.address &
  ", rcvId: "& $x.rcvId &
  ")"

proc initSendCallback(
    t: protocol.Protocol, subProtocolName: seq[byte]): SendCallback[Node] =
  return (
    proc (to: Node, data: seq[byte]): Future[void] =
      let fut = newFuture[void]()
      # TODO: In discovery v5 each talkreq waits for a talkresp, but here we
      # would really like the fire and forget semantics (similar to udp).
      # For now start talkreq/talkresp in background, and discard its result.
      # That way we also lose information about any possible errors.
      # Consider adding talkreq proc which does not wait for the response.
      discard t.talkreq(to, subProtocolName, data)
      fut.complete()
      return fut
  )

proc messageHandler(protocol: TalkProtocol, request: seq[byte],
    srcId: NodeId, srcUdpAddress: Address): seq[byte] =
  let p = UtpDiscv5Protocol(protocol)
  let maybeSender = p.prot.getNode(srcId)

  if maybeSender.isSome():
    let sender =  maybeSender.unsafeGet()
    # processIncomingBytes may respond to remote by using talkreq requests
    asyncSpawn p.router.processIncomingBytes(request, sender)
    # We always send empty responses as discv5 spec requires that talkreq
    # always receives a talkresp.
    @[]
  else:
    @[]

proc new*(
    T: type UtpDiscv5Protocol,
    p: protocol.Protocol,
    subProtocolName: seq[byte],
    acceptConnectionCb: AcceptConnectionCallback[Node],
    allowConnectionCb: AllowConnectionCallback[Node] = nil,
    socketConfig: SocketConfig = SocketConfig.init()): UtpDiscv5Protocol =
  doAssert(not(isNil(acceptConnectionCb)))

  let router = UtpRouter[Node].new(
    acceptConnectionCb,
    allowConnectionCb,
    socketConfig,
    p.rng
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

proc connectTo*(r: UtpDiscv5Protocol, address: Node):
    Future[ConnectionResult[Node]] =
  return r.router.connectTo(address)

proc connectTo*(r: UtpDiscv5Protocol, address: Node, connectionId: uint16):
    Future[ConnectionResult[Node]] =
  return r.router.connectTo(address, connectionId)

proc shutdown*(r: UtpDiscv5Protocol) =
  ## Closes all managed utp connections in background (does not close discovery,
  ## this is up to user)
  r.router.shutdown()

proc shutdownWait*(r: UtpDiscv5Protocol) {.async.} =
  ## Closes all managed utp connections in background (does not close discovery,
  ## this is up to user)
  await r.router.shutdownWait()
