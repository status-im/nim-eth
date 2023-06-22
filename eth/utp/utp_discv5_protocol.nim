# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[hashes, sugar],
  chronos, chronicles,
  ../p2p/discoveryv5/[protocol, messages_encoding, encoding],
  ./utp_router,
  ../keys

export utp_router, protocol

logScope:
  topics = "eth utp utp_discv5_protocol"

type
  NodeAddress* = object
    nodeId*: NodeId
    address*: Address

  UtpDiscv5Protocol* = ref object of TalkProtocol
    prot: protocol.Protocol
    router: UtpRouter[NodeAddress]

proc init*(T: type NodeAddress, nodeId: NodeId, address: Address): NodeAddress =
  NodeAddress(nodeId: nodeId, address: address)

proc init*(T: type NodeAddress, node: Node): Option[NodeAddress] =
  node.address.map((address: Address) =>
    NodeAddress(nodeId: node.id, address: address))

proc hash(x: NodeAddress): Hash =
  var h = 0
  h = h !& x.nodeId.hash
  h = h !& x.address.hash
  !$h

proc hash(x: UtpSocketKey[NodeAddress]): Hash =
  var h = 0
  h = h !& x.remoteAddress.hash
  h = h !& x.rcvId.hash
  !$h

func `$`*(x: UtpSocketKey[NodeAddress]): string =
  "(remoteId: " & $x.remoteAddress.nodeId &
  ", remoteAddress: " & $x.remoteAddress.address &
  ", rcvId: " & $x.rcvId &
  ")"

proc talkReqDirect(
    p: protocol.Protocol, n: NodeAddress, protocol, request: seq[byte]):
    Future[void] =
  let
    reqId = RequestId.init(p.rng[])
    message = encodeMessage(
      TalkReqMessage(protocol: protocol, request: request), reqId)
    (data, nonce) = encodeMessagePacket(
      p.rng[], p.codec, n.nodeId, n.address, message)

  trace "Send message packet",
    dstId = n.nodeId, address = n.address, kind = MessageKind.talkreq
  p.send(n.address, data)

proc initSendCallback(
    t: protocol.Protocol, subProtocolName: seq[byte]):
    SendCallback[NodeAddress] =
  return (
    proc (to: NodeAddress, data: seq[byte]): Future[void] =
      let fut = newFuture[void]()
      # hidden assumption here is that nodes already have established discv5
      # session between each other. In our use case this should be true as
      # opening stream is only done after successful OFFER/ACCEPT or
      # FINDCONTENT/CONTENT exchange which forces nodes to establish session
      # between each other.
      discard t.talkReqDirect(to, subProtocolName, data)
      fut.complete()
      return fut
  )

proc messageHandler(protocol: TalkProtocol, request: seq[byte],
    srcId: NodeId, srcUdpAddress: Address): seq[byte] =
  let
    p = UtpDiscv5Protocol(protocol)
    nodeAddress = NodeAddress.init(srcId, srcUdpAddress)
  debug "Received utp payload from known node. Start processing",
    nodeId = nodeAddress.nodeId, address = nodeAddress.address
  asyncSpawn p.router.processIncomingBytes(request, nodeAddress)

proc new*(
    T: type UtpDiscv5Protocol,
    p: protocol.Protocol,
    subProtocolName: seq[byte],
    acceptConnectionCb: AcceptConnectionCallback[NodeAddress],
    udata: pointer = nil,
    allowConnectionCb: AllowConnectionCallback[NodeAddress] = nil,
    socketConfig: SocketConfig = SocketConfig.init()): UtpDiscv5Protocol =
  doAssert(not(isNil(acceptConnectionCb)))

  let router = UtpRouter[NodeAddress].new(
    acceptConnectionCb,
    allowConnectionCb,
    udata,
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

proc new*(
    T: type UtpDiscv5Protocol,
    p: protocol.Protocol,
    subProtocolName: seq[byte],
    acceptConnectionCb: AcceptConnectionCallback[NodeAddress],
    udata: ref,
    allowConnectionCb: AllowConnectionCallback[NodeAddress] = nil,
    socketConfig: SocketConfig = SocketConfig.init()): UtpDiscv5Protocol =
  GC_ref(udata)
  UtpDiscv5Protocol.new(
    p,
    subProtocolName,
    acceptConnectionCb,
    cast[pointer](udata),
    allowConnectionCb,
    socketConfig
  )

proc connectTo*(r: UtpDiscv5Protocol, address: NodeAddress):
    Future[ConnectionResult[NodeAddress]] =
  return r.router.connectTo(address)

proc connectTo*(r: UtpDiscv5Protocol, address: NodeAddress, connectionId: uint16):
    Future[ConnectionResult[NodeAddress]] =
  return r.router.connectTo(address, connectionId)

proc shutdown*(r: UtpDiscv5Protocol) =
  ## Closes all managed utp connections in background (does not close discovery,
  ## this is up to user)
  r.router.shutdown()

proc shutdownWait*(r: UtpDiscv5Protocol) {.async.} =
  ## Closes all managed utp connections in background (does not close discovery,
  ## this is up to user)
  await r.router.shutdownWait()
