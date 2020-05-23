
## Generated at line 781
type
  DevP2P* = object
type
  helloObj* = object
    version*: uint
    clientId*: string
    capabilities*: seq[Capability]
    listenPort*: uint
    nodeId*: array[RawPublicKeySize, byte]

template hello*(PROTO: type DevP2P): type =
  helloObj

template msgProtocol*(MSG: type helloObj): type =
  DevP2P

template RecType*(MSG: type helloObj): untyped =
  helloObj

template msgId*(MSG: type helloObj): int =
  0

type
  sendDisconnectMsgObj* = object
    reason*: DisconnectionReasonList

template sendDisconnectMsg*(PROTO: type DevP2P): type =
  sendDisconnectMsgObj

template msgProtocol*(MSG: type sendDisconnectMsgObj): type =
  DevP2P

template RecType*(MSG: type sendDisconnectMsgObj): untyped =
  sendDisconnectMsgObj

template msgId*(MSG: type sendDisconnectMsgObj): int =
  1

type
  pingObj* = object
    emptyList*: EmptyList

template ping*(PROTO: type DevP2P): type =
  pingObj

template msgProtocol*(MSG: type pingObj): type =
  DevP2P

template RecType*(MSG: type pingObj): untyped =
  pingObj

template msgId*(MSG: type pingObj): int =
  2

type
  pongObj* = object
    emptyList*: EmptyList

template pong*(PROTO: type DevP2P): type =
  pongObj

template msgProtocol*(MSG: type pongObj): type =
  DevP2P

template RecType*(MSG: type pongObj): untyped =
  pongObj

template msgId*(MSG: type pongObj): int =
  3

var DevP2PProtocolObj = initProtocol("p2p", 5, nil, nil)
var DevP2PProtocol = addr DevP2PProtocolObj
template protocolInfo*(P`gensym75730262: type DevP2P): auto =
  DevP2PProtocol

proc hello*(peerOrResponder: Peer; version: uint; clientId: string;
           capabilities: seq[Capability]; listenPort: uint;
           nodeId: array[RawPublicKeySize, byte]): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 0
  let perPeerMsgId = 0
  append(writer, perPeerMsgId)
  startList(writer, 5)
  append(writer, version)
  append(writer, clientId)
  append(writer, capabilities)
  append(writer, listenPort)
  append(writer, nodeId)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc sendDisconnectMsg*(peerOrResponder: Peer; reason: DisconnectionReasonList): Future[
    void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 1
  let perPeerMsgId = 1
  append(writer, perPeerMsgId)
  append(writer, reason)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc ping*(peerOrResponder: Peer; emptyList: EmptyList): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 2
  let perPeerMsgId = 2
  append(writer, perPeerMsgId)
  append(writer, emptyList)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc pong*(peerOrResponder: Peer; emptyList: EmptyList): Future[void] {.gcsafe.} =
  let peer = getPeer(peerOrResponder)
  var writer = initRlpWriter()
  const
    perProtocolMsgId = 3
  let perPeerMsgId = 3
  append(writer, perPeerMsgId)
  append(writer, emptyList)
  let msgBytes = finish(writer)
  return sendMsg(peer, msgBytes)

proc sendDisconnectMsgUserHandler(peer: Peer; reason: DisconnectionReasonList) {.
    gcsafe, async.} =
  type
    CurrentProtocol = DevP2P
  const
    perProtocolMsgId = 1
  trace "disconnect message received", reason = reason.value, peer
  await peer.disconnect(reason.value, false)

proc pingUserHandler(peer: Peer; emptyList: EmptyList) {.gcsafe, async.} =
  type
    CurrentProtocol = DevP2P
  const
    perProtocolMsgId = 2
  discard peer.pong(EmptyList())

proc pongUserHandler(peer: Peer; emptyList: EmptyList) {.gcsafe, async.} =
  type
    CurrentProtocol = DevP2P
  const
    perProtocolMsgId = 3
  discard

proc helloThunk(peer: Peer; _`gensym75730215: int; data`gensym75730216: Rlp) {.async,
    gcsafe.} =
  var rlp = data`gensym75730216
  var msg {.noinit.}: helloObj
  tryEnterList(rlp)
  msg.version = checkedRlpRead(peer, rlp, uint)
  msg.clientId = checkedRlpRead(peer, rlp, string)
  msg.capabilities = checkedRlpRead(peer, rlp, seq[Capability])
  msg.listenPort = checkedRlpRead(peer, rlp, uint)
  msg.nodeId = checkedRlpRead(peer, rlp, array[RawPublicKeySize, byte])
  
proc sendDisconnectMsgThunk(peer: Peer; _`gensym75730250: int;
                           data`gensym75730251: Rlp) {.async, gcsafe.} =
  var rlp = data`gensym75730251
  var msg {.noinit.}: sendDisconnectMsgObj
  msg.reason = checkedRlpRead(peer, rlp, DisconnectionReasonList)
  await(sendDisconnectMsgUserHandler(peer, msg.reason))
  
proc pingThunk(peer: Peer; _`gensym75730252: int; data`gensym75730253: Rlp) {.async,
    gcsafe.} =
  var rlp = data`gensym75730253
  var msg {.noinit.}: pingObj
  msg.emptyList = checkedRlpRead(peer, rlp, EmptyList)
  await(pingUserHandler(peer, msg.emptyList))
  
proc pongThunk(peer: Peer; _`gensym75730254: int; data`gensym75730255: Rlp) {.async,
    gcsafe.} =
  var rlp = data`gensym75730255
  var msg {.noinit.}: pongObj
  msg.emptyList = checkedRlpRead(peer, rlp, EmptyList)
  await(pongUserHandler(peer, msg.emptyList))
  
registerMsg(DevP2PProtocol, 0, "hello", helloThunk, messagePrinter[helloObj],
            requestResolver[helloObj], nextMsgResolver[helloObj])
registerMsg(DevP2PProtocol, 1, "sendDisconnectMsg", sendDisconnectMsgThunk,
            messagePrinter[sendDisconnectMsgObj],
            requestResolver[sendDisconnectMsgObj],
            nextMsgResolver[sendDisconnectMsgObj])
registerMsg(DevP2PProtocol, 2, "ping", pingThunk, messagePrinter[pingObj],
            requestResolver[pingObj], nextMsgResolver[pingObj])
registerMsg(DevP2PProtocol, 3, "pong", pongThunk, messagePrinter[pongObj],
            requestResolver[pongObj], nextMsgResolver[pongObj])
setEventHandlers(DevP2PProtocol, nil, nil)
registerProtocol(DevP2PProtocol)