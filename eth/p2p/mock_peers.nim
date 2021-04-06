import
  std/[macros, deques, algorithm],
  chronos,
  ".."/[keys, rlp, p2p], ../common/eth_types,
  ./private/p2p_types, ./rlpx

type
  Action = proc (p: Peer, data: Rlp): Future[void] {.gcsafe.}

  ProtocolMessagePair = object
    protocol: ProtocolInfo
    id: int

  ExpectedMsg = object
    msg: ProtocolMessagePair
    response: Action

  MockConf* = ref object
    keys*: KeyPair
    address*: Address
    networkId*: uint
    chain*: AbstractChainDB
    clientId*: string
    waitForHello*: bool

    devp2pHandshake: ExpectedMsg
    handshakes: seq[ExpectedMsg]
    protocols: seq[ProtocolInfo]

    expectedMsgs: Deque[ExpectedMsg]
    receivedMsgsCount: int
    when useSnappy:
      useCompression*: bool

var
  nextUnusedMockPort = 40304

proc toAction(a: Action): Action = a

proc toAction[N](actions: array[N, Action]): Action =
  mixin await
  result = proc (peer: Peer, data: Rlp) {.async.} =
    for a in actions:
      await a(peer, data)

proc toAction(a: proc (): Future[void]): Action =
  result = proc (peer: Peer, data: Rlp) {.async.} =
    await a()

proc toAction(a: proc (peer: Peer): Future[void]): Action =
  result = proc (peer: Peer, data: Rlp) {.async.} =
    await a(peer)

proc delay*(duration: int): Action =
  result = proc (p: Peer, data: Rlp) {.async.} =
    await sleepAsync(duration)

proc reply(bytes: Bytes): Action =
  result = proc (p: Peer, data: Rlp) {.async.} =
    await p.sendMsg(bytes)

proc reply*[Msg](msg: Msg): Action =
  mixin await
  result = proc (p: Peer, data: Rlp) {.async.} =
    await p.send(msg)

proc localhostAddress*(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))

proc makeProtoMsgPair(MsgType: type): ProtocolMessagePair =
  mixin msgProtocol, protocolInfo
  result.protocol = MsgType.msgProtocol.protocolInfo
  result.id = MsgType.msgId

proc readReqId*(rlp: Rlp): int =
  var r = rlp
  return r.read(int)

proc expectationViolationMsg(mock: MockConf,
                             reason: string,
                             receivedMsg: ptr MessageInfo): string =
  result = "[Mock expectation violated] " & reason & ": " & receivedMsg.name
  for i in 0 ..< mock.expectedMsgs.len:
    let expected = mock.expectedMsgs[i].msg
    result.add "\n  " & expected.protocol.messages[expected.id].name
    if i == mock.receivedMsgsCount: result.add " <- we are here"
  result.add "\n"

proc addProtocol(mock: MockConf, p: ProtocolInfo): ProtocolInfo =
  result = create ProtocolInfoObj
  deepCopy(result[], p[])

  proc incomingMsgHandler(p: Peer, receivedMsgId: int, rlp: Rlp): Future[void] {.gcsafe.} =
    let (receivedMsgProto, receivedMsgInfo) = p.getMsgMetadata(receivedMsgId)
    let expectedMsgIdx = mock.receivedMsgsCount

    template fail(reason: string) =
      stdout.write mock.expectationViolationMsg(reason, receivedMsgInfo)
      quit 1

    if expectedMsgIdx > mock.expectedMsgs.len:
      fail "Mock peer received more messages than expected"

    let expectedMsg = mock.expectedMsgs[expectedMsgIdx]
    if receivedMsgInfo.id != expectedMsg.msg.id or
       receivedMsgProto.name != expectedMsg.msg.protocol.name:
      fail "Mock peer received an unexpected message"

    inc mock.receivedMsgsCount
    if expectedMsg.response != nil:
      return expectedMsg.response(p, rlp)
    else:
      result = newFuture[void]()
      result.complete()

  for m in mitems(result.messages):
    m.thunk = incomingMsgHandler

  result.handshake = nil

  # TODO This mock conf can override this
  result.disconnectHandler = nil

  mock.protocols.add result

proc addHandshake*(mock: MockConf, msg: auto) =
  var msgInfo = makeProtoMsgPair(msg.type)
  msgInfo.protocol = mock.addProtocol(msgInfo.protocol)
  let expectedMsg = ExpectedMsg(msg: msgInfo, response: reply(msg))

  when msg is DevP2P.hello:
    devp2pHandshake = expectedMsg
  else:
    mock.handshakes.add expectedMsg

proc addCapability*(mock: MockConf, Protocol: type) =
  mixin defaultTestingHandshake, protocolInfo

  when compiles(defaultTestingHandshake(Protocol)):
    mock.addHandshake(defaultTestingHandshake(Protocol))
  else:
    discard mock.addProtocol(Protocol.protocolInfo)

proc expectImpl(mock: MockConf, msg: ProtocolMessagePair, action: Action) =
  mock.expectedMsgs.addLast ExpectedMsg(msg: msg, response: action)

macro expect*(mock: MockConf, MsgType: type, handler: untyped = nil): untyped =
  if handler.kind in {nnkLambda, nnkDo}:
    handler.addPragma ident("async")

  result = newCall(
    bindSym("expectImpl"),
    mock,
    newCall(bindSym"makeProtoMsgPair", MsgType.getType),
    newCall(bindSym"toAction", handler))

template compression(m: MockConf): bool =
  when useSnappy:
    m.useCompression
  else:
    false

proc newMockPeer*(userConfigurator: proc (m: MockConf)): EthereumNode =
  var mockConf = new MockConf
  mockConf.keys = KeyPair.random()[]
  mockConf.address = localhostAddress(nextUnusedMockPort)
  inc nextUnusedMockPort
  mockConf.networkId = 1'u
  mockConf.clientId = "Mock Peer"
  mockConf.waitForHello = true
  mockConf.expectedMsgs = initDeque[ExpectedMsg]()

  userConfigurator(mockConf)

  var node = newEthereumNode(mockConf.keys,
                             mockConf.address,
                             mockConf.networkId,
                             mockConf.chain,
                             mockConf.clientId,
                             addAllCapabilities = false,
                             mockConf.compression())

  mockConf.handshakes.sort do (lhs, rhs: ExpectedMsg) -> int:
    # this is intentially sorted in reverse order, so we
    # can add them in the correct order below.
    return -cmp(lhs.msg.protocol.index, rhs.msg.protocol.index)

  for h in mockConf.handshakes:
    mockConf.expectedMsgs.addFirst h

  for p in mockConf.protocols:
    node.addCapability p

  when false:
    # TODO: This part doesn't work correctly yet.
    # rlpx{Connect,Accept} control the handshake.
    if mockConf.devp2pHandshake.response != nil:
      mockConf.expectedMsgs.addFirst mockConf.devp2pHandshake
    else:
      proc sendHello(p: Peer, data: Rlp) {.async.} =
        await p.hello(devp2pVersion,
                      mockConf.clientId,
                      node.capabilities,
                      uint(node.address.tcpPort),
                      node.keys.pubkey.getRaw())

      mockConf.expectedMsgs.addFirst ExpectedMsg(
        msg: makeProtoMsgPair(p2p.hello),
        response: sendHello)

  node.startListening()
  return node

proc rlpxConnect*(node, otherNode: EthereumNode): Future[Peer] =
  let otherAsRemote = newNode(otherNode.toENode())
  return rlpx.rlpxConnect(node, otherAsRemote)
