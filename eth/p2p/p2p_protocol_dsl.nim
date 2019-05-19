import
  macros,
  std_shims/macros_shim, chronos/timer

type
  MessageKind* = enum
    msgHandshake
    msgNotification
    msgRequest
    msgResponse

  Message* = ref object
    id*: int
    ident*: NimNode
    kind*: MessageKind
    procDef*: NimNode
    timeoutParam*: NimNode
    recIdent*: NimNode
    recBody*: NimNode
    userHandler*: NimNode

  Request* = ref object
    queries*: seq[Message]
    response*: Message

  P2PProtocol* = ref object
    # Settings
    name*: string
    version*: int
    timeouts*: int64
    useRequestIds*: bool
    shortName*: string
    outgoingRequestDecorator*: NimNode
    incomingRequestDecorator*: NimNode
    incomingRequestThunkDecorator*: NimNode
    incomingResponseDecorator*: NimNode
    incomingResponseThunkDecorator*: NimNode
    PeerStateType*: NimNode
    NetworkStateType*: NimNode
    backend*: Backend

    # Cached properties
    nameIdent*: NimNode
    protocolInfoVar*: NimNode

    # All messages
    messages*: seq[Message]

    # Messages by type:
    handshake*: Message
    notifications*: seq[Message]
    requests*: seq[Request]

    # Output procs
    outSendProcs*: NimNode
    outRecvProcs*: NimNode
    outProcRegistrations*: NimNode

    # Event handlers
    onPeerConnected*: NimNode
    onPeerDisconnected*: NimNode

  Backend* = ref object
    # Code generators
    implementMsg*: proc (p: P2PProtocol, msg: Message, resp: Message = nil)
    implementProtocolInit*: proc (p: P2PProtocol): NimNode
    afterProtocolInit*: proc (p: P2PProtocol)

    # Bound symbols to the back-end run-time types and procs
    PeerType*: NimNode
    NetworkType*: NimNode

    registerProtocol*: NimNode
    setEventHandlers*: NimNode

  BackendFactory* = proc (p: P2PProtocol): Backend

const
  defaultReqTimeout = 10.seconds

proc createPeerState[Peer, ProtocolState](peer: Peer): RootRef =
  var res = new ProtocolState
  mixin initProtocolState
  initProtocolState(res, peer)
  return cast[RootRef](res)

proc createNetworkState[NetworkNode, NetworkState](network: NetworkNode): RootRef {.gcsafe.} =
  var res = new NetworkState
  mixin initProtocolState
  initProtocolState(res, network)
  return cast[RootRef](res)

proc expectBlockWithProcs*(n: NimNode): seq[NimNode] =
  template helperName: auto = $n[0]

  if n.len != 2 or n[1].kind != nnkStmtList:
    error(helperName & " expects a block", n)

  for p in n[1]:
    if p.kind == nnkProcDef:
      result.add p
    elif p.kind == nnkCommentStmt:
      continue
    else:
      error(helperName & " expects a proc definition.", p)

proc nameOrNil*(procDef: NimNode): NimNode =
  if procDef != nil:
    procDef.name
  else:
    newNilLit()

proc chooseFieldType(n: NimNode): NimNode =
  ## Examines the parameter types used in the message signature
  ## and selects the corresponding field type for use in the
  ## message object type (i.e. `p2p.hello`).
  ##
  ## For now, only openarray types are remapped to sequences.
  result = n
  if n.kind == nnkBracketExpr and eqIdent(n[0], "openarray"):
    result = n.copyNimTree
    result[0] = ident("seq")

proc verifyStateType(t: NimNode): NimNode =
  result = t[1]
  if result.kind == nnkSym and $result == "nil":
    return nil
  if result.kind != nnkBracketExpr or $result[0] != "ref":
    error $result & " must be a ref type"

proc processProtocolBody*(p: P2PProtocol, protocolBody: NimNode)

proc init*(T: type P2PProtocol, backendFactory: BackendFactory,
           name: string, version: int, body: NimNode,
           timeouts: int64, useRequestIds: bool, shortName: string,
           outgoingRequestDecorator: NimNode,
           incomingRequestDecorator: NimNode,
           incomingRequestThunkDecorator: NimNode,
           incomingResponseDecorator: NimNode,
           incomingResponseThunkDecorator: NimNode,
           peerState, networkState: NimNode): P2PProtocol =

  result = P2PProtocol(
    name: name,
    version: version,
    timeouts: timeouts,
    useRequestIds: useRequestIds,
    shortName: shortName,
    outgoingRequestDecorator: outgoingRequestDecorator,
    incomingRequestDecorator: incomingRequestDecorator,
    incomingRequestThunkDecorator: incomingRequestThunkDecorator,
    incomingResponseDecorator: incomingResponseDecorator,
    incomingResponseThunkDecorator: incomingResponseThunkDecorator,
    PeerStateType: verifyStateType peerState,
    NetworkStateType: verifyStateType networkState,
    nameIdent: ident(name),
    protocolInfoVar: ident(name & "Protocol"),
    outSendProcs: newStmtList(),
    outRecvProcs: newStmtList(),
    outProcRegistrations: newStmtList())

  result.backend = backendFactory(result)
  result.processProtocolBody body

  if not result.backend.afterProtocolInit.isNil:
    result.backend.afterProtocolInit(result)

proc augmentUserHandler(p: P2PProtocol, userHandlerProc: NimNode, msgId = -1) =
  ## This procs adds a set of common helpers available in all messages handlers
  ## (e.g. `perProtocolMsgId`, `peer.state`, etc).
  var
    prelude = newStmtList()
    getState = ident"getState"
    getNetworkState = ident"getNetworkState"
    currentProtocolSym = ident"CurrentProtocol"
    perProtocolMsgId = ident"perProtocolMsgId"
    protocolInfoVar = p.protocolInfoVar
    protocolNameIdent = p.nameIdent
    PeerType = p.backend.PeerType
    PeerStateType = p.PeerStateType
    NetworkStateType = p.NetworkStateType

  userHandlerProc.addPragma ident"gcsafe"
  userHandlerProc.addPragma ident"async"

  userHandlerProc.body.insert 0, prelude

  when false:
    # TODO
    ## Turns a regular proc definition into an async proc and adds
    ## the helpers for accessing the peer and network protocol states.
    case msgKind
    of msgRequest:  userHandlerProc.applyDecorator incomingRequestDecorator
    of msgResponse: userHandlerProc.applyDecorator incomingResponseDecorator
    else: discard

  # We allow the user handler to use `openarray` params, but we turn
  # those into sequences to make the `async` pragma happy.
  for i in 1 ..< userHandlerProc.params.len:
    var param = userHandlerProc.params[i]
    param[^2] = chooseFieldType(param[^2])

  prelude.add quote do:
    type `currentProtocolSym` = `protocolNameIdent`

  if msgId >= 0:
    prelude.add quote do:
      const `perProtocolMsgId` = `msgId`

  # Define local accessors for the peer and the network protocol states
  # inside each user message handler proc (e.g. peer.state.foo = bar)
  if PeerStateType != nil:
    prelude.add quote do:
      template state(p: `PeerType`): `PeerStateType` =
        cast[`PeerStateType`](`getState`(p, `protocolInfoVar`))

  if NetworkStateType != nil:
    prelude.add quote do:
      template networkState(p: `PeerType`): `NetworkStateType` =
        cast[`NetworkStateType`](`getNetworkState`(p.network, `protocolInfoVar`))

proc addPreludeDefs*(userHandlerProc: NimNode, definitions: NimNode) =
  userHandlerProc.body[0].add definitions

proc eventHandlerToProc(p: P2PProtocol, doBlock: NimNode, handlerName: string): NimNode =
  ## Turns a "named" do block to a regular async proc
  ## (e.g. onPeerConnected do ...)
  result = newTree(nnkProcDef)
  doBlock.copyChildrenTo(result)
  result.name = ident(p.name & handlerName) # genSym(nskProc, p.name & handlerName)
  p.augmentUserHandler result

proc ensureTimeoutParam(procDef: NimNode, timeouts: int64): NimNode =
  ## Make sure the messages has a timeout parameter and it has the correct type.
  ## The parameter will be removed from the signature and returned for caching
  ## in the Message's timeoutParam field. It is needed only for the send procs.
  var
    Duration = bindSym"Duration"
    milliseconds = bindSym"milliseconds"
    lastParam = procDef.params[^1]

  if eqIdent(lastParam[0], "timeout"):
    if lastParam[2].kind == nnkEmpty:
      error "You must specify a default value for the `timeout` parameter", lastParam
    lastParam[2] = newCall(milliseconds, newLit(100))#  newCall(Duration, lastParam[2])
    if lastParam[1].kind == nnkEmpty:
      lastParam[1] = Duration
    elif not eqIdent(lastParam[1], "Duration"):
      error "The timeout parameter should be of type 'chronos.Duration'", lastParam[1]

    result = lastParam
    procDef.params.del(procDef.params.len - 1)

  else:
    result = newTree(nnkIdentDefs,
                     ident"timeout",
                     Duration,
                     newCall(milliseconds, newLit(timeouts)))

proc newMsg(p: P2PProtocol, kind: MessageKind, id: int,
            procDef: NimNode, timeoutParam: NimNode = nil): Message =

  if procDef[0].kind == nnkPostfix:
    error("p2pProcotol procs are public by default. " &
          "Please remove the postfix `*`.", procDef)

  var
    msgIdent = procDef.name
    msgName = $msgIdent
    recFields = newTree(nnkRecList)
    recBody = newTree(nnkObjectTy, newEmptyNode(), newEmptyNode(), recFields)
    recName = ident(msgName & "Obj")

  for param, paramType in procDef.typedParams(skip = 1):
    recFields.add newTree(nnkIdentDefs,
      newTree(nnkPostfix, ident("*"), param), # The fields are public
      chooseFieldType(paramType),             # some types such as openarray
                                              # are automatically remapped
      newEmptyNode())

  result = Message(id: id, ident: msgIdent, kind: kind,
                   procDef: procDef, recIdent: recName, recBody: recBody,
                   timeoutParam: timeoutParam)

  if procDef.body.kind != nnkEmpty:
    result.userHandler = copy procDef
    p.augmentUserHandler result.userHandler
    result.userHandler.name = genSym(nskProc, msgName)

  p.messages.add result

proc identWithExportMarker*(msg: Message): NimNode =
  newTree(nnkPostfix, ident("*"), msg.ident)

proc createSendProc*(msg: Message, procType = nnkProcDef): NimNode =
  # TODO: file an issue:
  # macros.newProc and macros.params doesn't work with nnkMacroDef

  let pragmas = if procType == nnkProcDef: newTree(nnkPragma, ident"gcsafe")
                else: newEmptyNode()

  result = newNimNode(procType).add(
    msg.identWithExportMarker, ## name
    newEmptyNode(),
    newEmptyNode(),
    msg.procDef.params.copy, ## params
    pragmas,
    newEmptyNode(),
    newStmtList()) ## body

  if msg.kind in {msgHandshake, msgRequest}:
    result[3].add msg.timeoutParam

  result[3][0] = if procType == nnkMacroDef: ident "untyped"
                 else: newTree(nnkBracketExpr, ident("Future"), msg.recIdent)

proc appendAllParams*(node: NimNode, procDef: NimNode, skipFirst = 0): NimNode =
  result = node
  for p, _ in procDef.typedParams(skip = skipFirst):
    result.add p

proc netInit*(p: P2PProtocol): NimNode =
  if p.NetworkStateType == nil:
    newNilLit()
  else:
    newTree(nnkBracketExpr, bindSym"createNetworkState",
                            p.backend.NetworkType,
                            p.NetworkStateType)

proc peerInit*(p: P2PProtocol): NimNode =
  if p.PeerStateType == nil:
    newNilLit()
  else:
    newTree(nnkBracketExpr, bindSym"createPeerState",
                            p.backend.PeerType,
                            p.PeerStateType)

proc processProtocolBody*(p: P2PProtocol, protocolBody: NimNode) =
  ## This procs handles all DSL statements valid inside a p2pProtocol.
  ##
  ## It will populate the protocol's fields such as:
  ##   * handshake
  ##   * requests
  ##   * notifications
  ##   * onPeerConnected
  ##   * onPeerDisconnected
  ##
  ## All messages will have properly computed numeric IDs
  ##
  var nextId = 0

  for n in protocolBody:
    case n.kind
    of {nnkCall, nnkCommand}:
      if eqIdent(n[0], "nextID"):
        # By default message IDs are assigned in increasing order
        # `nextID` can be used to skip some of the numeric slots
        if n.len == 2 and n[1].kind == nnkIntLit:
          nextId = n[1].intVal.int
        else:
          error("nextID expects a single int value", n)

      elif eqIdent(n[0], "requestResponse"):
        # `requestResponse` can be given a block of 2 or more procs.
        # The last one is considered to be a response message, while
        # all preceeding ones are requests triggering the response.
        # The system makes sure to automatically insert a hidden `reqId`
        # parameter used to discriminate the individual messages.
        let procs = expectBlockWithProcs(n)
        if procs.len < 2:
          error "requestResponse expects a block with at least two proc definitions"

        var queries = newSeq[Message]()
        for i in 0 .. procs.len - 2:
          var timeout = ensureTimeoutParam(procs[i], p.timeouts)
          queries.add p.newMsg(msgRequest, nextId + i, procs[i], timeout)

        p.requests.add Request(
          queries: queries,
          response: p.newMsg(msgResponse, nextId + procs.len - 1, procs[^1]))

        inc nextId, procs.len

      elif eqIdent(n[0], "handshake"):
        let procs = expectBlockWithProcs(n)
        if procs.len != 1:
          error "handshake expects a block with a single proc definition", n

        if p.handshake != nil:
          error "The handshake for the protocol is already defined", n

        var timeout = ensureTimeoutParam(procs[0], p.timeouts)
        p.handshake = p.newMsg(msgHandshake, nextId, procs[0], timeout)
        inc nextId

      elif eqIdent(n[0], "onPeerConnected"):
        p.onPeerConnected = p.eventHandlerToProc(n[1], "PeerConnected")

      elif eqIdent(n[0], "onPeerDisconnected"):
        p.onPeerDisconnected = p.eventHandlerToProc(n[1], "PeerDisconnected")

      else:
        error(repr(n) & " is not a recognized call in P2P protocol definitions", n)

    of nnkProcDef:
      p.notifications.add p.newMsg(msgNotification, nextId, n)
      inc nextId

    of nnkCommentStmt:
      discard

    else:
      error "Illegal syntax in a P2P protocol definition", n

proc genTypeSection*(p: P2PProtocol): NimNode =
  var
    protocolName = p.nameIdent
    peerState = p.PeerStateType
    networkState= p.NetworkStateType

  result = newStmtList()
  result.add quote do:
    # Create a type acting as a pseudo-object representing the protocol
    # (e.g. p2p)
    type `protocolName`* = object

  if peerState != nil:
    result.add quote do:
      template State*(P: type `protocolName`): type = `peerState`

  if networkState != nil:
    result.add quote do:
      template NetworkState*(P: type `protocolName`): type = `networkState`

  for msg in p.messages:
    let
      msgId = msg.id
      msgName = msg.ident
      msgRecName = msg.recIdent
      msgRecBody = msg.recBody

    result.add quote do:
      # This is a type featuring a single field for each message param:
      type `msgRecName`* = `msgRecBody`

      # Add a helper template for accessing the message type:
      # e.g. p2p.hello:
      template `msgName`*(T: type `protocolName`): type = `msgRecName`

      # Add a helper template for obtaining the message Id for
      # a particular message type:
      template msgId*(T: type `msgRecName`): int = `msgId`
      template msgProtocol*(T: type `msgRecName`): type = `protocolName`

proc genCode*(p: P2PProtocol): NimNode =
  # TODO: try switching to a simpler for msg in p.messages: loop
  if p.handshake != nil:
    p.backend.implementMsg p, p.handshake

  for msg in p.notifications:
    p.backend.implementMsg p, msg

  for req in p.requests:
    p.backend.implementMsg p, req.response
    for query in req.queries: p.backend.implementMsg(p, query, req.response)

  result = newStmtList()
  result.add p.genTypeSection()

  let
    protocolInfoVar = p.protocolInfoVar
    protocolName = p.nameIdent
    protocolInit = p.backend.implementProtocolInit(p)

  result.add quote do:
    # One global variable per protocol holds the protocol run-time data
    var p = `protocolInit`
    var `protocolInfoVar` = addr p

    # The protocol run-time data is available as a pseudo-field
    # (e.g. `p2p.protocolInfo`)
    template protocolInfo*(P: type `protocolName`): auto = `protocolInfoVar`

  result.add p.outSendProcs,
             p.outRecvProcs,
             p.outProcRegistrations

  if p.onPeerConnected != nil: result.add p.onPeerConnected
  if p.onPeerDisconnected != nil: result.add p.onPeerDisconnected

  result.add newCall(p.backend.setEventHandlers,
                     protocolInfoVar,
                     nameOrNil p.onPeerConnected,
                     nameOrNil p.onPeerDisconnected)

  result.add newCall(p.backend.registerProtocol, protocolInfoVar)

macro emitForSingleBackend(
    name: static[string],
    version: static[int],
    backend: static[BackendFactory],
    body: untyped,
    # TODO Nim can't handle a proper duration paramter here
    timeouts: static[int64] = defaultReqTimeout.milliseconds,
    useRequestIds: static[bool] = true,
    shortName: static[string] = "",
    outgoingRequestDecorator: untyped = nil,
    incomingRequestDecorator: untyped = nil,
    incomingRequestThunkDecorator: untyped = nil,
    incomingResponseDecorator: untyped = nil,
    incomingResponseThunkDecorator: untyped = nil,
    peerState = type(nil),
    networkState = type(nil)): untyped =

  var p = P2PProtocol.init(
    backend,
    name, version, body, timeouts,
    useRequestIds, shortName,
    outgoingRequestDecorator,
    incomingRequestDecorator,
    incomingRequestThunkDecorator,
    incomingResponseDecorator,
    incomingResponseThunkDecorator,
    peerState.getType, networkState.getType)

  result = p.genCode()

  when defined(debugRlpxProtocol) or defined(debugMacros):
    echo repr(result)

macro emitForAllBackends(backendSyms: typed, options: untyped, body: untyped): untyped =
  let name = $(options[0])

  var backends = newSeq[NimNode]()
  if backendSyms.kind == nnkSym:
    backends.add backendSyms
  else:
    for backend in backendSyms:
      backends.add backend

  result = newStmtList()

  for backend in backends:
    let call = copy options
    call[0] = bindSym"emitForSingleBackend"
    call.add newTree(nnkExprEqExpr, ident("name"), newLit(name))
    call.add newTree(nnkExprEqExpr, ident("backend"), backend)
    call.add newTree(nnkExprEqExpr, ident("body"), body)
    result.add call

template p2pProtocol*(options: untyped, body: untyped) {.dirty.} =
  bind emitForAllBackends
  emitForAllBackends(p2pProtocolBackendImpl, options, body)

