import
  options, sequtils,
  stew/shims/macros, chronos, faststreams/outputs

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
    recName*: NimNode
    strongRecName*: NimNode
    recBody*: NimNode
    protocol*: P2PProtocol
    response*: Message
    userHandler*: NimNode
    initResponderCall*: NimNode

  Request* = ref object
    queries*: seq[Message]
    response*: Message

  SendProc* = object
    ## A `SendProc` is a proc used to send a single P2P message.
    ## If it's a Request, then the return type will be a Future
    ## of the respective Response type. All send procs also have
    ## an automatically inserted `timeout` parameter.

    msg*: Message
      ## The message being implemented

    def*: NimNode
      ## The definition of the proc

    peerParam*: NimNode
      ## Cached ident for the peer param

    msgParams*: seq[NimNode]
      ## Cached param ident for all values that must be written
      ## on the wire. The automatically inserted `timeout` is not
      ## included.

    timeoutParam*: NimNode
      ## Cached ident for the timeout parameter

    extraDefs*: NimNode
      ## The reponse procs have extra templates that must become
      ## part of the generated code

  P2PProtocol* = ref object
    # Settings
    name*: string
    version*: int
    timeouts*: int64
    useRequestIds*: bool
    useSingleRecordInlining*: bool
    rlpxName*: string
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
    implementMsg*: proc (msg: Message)
    implementProtocolInit*: proc (protocol: P2PProtocol): NimNode

    afterProtocolInit*: proc (protocol: P2PProtocol)

    # Bound symbols to the back-end run-time types and procs
    PeerType*: NimNode
    NetworkType*: NimNode
    SerializationFormat*: NimNode
    ResponderType*: NimNode
    RequestResultsWrapper*: NimNode
    ReqIdType*: NimNode

    registerProtocol*: NimNode
    setEventHandlers*: NimNode

  BackendFactory* = proc (p: P2PProtocol): Backend

  P2PBackendError* = object of CatchableError
  InvalidMsgError* = object of P2PBackendError

const
  defaultReqTimeout = 10.seconds
  tracingEnabled = defined(p2pdump)

let
  # Variable names affecting the public interface of the library:
  reqIdVar*             {.compileTime.} = ident "reqId"
  # XXX: Binding the int type causes instantiation failure for some reason
  ReqIdType*            {.compileTime.} = ident "int"
  peerVar*              {.compileTime.} = ident "peer"
  responseVar*          {.compileTime.} = ident "response"
  streamVar*            {.compileTime.} = ident "stream"
  deadlineVar*          {.compileTime.} = ident "deadline"
  perProtocolMsgIdVar*  {.compileTime.} = ident "perProtocolMsgId"
  currentProtocolSym*   {.compileTime.} = ident "CurrentProtocol"
  resultIdent*          {.compileTime.} = ident "result"

  # Locally used symbols:
  Option                {.compileTime.} = ident "Option"
  Future                {.compileTime.} = ident "Future"
  Void                  {.compileTime.} = ident "void"
  writeField            {.compileTime.} = ident "writeField"

template Opt(T): auto = newTree(nnkBracketExpr, Option, T)
template Fut(T): auto = newTree(nnkBracketExpr, Future, T)

proc initFuture*[T](loc: var Future[T]) =
  loc = newFuture[T]()

template applyDecorator(p: NimNode, decorator: NimNode) =
  if decorator.kind != nnkNilLit:
    p.pragma.insert(0, decorator)

when tracingEnabled:
  proc logSentMsgFields(peer: NimNode,
                        protocolInfo: NimNode,
                        msgName: string,
                        fields: openarray[NimNode]): NimNode =
    ## This generates the tracing code inserted in the message sending procs
    ## `fields` contains all the params that were serialized in the message
    let
      tracer = ident "tracer"
      tracerStream = ident "tracerStream"
      logMsgEventImpl = ident "logMsgEventImpl"

    result = quote do:
      var `tracerStream` = memoryOutput()
      var `tracer` = JsonWriter.init(`tracerStream`)
      beginRecord(`tracer`)

    for f in fields:
      result.add newCall(writeField, tracer, newLit($f), f)

    result.add quote do:
      endRecord(`tracer`)
      `logMsgEventImpl`("outgoing_msg", `peer`,
                        `protocolInfo`, `msgName`,
                        getOutput(`tracerStream`, string))

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
           timeouts: int64, useRequestIds: bool, rlpxName: string,
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
    rlpxName: rlpxName,
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
  assert(not result.backend.implementProtocolInit.isNil)
  assert(not result.backend.ResponderType.isNil)

  if result.backend.ReqIdType.isNil:
    result.backend.ReqIdType = ident "int"

  result.processProtocolBody body

  if not result.backend.afterProtocolInit.isNil:
    result.backend.afterProtocolInit(result)

proc augmentUserHandler(p: P2PProtocol, userHandlerProc: NimNode, msgId = -1) =
  ## This procs adds a set of common helpers available in all messages handlers
  ## (e.g. `perProtocolMsgId`, `peer.state`, etc).

  userHandlerProc.addPragma ident"gcsafe"
  userHandlerProc.addPragma ident"async"

  var
    getState = ident"getState"
    getNetworkState = ident"getNetworkState"
    protocolInfoVar = p.protocolInfoVar
    protocolNameIdent = p.nameIdent
    PeerType = p.backend.PeerType
    PeerStateType = p.PeerStateType
    NetworkStateType = p.NetworkStateType
    prelude = newStmtList()

  userHandlerProc.body.insert 0, prelude

  # We allow the user handler to use `openarray` params, but we turn
  # those into sequences to make the `async` pragma happy.
  for i in 1 ..< userHandlerProc.params.len:
    var param = userHandlerProc.params[i]
    param[^2] = chooseFieldType(param[^2])

  prelude.add quote do:
    type `currentProtocolSym` = `protocolNameIdent`

  if msgId >= 0:
    prelude.add quote do:
      const `perProtocolMsgIdVar` = `msgId`

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

proc hasReqId*(msg: Message): bool =
  msg.protocol.useRequestIds and msg.kind in {msgRequest, msgResponse}

proc ResponderType(msg: Message): NimNode =
  var resp = if msg.kind == msgRequest: msg.response else: msg
  newTree(nnkBracketExpr,
          msg.protocol.backend.ResponderType, resp.strongRecName)

proc newMsg(protocol: P2PProtocol, kind: MessageKind, id: int,
            procDef: NimNode, timeoutParam: NimNode = nil,
            response: Message = nil): Message =

  if procDef[0].kind == nnkPostfix:
    error("p2pProcotol procs are public by default. " &
          "Please remove the postfix `*`.", procDef)

  var
    msgIdent = procDef.name
    msgName = $msgIdent
    recFields = newTree(nnkRecList)
    recBody = newTree(nnkObjectTy, newEmptyNode(), newEmptyNode(), recFields)
    strongRecName = ident(msgName & "Obj")
    recName = strongRecName

  for param, paramType in procDef.typedParams(skip = 1):
    recFields.add newTree(nnkIdentDefs,
      newTree(nnkPostfix, ident("*"), param), # The fields are public
      chooseFieldType(paramType),             # some types such as openarray
      newEmptyNode())                         # are automatically remapped

  if recFields.len == 1 and protocol.useSingleRecordInlining:
    # When we have a single parameter, it's treated as the transferred message
    # type. `recName` will be resolved to the message type that's intended
    # for serialization while `strongRecName` will be a distinct type over
    # which overloads such as `msgId` can be defined. We must use a distinct
    # type because otherwise Nim may see multiple overloads defined over the
    # same request parameter type and this will be an ambiguity error.
    recName = recFields[0][1]
    recBody = newTree(nnkDistinctTy, recName)

  result = Message(protocol: protocol,
                   id: id,
                   ident: msgIdent,
                   kind: kind,
                   procDef: procDef,
                   recName: recName,
                   strongRecName: strongRecName,
                   recBody: recBody,
                   timeoutParam: timeoutParam,
                   response: response)

  if procDef.body.kind != nnkEmpty:
    var userHandler = copy procDef

    protocol.augmentUserHandler userHandler, id
    userHandler.name = genSym(nskProc, msgName)

    # Request and Response handlers get an extra `reqId` parameter if the
    # protocol uses them:
    if result.hasReqId:
      userHandler.params.insert(2, newIdentDefs(reqIdVar, protocol.backend.ReqIdType))

    # All request handlers get an automatically inserter `response` variable:
    if kind == msgRequest:
      assert response != nil
      let
        peerParam = userHandler.params[1][0]
        ResponderType = result.ResponderType
        initResponderCall = newCall(ident"init", ResponderType, peerParam)

      if protocol.useRequestIds:
        initResponderCall.add reqIdVar

      userHandler.addPreludeDefs newVarStmt(responseVar, initResponderCall)

      result.initResponderCall = initResponderCall

    case kind
    of msgRequest:  userHandler.applyDecorator protocol.incomingRequestDecorator
    of msgResponse: userHandler.applyDecorator protocol.incomingResponseDecorator
    else: discard

    result.userHandler = userHandler
    protocol.outRecvProcs.add result.userHandler

  protocol.messages.add result

proc identWithExportMarker*(msg: Message): NimNode =
  newTree(nnkPostfix, ident("*"), msg.ident)

proc requestResultType*(msg: Message): NimNode =
  let
    protocol = msg.protocol
    backend = protocol.backend
    responseRec = msg.response.recName

  var wrapperType = backend.RequestResultsWrapper
  if wrapperType != nil:
    if eqIdent(wrapperType, "void"):
      return responseRec
    else:
      return newTree(nnkBracketExpr, wrapperType, responseRec)
  else:
    return newTree(nnkBracketExpr, Option, responseRec)

proc createSendProc*(msg: Message,
                     procType = nnkProcDef,
                     isRawSender = false,
                     nameSuffix = ""): SendProc =
  # TODO: file an issue:
  # macros.newProc and macros.params doesn't work with nnkMacroDef

  let
    nameSuffix = if nameSuffix.len == 0: (if isRawSender: "RawSender" else: "")
                 else: nameSuffix

    name = if nameSuffix.len == 0: msg.identWithExportMarker
           else: ident($msg.ident & nameSuffix)

    pragmas = if procType == nnkProcDef: newTree(nnkPragma, ident"gcsafe")
              else: newEmptyNode()

  var def = newNimNode(procType).add(
    name,
    newEmptyNode(),
    newEmptyNode(),
    copy msg.procDef.params,
    pragmas,
    newEmptyNode(),
    newStmtList()) ## body

  if proctype == nnkProcDef:
    for p in msg.procDef.pragma:
      def.addPragma p

  result.msg = msg
  result.def = def

  for param, paramType in def.typedParams():
    if result.peerParam.isNil:
      result.peerParam = param
    else:
      result.msgParams.add param

  case msg.kind
  of msgHandshake, msgRequest:
    # Add a timeout parameter for all request procs
    let timeout = copy msg.timeoutParam
    def[3].add timeout
    result.timeoutParam = timeout[0]

  of msgResponse:
    # A response proc must be called with a response object that originates
    # from a certain request. Here we change the Peer parameter at position
    # 1 to the correct strongly-typed ResponderType. The incoming procs still
    # gets the normal Peer paramter.
    let
      ResponderType = msg.ResponderType
      sendProcName = msg.ident

    def[3][1][1] = ResponderType

    # We create a helper that enables the `response.send()` syntax
    # inside the user handler of the request proc:
    result.extraDefs = quote do:
      template send*(r: `ResponderType`, args: varargs[untyped]): auto =
        `sendProcName`(r, args)

  of msgNotification:
    discard

  def[3][0] = if procType == nnkMacroDef:
                ident "untyped"
              elif msg.kind == msgRequest and not isRawSender:
                Fut(msg.requestResultType)
              elif msg.kind == msgHandshake and not isRawSender:
                Fut(msg.recName)
              else:
                Fut(Void)

proc setBody*(sendProc: SendProc, body: NimNode) =
  var
    msg = sendProc.msg
    protocol = msg.protocol
    def = sendProc.def

  # TODO: macros.body triggers an assertion error when the proc type is nnkMacroDef
  def[6] = body

  if msg.kind == msgRequest:
    def.applyDecorator protocol.outgoingRequestDecorator

  msg.protocol.outSendProcs.add def

  if sendProc.extraDefs != nil:
    msg.protocol.outSendProcs.add sendProc.extraDefs

proc writeParamsAsRecord*(params: openarray[NimNode],
                          outputStream, Format, RecordType: NimNode): NimNode =
  if params.len == 0:
    return newStmtList()

  var
    appendParams = newStmtList()
    recordWriterCtx = ident "recordWriterCtx"
    writer = ident "writer"

  for param in params:
    appendParams.add newCall(writeField,
                             writer, recordWriterCtx,
                             newLit($param), param)

  # TODO: this doesn't respect the `useSingleRecordInlining` option.
  # Right now, it's not a problem because it's used only in the libp2p back-end
  if params.len > 1:
    result = quote do:
      mixin init, writerType, beginRecord, endRecord

      var `writer` = init(WriterType(`Format`), `outputStream`)
      var `recordWriterCtx` = beginRecord(`writer`, `RecordType`)
      `appendParams`
      endRecord(`writer`, `recordWriterCtx`)
  else:
    let param = params[0]

    result = quote do:
      var `writer` = init(WriterType(`Format`), `outputStream`)
      writeValue(`writer`, `param`)

proc useStandardBody*(sendProc: SendProc,
                      preSerializationStep: proc(stream: NimNode): NimNode,
                      postSerializationStep: proc(stream: NimNode): NimNode,
                      sendCallGenerator: proc (peer, bytes: NimNode): NimNode) =
  let
    msg = sendProc.msg
    outputStream = ident "outputStream"
    msgBytes = ident "msgBytes"

    recipient = sendProc.peerParam
    msgRecName = msg.recName
    Format = msg.protocol.backend.SerializationFormat

    preSerialization = if preSerializationStep.isNil: newStmtList()
                       else: preSerializationStep(outputStream)

    serilization = writeParamsAsRecord(sendProc.msgParams,
                                       outputStream, Format, msgRecName)

    postSerialization = if postSerializationStep.isNil: newStmtList()
                        else: postSerializationStep(outputStream)

    appendParams = newStmtList()

    sendCall = sendCallGenerator(recipient, msgBytes)

    tracing = when not tracingEnabled:
                newStmtList()
              else:
                logSentMsgFields(recipient,
                                 msg.protocol.protocolInfoVar,
                                 $msg.ident,
                                 sendProc.msgParams)

  sendProc.setBody quote do:
    mixin init, WriterType, beginRecord, endRecord, getOutput

    var `outputStream` = memoryOutput()
    `preSerialization`
    `serilization`
    `postSerialization`
    `tracing`
    let `msgBytes` = getOutput(`outputStream`)
    `sendCall`

proc correctSerializerProcParams(params: NimNode) =
  # A serializer proc is just like a send proc, but:
  # 1. it has a void return type
  params[0] = ident "void"
  # 2. The peer params is replaced with OutputStream
  params[1] = newIdentDefs(streamVar, bindSym "OutputStream")
  # 3. The timeout param is removed
  params.del(params.len - 1)

proc createSerializer*(msg: Message, procType = nnkProcDef): NimNode =
  var serializer = msg.createSendProc(procType, nameSuffix = "Serializer")
  correctSerializerProcParams serializer.def.params

  serializer.setBody writeParamsAsRecord(
    serializer.msgParams,
    streamVar,
    msg.protocol.backend.SerializationFormat,
    msg.recName)

  return serializer.def

proc defineThunk*(msg: Message, thunk: NimNode) =
  let protocol = msg.protocol

  case msg.kind
  of msgRequest:  thunk.applyDecorator protocol.incomingRequestThunkDecorator
  of msgResponse: thunk.applyDecorator protocol.incomingResponseThunkDecorator
  else: discard

  protocol.outRecvProcs.add thunk

proc genUserHandlerCall*(msg: Message, receivedMsg: NimNode,
                         leadingParams: varargs[NimNode]): NimNode =
  if msg.userHandler == nil:
    return newStmtList()

  result = newCall(msg.userHandler.name, leadingParams)

  var params = toSeq(msg.procDef.typedParams(skip = 1))
  if params.len == 1 and msg.protocol.useSingleRecordInlining:
    result.add receivedMsg
  else:
    for p in params:
      result.add newDotExpr(receivedMsg, p[0])

proc genAwaitUserHandler*(msg: Message, receivedMsg: NimNode,
                          leadingParams: varargs[NimNode]): NimNode =
  result = msg.genUserHandlerCall(receivedMsg, leadingParams)
  if result.len > 0: result = newCall("await", result)

proc appendAllParams*(node: NimNode, procDef: NimNode, skipFirst = 0): NimNode =
  result = node
  for p, _ in procDef.typedParams(skip = skipFirst):
    result.add p

proc paramNames*(procDef: NimNode, skipFirst = 0): seq[NimNode] =
  result = newSeq[NimNode]()
  for name, _ in procDef.typedParams(skip = skipFirst):
    result.add name

proc netInit*(p: P2PProtocol): NimNode =
  if p.NetworkStateType == nil:
    newNilLit()
  else:
    newTree(nnkBracketExpr, bindSym"createNetworkState",
                            p.backend.NetworkType,
                            p.NetworkStateType)

proc createHandshakeTemplate*(msg: Message,
                              rawSendProc, handshakeImpl,
                              nextMsg: NimNode): SendProc =
  let
    handshakeExchanger = msg.createSendProc(procType = nnkTemplateDef)
    forwardCall = newCall(rawSendProc).appendAllParams(handshakeExchanger.def)
    peerValue = forwardCall[1]
    timeoutValue = msg.timeoutParam[0]
    peerVarSym = genSym(nskLet, "peer")
    msgRecName = msg.recName

  forwardCall[1] = peerVarSym
  forwardCall.del(forwardCall.len - 1)

  handshakeExchanger.setBody quote do:
    let `peerVarSym` = `peerValue`
    let sendingFuture = `forwardCall`
    `handshakeImpl`(`peerVarSym`,
                    sendingFuture,
                    `nextMsg`(`peerVarSym`, `msgRecName`),
                    `timeoutValue`)

  return handshakeExchanger

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
        let responseMsg = p.newMsg(msgResponse, nextId + procs.len - 1, procs[^1])

        for i in 0 .. procs.len - 2:
          var timeout = ensureTimeoutParam(procs[i], p.timeouts)
          queries.add p.newMsg(msgRequest, nextId + i, procs[i], timeout,
                               response = responseMsg)

        p.requests.add Request(queries: queries, response: responseMsg)

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
      msgRecName = msg.recName
      msgStrongRecName = msg.strongRecName
      msgRecBody = msg.recBody

    result.add quote do:
      # This is a type featuring a single field for each message param:
      type `msgStrongRecName`* = `msgRecBody`

      # Add a helper template for accessing the message type:
      # e.g. p2p.hello:
      template `msgName`*(T: type `protocolName`): type = `msgRecName`

      # Add a helper template for obtaining the message Id for
      # a particular message type:
      template msgId*(T: type `msgStrongRecName`): int = `msgId`
      template msgProtocol*(T: type `msgStrongRecName`): type = `protocolName`
      template RecType*(T: type `msgStrongRecName`): untyped = `msgRecName`

proc genCode*(p: P2PProtocol): NimNode =
  # TODO: try switching to a simpler for msg in p.messages: loop
  when true:
    for msg in p.messages:
      p.backend.implementMsg msg
  else:
    if p.handshake != nil:
      p.backend.implementMsg p.handshake

    for msg in p.notifications:
      p.backend.implementMsg msg

    for req in p.requests:
      p.backend.implementMsg req.response
      for query in req.queries: p.backend.implementMsg(query)

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
    rlpxName: static[string] = "",
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
    useRequestIds, rlpxName,
    outgoingRequestDecorator,
    incomingRequestDecorator,
    incomingRequestThunkDecorator,
    incomingResponseDecorator,
    incomingResponseThunkDecorator,
    peerState.getType, networkState.getType)

  result = p.genCode()

  when defined(debugP2pProtocol) or defined(debugMacros):
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

