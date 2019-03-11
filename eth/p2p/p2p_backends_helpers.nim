proc getState(peer: Peer, proto: ProtocolInfo): RootRef =
  peer.protocolStates[proto.index]

template state*(peer: Peer, Protocol: type): untyped =
  ## Returns the state object of a particular protocol for a
  ## particular connection.
  mixin State
  bind getState
  cast[Protocol.State](getState(peer, Protocol.protocolInfo))

proc getNetworkState(node: EthereumNode, proto: ProtocolInfo): RootRef =
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

proc createPeerState[ProtocolState](peer: Peer): RootRef =
  var res = new ProtocolState
  mixin initProtocolState
  initProtocolState(res, peer)
  return cast[RootRef](res)

proc createNetworkState[NetworkState](network: EthereumNode): RootRef {.gcsafe.} =
  var res = new NetworkState
  mixin initProtocolState
  initProtocolState(res, network)
  return cast[RootRef](res)

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

proc popTimeoutParam(n: NimNode): NimNode =
  var lastParam = n.params[^1]
  if eqIdent(lastParam[0], "timeout"):
    if lastParam[2].kind == nnkEmpty:
      macros.error "You must specify a default value for the `timeout` parameter", lastParam
    result = lastParam
    n.params.del(n.params.len - 1)

proc verifyStateType(t: NimNode): NimNode =
  result = t[1]
  if result.kind == nnkSym and $result == "nil":
    return nil
  if result.kind != nnkBracketExpr or $result[0] != "ref":
    macros.error($result & " must be a ref type")

proc newFuture[T](location: var Future[T]) =
  location = newFuture[T]()

