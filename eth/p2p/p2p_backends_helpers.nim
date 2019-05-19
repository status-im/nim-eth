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

proc initFuture[T](loc: var Future[T]) =
  loc = newFuture[T]()

