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

proc initProtocolState*[T](state: T, x: Peer|EthereumNode)
    {.gcsafe, raises: [Defect].} =
  discard

proc initProtocolStates(peer: Peer, protocols: openarray[ProtocolInfo])
    {.raises: [Defect].} =
  # Initialize all the active protocol states
  newSeq(peer.protocolStates, allProtocols.len)
  for protocol in protocols:
    let peerStateInit = protocol.peerStateInitializer
    if peerStateInit != nil:
      peer.protocolStates[protocol.index] = peerStateInit(peer)

