# nim-eth
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, algorithm, random, typetraits, strutils],
  chronos, chronos/timer, chronicles,
  ./keys, ./p2p/private/p2p_types,
  ./p2p/[kademlia, discovery, enode, peer_pool, rlpx]

export
  p2p_types, rlpx, enode, kademlia

proc addCapability*(node: var EthereumNode,
                    p: ProtocolInfo,
                    networkState: RootRef = nil) =
  doAssert node.connectionState == ConnectionState.None

  let pos = lowerBound(node.protocols, p, rlpx.cmp)
  node.protocols.insert(p, pos)
  node.capabilities.insert(p.asCapability, pos)

  if p.networkStateInitializer != nil and networkState.isNil:
    node.protocolStates[p.index] = p.networkStateInitializer(node)

  if networkState.isNil.not:
    node.protocolStates[p.index] = networkState

template addCapability*(node: var EthereumNode, Protocol: type) =
  addCapability(node, Protocol.protocolInfo)

template addCapability*(node: var EthereumNode,
                        Protocol: type,
                        networkState: untyped) =
  mixin NetworkState
  type
    ParamType = type(networkState)

  when ParamType isnot Protocol.NetworkState:
    const errMsg = "`$1` is not compatible with `$2`" % [
      name(ParamType), name(Protocol.NetworkState)]
    {. error: errMsg .}

  addCapability(node, Protocol.protocolInfo,
    cast[RootRef](networkState))

proc replaceNetworkState*(node: var EthereumNode,
                          p: ProtocolInfo,
                          networkState: RootRef) =
  node.protocolStates[p.index] = networkState

template replaceNetworkState*(node: var EthereumNode,
                              Protocol: type,
                              networkState: untyped) =
  mixin NetworkState
  type
    ParamType = type(networkState)

  when ParamType isnot Protocol.NetworkState:
    const errMsg = "`$1` is not compatible with `$2`" % [
      name(ParamType), name(Protocol.NetworkState)]
    {. error: errMsg .}

  replaceNetworkState(node, Protocol.protocolInfo,
    cast[RootRef](networkState))

proc newEthereumNode*(
    keys: KeyPair,
    address: Address,
    networkId: NetworkId,
    clientId = "nim-eth-p2p",
    addAllCapabilities = true,
    useCompression: bool = false,
    minPeers = 10,
    bootstrapNodes: seq[ENode] = @[],
    bindUdpPort: Port,
    bindTcpPort: Port,
    bindIp = IPv4_any(),
    rng = newRng()): EthereumNode =

  if rng == nil: # newRng could fail
    raise (ref Defect)(msg: "Cannot initialize RNG")

  new result
  result.keys = keys
  result.networkId = networkId
  result.clientId = clientId
  result.protocols.newSeq 0
  result.capabilities.newSeq 0
  result.address = address
  result.connectionState = ConnectionState.None
  result.bindIp = bindIp
  result.bindPort = bindTcpPort

  result.discovery = newDiscoveryProtocol(
    keys.seckey, address, bootstrapNodes, bindUdpPort, bindIp, rng)

  result.rng = rng

  when useSnappy:
    result.protocolVersion = if useCompression: devp2pSnappyVersion
                             else: devp2pVersion

  result.protocolStates.newSeq allProtocols.len

  result.peerPool = newPeerPool(
    result, networkId, keys, nil, clientId, minPeers = minPeers)

  result.peerPool.discovery = result.discovery

  if addAllCapabilities:
    for p in allProtocols:
      result.addCapability(p)

proc processIncoming(server: StreamServer,
                     remote: StreamTransport): Future[void] {.async, gcsafe.} =
  var node = getUserData[EthereumNode](server)
  let peer = await node.rlpxAccept(remote)
  if not peer.isNil:
    trace "Connection established (incoming)", peer
    if node.peerPool != nil:
      node.peerPool.connectingNodes.excl(peer.remote)
      node.peerPool.addPeer(peer)

proc listeningAddress*(node: EthereumNode): ENode =
  node.toENode()

proc startListening*(node: EthereumNode) {.raises: [CatchableError, Defect].} =
  # TODO: allow binding to both IPv4 & IPv6
  let ta = initTAddress(node.bindIp, node.bindPort)
  if node.listeningServer == nil:
    node.listeningServer = createStreamServer(ta, processIncoming,
                                              {ReuseAddr},
                                              udata = cast[pointer](node))
  node.listeningServer.start()
  info "RLPx listener up", self = node.listeningAddress

proc connectToNetwork*(
    node: EthereumNode, startListening = true,
    enableDiscovery = true, waitForPeers = true) {.async.} =
  doAssert node.connectionState == ConnectionState.None

  node.connectionState = Connecting

  if startListening:
    p2p.startListening(node)

  if enableDiscovery:
    node.discovery.open()
    await node.discovery.bootstrap()
    node.peerPool.start()
  else:
    info "Discovery disabled"

  while node.peerPool.connectedNodes.len == 0 and waitForPeers:
    trace "Waiting for more peers", peers = node.peerPool.connectedNodes.len
    await sleepAsync(500.milliseconds)

proc stopListening*(node: EthereumNode) {.raises: [CatchableError, Defect].} =
  node.listeningServer.stop()

iterator peers*(node: EthereumNode): Peer =
  for peer in node.peerPool.peers:
    yield peer

iterator peers*(node: EthereumNode, Protocol: type): Peer =
  for peer in node.peerPool.peers(Protocol):
    yield peer

iterator protocolPeers*(node: EthereumNode, Protocol: type): auto =
  mixin state
  for peer in node.peerPool.peers(Protocol):
    yield peer.state(Protocol)

iterator randomPeers*(node: EthereumNode, maxPeers: int): Peer =
  # TODO: this can be implemented more efficiently

  # XXX: this doesn't compile, why?
  # var peer = toSeq node.peers
  var peers = newSeqOfCap[Peer](node.peerPool.connectedNodes.len)
  for peer in node.peers: peers.add(peer)

  shuffle(peers)
  for i in 0 ..< min(maxPeers, peers.len):
    yield peers[i]

proc randomPeer*(node: EthereumNode): Peer =
  let peerIdx = rand(node.peerPool.connectedNodes.len)
  var i = 0
  for peer in node.peers:
    if i == peerIdx: return peer
    inc i

iterator randomPeers*(node: EthereumNode, maxPeers: int, Protocol: type): Peer =
  var peers = newSeqOfCap[Peer](node.peerPool.connectedNodes.len)
  for peer in node.peers(Protocol):
    peers.add(peer)
  shuffle(peers)
  if peers.len > maxPeers: peers.setLen(maxPeers)
  for p in peers: yield p

proc randomPeerWith*(node: EthereumNode, Protocol: type): Peer =
  var candidates = newSeq[Peer]()
  for p in node.peers(Protocol):
    candidates.add(p)
  if candidates.len > 0:
    return candidates.rand()

proc getPeer*(node: EthereumNode, peerId: NodeId, Protocol: type): Option[Peer] =
  for peer in node.peers(Protocol):
    if peer.remote.id == peerId:
      return some(peer)

proc connectToNode*(node: EthereumNode, n: Node) {.async.} =
  await node.peerPool.connectToNode(n)

proc connectToNode*(node: EthereumNode, n: ENode) {.async.} =
  await node.peerPool.connectToNode(n)

func numPeers*(node: EthereumNode): int =
  node.peerPool.numPeers

func hasPeer*(node: EthereumNode, n: ENode): bool =
  n in node.peerPool

func hasPeer*(node: EthereumNode, n: Node): bool =
  n in node.peerPool

func hasPeer*(node: EthereumNode, n: Peer): bool =
  n in node.peerPool
