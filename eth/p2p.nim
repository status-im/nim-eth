#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import
  tables, algorithm, random,
  chronos, chronos/timer, chronicles,
  eth/keys, eth/common/eth_types,
  eth/p2p/[kademlia, discovery, enode, peer_pool, rlpx],
  eth/p2p/private/p2p_types

export
  p2p_types, rlpx, enode, kademlia

proc addCapability*(node: var EthereumNode, p: ProtocolInfo) =
  assert node.connectionState == ConnectionState.None

  let pos = lowerBound(node.protocols, p, rlpx.cmp)
  node.protocols.insert(p, pos)
  node.capabilities.insert(p.asCapability, pos)

  if p.networkStateInitializer != nil:
    node.protocolStates[p.index] = p.networkStateInitializer(node)

template addCapability*(node: var EthereumNode, Protocol: type) =
  addCapability(node, Protocol.protocolInfo)

proc newEthereumNode*(keys: KeyPair,
                      address: Address,
                      networkId: uint,
                      chain: AbstractChainDB,
                      clientId = "nim-eth-p2p/0.2.0", # TODO: read this value from nimble somehow
                      addAllCapabilities = true,
                      useCompression: bool = false,
                      minPeers = 10): EthereumNode =
  new result
  result.keys = keys
  result.networkId = networkId
  result.clientId = clientId
  result.protocols.newSeq 0
  result.capabilities.newSeq 0
  result.address = address
  result.connectionState = ConnectionState.None

  when useSnappy:
    result.protocolVersion = if useCompression: devp2pSnappyVersion
                             else: devp2pVersion

  result.protocolStates.newSeq allProtocols.len

  result.peerPool = newPeerPool(result, networkId,
                                keys, nil,
                                clientId, address.tcpPort,
                                minPeers = minPeers)

  if addAllCapabilities:
    for p in allProtocols:
      result.addCapability(p)

proc processIncoming(server: StreamServer,
                     remote: StreamTransport): Future[void] {.async, gcsafe.} =
  var node = getUserData[EthereumNode](server)
  let peerfut = node.rlpxAccept(remote)
  yield peerfut
  if not peerfut.failed:
    let peer = peerfut.read()
    if node.peerPool != nil:
      if not node.peerPool.addPeer(peer):
        # In case an outgoing connection was added in the meanwhile or a
        # malicious peer opens multiple connections
        debug "Disconnecting peer (incoming)", reason = AlreadyConnected
        await peer.disconnect(AlreadyConnected)
  else:
    remote.close()

proc listeningAddress*(node: EthereumNode): ENode =
  return initENode(node.keys.pubKey, node.address)

proc startListening*(node: EthereumNode) =
  let ta = initTAddress(node.address.ip, node.address.tcpPort)
  if node.listeningServer == nil:
    node.listeningServer = createStreamServer(ta, processIncoming,
                                              {ReuseAddr},
                                              udata = cast[pointer](node))
  node.listeningServer.start()
  info "RLPx listener up", self = node.listeningAddress

proc connectToNetwork*(node: EthereumNode,
                       bootstrapNodes: seq[ENode],
                       startListening = true,
                       enableDiscovery = true) {.async.} =
  assert node.connectionState == ConnectionState.None

  node.connectionState = Connecting
  node.discovery = newDiscoveryProtocol(node.keys.seckey,
                                        node.address,
                                        bootstrapNodes)
  node.peerPool.discovery = node.discovery

  if startListening:
    p2p.startListening(node)

  if enableDiscovery:
    node.discovery.open()
    await node.discovery.bootstrap()
  else:
    info "Discovery disabled"

  node.peerPool.start()

  while node.peerPool.connectedNodes.len == 0:
    trace "Waiting for more peers", peers = node.peerPool.connectedNodes.len
    await sleepAsync(500)

proc stopListening*(node: EthereumNode) =
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
  let peerIdx = random(node.peerPool.connectedNodes.len)
  var i = 0
  for peer in node.peers:
    if i == peerIdx: return peer
    inc i

proc randomPeerWith*(node: EthereumNode, Protocol: type): Peer =
  mixin state
  var candidates = newSeq[Peer]()
  for p in node.peers(Protocol):
    candidates.add(p)
  if candidates.len > 0:
    return candidates.rand()

