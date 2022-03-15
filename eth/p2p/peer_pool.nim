# nim-eth
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# PeerPool attempts to keep connections to at least min_peers
# on the given network.

{.push raises: [Defect].}

import
  std/[os, tables, times, random, sequtils, options],
  chronos, chronicles,
  ".."/[rlp, keys, common],
  ./private/p2p_types, "."/[discovery, kademlia, rlpx]

const
  lookupInterval = 5
  connectLoopSleep = chronos.milliseconds(2000)

proc newPeerPool*(
    network: EthereumNode, networkId: NetworkId, keyPair: KeyPair,
    discovery: DiscoveryProtocol, clientId: string, minPeers = 10): PeerPool =
  new result
  result.network = network
  result.keyPair = keyPair
  result.minPeers = minPeers
  result.networkId = networkId
  result.discovery = discovery
  result.connectedNodes = initTable[Node, Peer]()
  result.connectingNodes = initHashSet[Node]()
  result.observers = initTable[int, PeerObserver]()

proc nodesToConnect(p: PeerPool): seq[Node] =
  p.discovery.randomNodes(p.minPeers).filterIt(it notin p.discovery.bootstrapNodes)

proc addObserver(p: PeerPool, observerId: int, observer: PeerObserver) =
  doAssert(observerId notin p.observers)
  p.observers[observerId] = observer
  if not observer.onPeerConnected.isNil:
    for peer in p.connectedNodes.values:
      if observer.protocol.isNil or peer.supports(observer.protocol):
        observer.onPeerConnected(peer)

proc delObserver(p: PeerPool, observerId: int) =
  p.observers.del(observerId)

proc addObserver*(p: PeerPool, observerId: ref, observer: PeerObserver) =
  p.addObserver(cast[int](observerId), observer)

proc delObserver*(p: PeerPool, observerId: ref) =
  p.delObserver(cast[int](observerId))

template setProtocol*(observer: PeerObserver, Protocol: type) =
  observer.protocol = Protocol.protocolInfo

proc stopAllPeers(p: PeerPool) {.async.} =
  debug "Stopping all peers ..."
  # TODO: ...
  # await asyncio.gather(
  #   *[peer.stop() for peer in self.connected_nodes.values()])

# async def stop(self) -> None:
#   self.cancel_token.trigger()
#   await self.stop_all_peers()

proc connect(p: PeerPool, remote: Node): Future[Peer] {.async.} =
  ## Connect to the given remote and return a Peer instance when successful.
  ## Returns nil if the remote is unreachable, times out or is useless.
  if remote in p.connectedNodes:
    trace "skipping_connection_to_already_connected_peer", remote
    return nil

  if remote in p.connectingNodes:
    # debug "skipping connection"
    return nil

  trace "Connecting to node", remote
  p.connectingNodes.incl(remote)
  result = await p.network.rlpxConnect(remote)
  p.connectingNodes.excl(remote)

  # expected_exceptions = (
  #   UnreachablePeer, TimeoutError, PeerConnectionLost, HandshakeFailure)
  # try:
  #   self.logger.debug("Connecting to %s...", remote)
  #   peer = await wait_with_token(
  #     handshake(remote, self.privkey, self.peer_class, self.network_id),
  #     token=self.cancel_token,
  #     timeout=HANDSHAKE_TIMEOUT)
  #   return peer
  # except OperationCancelled:
  #   # Pass it on to instruct our main loop to stop.
  #   raise
  # except expected_exceptions as e:
  #   self.logger.debug("Could not complete handshake with %s: %s", remote, repr(e))
  # except Exception:
  #   self.logger.exception("Unexpected error during auth/p2p handshake with %s", remote)
  # return None

proc lookupRandomNode(p: PeerPool) {.async.} =
  discard await p.discovery.lookupRandom()
  p.lastLookupTime = epochTime()

proc getRandomBootnode(p: PeerPool): Option[Node] =
  if p.discovery.bootstrapNodes.len != 0:
    result = option(p.discovery.bootstrapNodes.sample())

proc addPeer*(pool: PeerPool, peer: Peer) {.gcsafe.} =
  doAssert(peer.remote notin pool.connectedNodes)
  pool.connectedNodes[peer.remote] = peer
  connected_peers.inc()
  for o in pool.observers.values:
    if not o.onPeerConnected.isNil:
      if o.protocol.isNil or peer.supports(o.protocol):
        o.onPeerConnected(peer)

proc connectToNode*(p: PeerPool, n: Node) {.async.} =
  let peer = await p.connect(n)
  if not peer.isNil:
    trace "Connection established (outgoing)", peer
    p.addPeer(peer)

proc connectToNodes(p: PeerPool, nodes: seq[Node]) {.async.} =
  for node in nodes:
    discard p.connectToNode(node)

    # # TODO: Consider changing connect() to raise an exception instead of
    # # returning None, as discussed in
    # # https://github.com/ethereum/py-evm/pull/139#discussion_r152067425
    # echo "Connecting to node: ", node
    # let peer = await p.connect(node)
    # if not peer.isNil:
    #   info "Successfully connected to ", peer
    #   ensureFuture peer.run(p)

    #   p.connectedNodes[peer.remote] = peer
    #   # for subscriber in self._subscribers:
    #   #   subscriber.register_peer(peer)
    #   if p.connectedNodes.len >= p.minPeers:
    #     return

proc maybeConnectToMorePeers(p: PeerPool) {.async.} =
  ## Connect to more peers if we're not yet connected to at least self.minPeers.
  if p.connectedNodes.len >= p.minPeers:
    # debug "pool already connected to enough peers (sleeping)", count = p.connectedNodes
    return

  if p.lastLookupTime + lookupInterval < epochTime():
    asyncSpawn p.lookupRandomNode()

  let debugEnode = getEnv("ETH_DEBUG_ENODE")
  if debugEnode.len != 0:
    await p.connectToNode(newNode(debugEnode))
  else:
    await p.connectToNodes(p.nodesToConnect())

  # In some cases (e.g ROPSTEN or private testnets), the discovery table might
  # be full of bad peers, so if we can't connect to any peers we try a random
  # bootstrap node as well.
  if p.connectedNodes.len == 0 and (let n = p.getRandomBootnode(); n.isSome):
    await p.connectToNode(n.get())

proc run(p: PeerPool) {.async.} =
  trace "Running PeerPool..."
  p.running = true
  while p.running:

    debug "Amount of peers", amount = p.connectedNodes.len()
    var dropConnections = false
    try:
      await p.maybeConnectToMorePeers()
    except CatchableError as e:
      # Most unexpected errors should be transient, so we log and restart from
      # scratch.
      error "Unexpected PeerPool error, restarting",
        err = e.msg, stackTrace = e.getStackTrace()
      dropConnections = true

    if dropConnections:
      await p.stopAllPeers()

    await sleepAsync(connectLoopSleep)

proc start*(p: PeerPool) =
  if not p.running:
    asyncSpawn p.run()

proc len*(p: PeerPool): int = p.connectedNodes.len
# @property
# def peers(self) -> List[BasePeer]:
#   peers = list(self.connected_nodes.values())
#   # Shuffle the list of peers so that dumb callsites are less likely to send
#   # all requests to
#   # a single peer even if they always pick the first one from the list.
#   random.shuffle(peers)
#   return peers

# async def get_random_peer(self) -> BasePeer:
#   while not self.peers:
#     self.logger.debug("No connected peers, sleeping a bit")
#     await asyncio.sleep(0.5)
#   return random.choice(self.peers)

iterator peers*(p: PeerPool): Peer =
  for remote, peer in p.connectedNodes:
    yield peer

iterator peers*(p: PeerPool, Protocol: type): Peer =
  for peer in p.peers:
    if peer.supports(Protocol):
      yield peer

