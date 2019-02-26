# PeerPool attempts to keep connections to at least min_peers
# on the given network.

import
  os, tables, times, random, sequtils, options,
  chronos, chronicles, eth/[rlp, keys],
  private/p2p_types, discovery, kademlia, rlpx

const
  lookupInterval = 5
  connectLoopSleepMs = 2000

proc newPeerPool*(network: EthereumNode,
                  networkId: uint, keyPair: KeyPair,
                  discovery: DiscoveryProtocol, clientId: string,
                  listenPort = Port(30303), minPeers = 10): PeerPool =
  new result
  result.network = network
  result.keyPair = keyPair
  result.minPeers = minPeers
  result.networkId = networkId
  result.discovery = discovery
  result.connectedNodes = initTable[Node, Peer]()
  result.connectingNodes = initSet[Node]()
  result.observers = initTable[int, PeerObserver]()
  result.listenPort = listenPort

template ensureFuture(f: untyped) = asyncCheck f

proc nodesToConnect(p: PeerPool): seq[Node] {.inline.} =
  p.discovery.randomNodes(p.minPeers).filterIt(it notin p.discovery.bootstrapNodes)

proc addObserver(p: PeerPool, observerId: int, observer: PeerObserver) =
  assert(observerId notin p.observers)
  p.observers[observerId] = observer
  if not observer.onPeerConnected.isNil:
    for peer in p.connectedNodes.values:
      observer.onPeerConnected(peer)

proc delObserver(p: PeerPool, observerId: int) =
  p.observers.del(observerId)

proc addObserver*(p: PeerPool, observerId: ref, observer: PeerObserver) {.inline.} =
  p.addObserver(cast[int](observerId), observer)

proc delObserver*(p: PeerPool, observerId: ref) {.inline.} =
  p.delObserver(cast[int](observerId))

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
  # This method runs in the background, so we must catch OperationCancelled
  # ere otherwise asyncio will warn that its exception was never retrieved.
  try:
    discard await p.discovery.lookupRandom()
  except: # OperationCancelled
    discard
  p.lastLookupTime = epochTime()

proc getRandomBootnode(p: PeerPool): Option[Node] =
  if p.discovery.bootstrapNodes.len != 0:
    result = option(p.discovery.bootstrapNodes.rand())

proc addPeer*(pool: PeerPool, peer: Peer): bool =
  if peer.remote notin pool.connectedNodes:
    pool.connectedNodes[peer.remote] = peer
    for o in pool.observers.values:
      if not o.onPeerConnected.isNil:
        o.onPeerConnected(peer)
    return true
  else: return false

proc connectToNode*(p: PeerPool, n: Node) {.async.} =
  let peer = await p.connect(n)
  if not peer.isNil:
    trace "Connection established", peer
    if not p.addPeer(peer):
      # In case an incoming connection was added in the meanwhile
      trace "Disconnecting peer (outgoing)", reason = AlreadyConnected
      await peer.disconnect(AlreadyConnected)

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
    ensureFuture p.lookupRandomNode()

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
    var dropConnections = false
    try:
      await p.maybeConnectToMorePeers()
    except Exception as e:
      # Most unexpected errors should be transient, so we log and restart from
      # scratch.
      error "Unexpected PeerPool error, restarting",
            err = getCurrentExceptionMsg(),
            stackTrace = e.getStackTrace()
      dropConnections = true

    if dropConnections:
      await p.stopAllPeers()

    await sleepAsync(connectLoopSleepMs)

proc start*(p: PeerPool) =
  if not p.running:
    asyncCheck p.run()

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

