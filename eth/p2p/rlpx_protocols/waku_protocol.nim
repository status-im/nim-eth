#
#                 Waku
#              (c) Copyright 2018-2019
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

## Waku
## *******
##
## Waku is a fork of Whisper.
##
## Waku is a gossip protocol that synchronizes a set of messages across nodes
## with attention given to sender and recipient anonymitiy. Messages are
## categorized by a topic and stay alive in the network based on a time-to-live
## measured in seconds. Spam prevention is based on proof-of-work, where large
## or long-lived messages must spend more work.
##
## Implementation should be according to Waku specification defined here:
## https://github.com/vacp2p/specs/blob/master/waku/waku.md
##
## Example usage
## ----------
## First an `EthereumNode` needs to be created, either with all capabilities set
## or with specifically the Waku capability set.
## The latter can be done like this:
##
##   .. code-block::nim
##      var node = newEthereumNode(keypair, address, netId, nil,
##                                 addAllCapabilities = false)
##      node.addCapability Waku
##
## Now calls such as ``postMessage`` and ``subscribeFilter`` can be done.
## However, they only make real sense after ``connectToNetwork`` was started. As
## else there will be no peers to send and receive messages from.

import
  options, tables, times, chronos, chronicles, metrics,
  eth/[keys, async_utils, p2p], whisper/whisper_types, eth/trie/trie_defs

export
  whisper_types

logScope:
  topics = "waku"

declarePublicCounter dropped_low_pow_envelopes,
  "Dropped envelopes because of too low PoW"
declarePublicCounter dropped_too_large_envelopes,
  "Dropped envelopes because larger than maximum allowed size"
declarePublicCounter dropped_bloom_filter_mismatch_envelopes,
  "Dropped envelopes because not matching with bloom filter"
declarePublicCounter dropped_topic_mismatch_envelopes,
  "Dropped envelopes because of not matching topics"
declarePublicCounter dropped_duplicate_envelopes,
  "Dropped duplicate envelopes"

const
  defaultQueueCapacity = 2048
  wakuVersion* = 0 ## Waku version.
  wakuVersionStr* = $wakuVersion ## Waku version.
  defaultMinPow* = 0.2'f64 ## The default minimum PoW requirement for this node.
  defaultMaxMsgSize* = 1024'u32 * 1024'u32 ## The current default and max
  ## message size. This can never be larger than the maximum RLPx message size.
  messageInterval* = chronos.milliseconds(300) ## Interval at which messages are
  ## send to peers, in ms.
  pruneInterval* = chronos.milliseconds(1000)  ## Interval at which message
  ## queue is pruned, in ms.
  topicInterestMax = 1000

type
  WakuMode* = enum
    # TODO: is there a reason to allow such "none" mode? This was originally
    # put here when it was still supposed to be compatible with Whisper.
    None, # No Waku mode
    WakuChan, # Waku client
    WakuSan # Waku node
    # TODO: Light mode could also become part of this enum
    # TODO: With discv5, this could be capabilities also announced at level of
    # discovery.

  WakuConfig* = object
    powRequirement*: float64
    bloom*: Bloom
    isLightNode*: bool
    maxMsgSize*: uint32
    confirmationsEnabled*: bool
    rateLimits*: RateLimits
    wakuMode*: WakuMode
    topics*: seq[Topic]

  WakuPeer = ref object
    initialized: bool # when successfully completed the handshake
    powRequirement*: float64
    bloom*: Bloom
    isLightNode*: bool
    trusted*: bool
    wakuMode*: WakuMode
    topics*: seq[Topic]
    received: HashSet[Hash]

  P2PRequestHandler* = proc(peer: Peer, envelope: Envelope) {.gcsafe.}

  WakuNetwork = ref object
    queue*: ref Queue
    filters*: Filters
    config*: WakuConfig
    p2pRequestHandler*: P2PRequestHandler

  RateLimits* = object
    # TODO: uint or specifically uint32?
    limitIp*: uint
    limitPeerId*: uint
    limitTopic*: uint


proc allowed*(msg: Message, config: WakuConfig): bool =
  # Check max msg size, already happens in RLPx but there is a specific waku
  # max msg size which should always be < RLPx max msg size
  if msg.size > config.maxMsgSize:
    dropped_too_large_envelopes.inc()
    warn "Message size too large", size = msg.size
    return false

  if msg.pow < config.powRequirement:
    dropped_low_pow_envelopes.inc()
    warn "Message PoW too low", pow = msg.pow, minPow = config.powRequirement
    return false

  if not bloomFilterMatch(config.bloom, msg.bloom):
    dropped_bloom_filter_mismatch_envelopes.inc()
    warn "Message does not match node bloom filter"
    return false

  if config.wakuMode == WakuChan:
    if msg.env.topic notin config.topics:
      dropped_topic_mismatch_envelopes.inc()
      warn "Message topic does not match Waku topic list"
      return false

  return true

proc run(peer: Peer) {.gcsafe, async.}
proc run(node: EthereumNode, network: WakuNetwork) {.gcsafe, async.}

proc initProtocolState*(network: WakuNetwork, node: EthereumNode) {.gcsafe.} =
  new(network.queue)
  network.queue[] = initQueue(defaultQueueCapacity)
  network.filters = initTable[string, Filter]()
  network.config.bloom = fullBloom()
  network.config.powRequirement = defaultMinPow
  network.config.isLightNode = false
  # confirmationsEnabled and rateLimits is not yet used but we add it here and
  # in the status message to be compatible with the Status go implementation.
  network.config.confirmationsEnabled = false
  # TODO: Limits of 0 are ignored I hope, this is not clearly written in spec.
  network.config.rateLimits =
    RateLimits(limitIp: 0, limitPeerId: 0, limitTopic:0)
  network.config.maxMsgSize = defaultMaxMsgSize
  network.config.wakuMode = None # default no waku mode
  network.config.topics = @[]
  asyncCheck node.run(network)

p2pProtocol Waku(version = wakuVersion,
                 rlpxName = "waku",
                 peerState = WakuPeer,
                 networkState = WakuNetwork):

  onPeerConnected do (peer: Peer):
    trace "onPeerConnected Waku"
    let
      wakuNet = peer.networkState
      wakuPeer = peer.state

    let m = await peer.status(wakuVersion,
                              cast[uint64](wakuNet.config.powRequirement),
                              @(wakuNet.config.bloom),
                              wakuNet.config.isLightNode,
                              wakuNet.config.confirmationsEnabled,
                              wakuNet.config.rateLimits,
                              wakuNet.config.wakuMode,
                              wakuNet.config.topics,
                              timeout = chronos.milliseconds(500))

    if m.protocolVersion == wakuVersion:
      debug "Waku peer", peer, wakuVersion
    else:
      raise newException(UselessPeerError, "Incompatible Waku version")

    wakuPeer.powRequirement = cast[float64](m.powConverted)

    if m.bloom.len > 0:
      if m.bloom.len != bloomSize:
        raise newException(UselessPeerError, "Bloomfilter size mismatch")
      else:
        wakuPeer.bloom.bytesCopy(m.bloom)
    else:
      # If no bloom filter is send we allow all
      wakuPeer.bloom = fullBloom()

    wakuPeer.isLightNode = m.isLightNode
    if wakuPeer.isLightNode and wakuNet.config.isLightNode:
      # No sense in connecting two light nodes so we disconnect
      raise newException(UselessPeerError, "Two light nodes connected")

    # When Waku-san connect to all. When None, connect to all, Waku-chan has
    # to decide to disconnect. When Waku-chan, connect only to Waku-san.
    wakuPeer.wakuMode = m.wakuMode
    if wakuNet.config.wakuMode == WakuChan:
      if wakuPeer.wakuMode == WakuChan:
        raise newException(UselessPeerError, "Two Waku-chan connected")
      elif wakuPeer.wakuMode == None:
        raise newException(UselessPeerError, "Not in Waku mode")
    if wakuNet.config.wakuMode == WakuSan and
        wakuPeer.wakuMode == WakuChan:
      # TODO: need some maximum check on amount of topics
      wakuPeer.topics = m.topics

    wakuPeer.received.init()
    wakuPeer.trusted = false
    wakuPeer.initialized = true

    # No timer based queue processing for a light node.
    if not wakuNet.config.isLightNode:
      traceAsyncErrors peer.run()

    debug "Waku peer initialized", peer

  handshake:
    proc status(peer: Peer,
                protocolVersion: uint,
                powConverted: uint64,
                bloom: Bytes,
                isLightNode: bool,
                confirmationsEnabled: bool,
                rateLimits: RateLimits,
                wakuMode: WakuMode,
                topics: seq[Topic])

  proc messages(peer: Peer, envelopes: openarray[Envelope]) =
    if not peer.state.initialized:
      warn "Handshake not completed yet, discarding messages"
      return

    for envelope in envelopes:
      # check if expired or in future, or ttl not 0
      if not envelope.valid():
        warn "Expired or future timed envelope", peer
        # disconnect from peers sending bad envelopes
        # await peer.disconnect(SubprotocolReason)
        continue

      let msg = initMessage(envelope)
      if not msg.allowed(peer.networkState.config):
        # disconnect from peers sending bad envelopes
        # await peer.disconnect(SubprotocolReason)
        continue

      # This peer send this message thus should not receive it again.
      # If this peer has the message in the `received` set already, this means
      # it was either already received here from this peer or send to this peer.
      # Either way it will be in our queue already (and the peer should know
      # this) and this peer is sending duplicates.
      # Note: geth does not check if a peer has send a message to them before
      # broadcasting this message. This too is seen here as a duplicate message
      # (see above comment). If we want to seperate these cases (e.g. when peer
      # rating), then we have to add a "peer.state.send" HashSet.
      # Note: it could also be a race between the arrival of a message send by
      # this node to a peer and that same message arriving from that peer (after
      # it was received from another peer) here.
      if peer.state.received.containsOrIncl(msg.hash):
        dropped_duplicate_envelopes.inc()
        trace "Peer sending duplicate messages", peer, hash = $msg.hash
        # await peer.disconnect(SubprotocolReason)
        continue

      # This can still be a duplicate message, but from another peer than
      # the peer who send the message.
      if peer.networkState.queue[].add(msg):
        # notify filters of this message
        peer.networkState.filters.notify(msg)

  proc powRequirement(peer: Peer, value: uint64) =
    if not peer.state.initialized:
      warn "Handshake not completed yet, discarding powRequirement"
      return

    peer.state.powRequirement = cast[float64](value)

  proc bloomFilterExchange(peer: Peer, bloom: Bytes) =
    if not peer.state.initialized:
      warn "Handshake not completed yet, discarding bloomFilterExchange"
      return

    if bloom.len == bloomSize:
      peer.state.bloom.bytesCopy(bloom)

  nextID 20

  proc rateLimits(peer: Peer, rateLimits: RateLimits) = discard

  proc topicInterest(peer: Peer, topics: openarray[Topic]) =
    if not peer.state.initialized:
      warn "Handshake not completed yet, discarding topicInterest"
      return

    if topics.len > topicInterestMax:
      error "Too many topics in the topic-interest list"
      return

    if peer.state.wakuMode == WakuChan:
      peer.state.topics = topics

  nextID 126

  proc p2pRequest(peer: Peer, envelope: Envelope) =
    if not peer.networkState.p2pRequestHandler.isNil():
      peer.networkState.p2pRequestHandler(peer, envelope)

  proc p2pMessage(peer: Peer, envelopes: openarray[Envelope]) =
    if peer.state.trusted:
      # when trusted we can bypass any checks on envelope
      for envelope in envelopes:
        let msg = Message(env: envelope, isP2P: true)
        peer.networkState.filters.notify(msg)

  # Following message IDs are not part of EIP-627, but are added and used by
  # the Status application, we ignore them for now.
  nextID 11
  proc batchAcknowledged(peer: Peer) = discard
  proc messageResponse(peer: Peer) = discard

  nextID 123
  requestResponse:
    proc p2pSyncRequest(peer: Peer) = discard
    proc p2pSyncResponse(peer: Peer) = discard


  proc p2pRequestComplete(peer: Peer, requestId: Hash, lastEnvelopeHash: Hash,
    cursor: Bytes) = discard
    # TODO:
    # In the current specification the parameters are not wrapped in a regular
    # envelope as is done for the P2P Request packet. If we could alter this in
    # the spec it would be a cleaner separation between Waku and Mail server /
    # client.
    # Also, if a requestResponse block is used, a reqestId will automatically
    # be added by the protocol DSL.
    # However the requestResponse block in combination with p2pRequest cannot be
    # used due to the unfortunate fact that the packet IDs are not consecutive,
    # and nextID is not recognized in between these. The nextID behaviour could
    # be fixed, however it would be cleaner if the specification could be
    # changed to have these IDs to be consecutive.

# 'Runner' calls ---------------------------------------------------------------

proc processQueue(peer: Peer) =
  # Send to peer all valid and previously not send envelopes in the queue.
  var
    envelopes: seq[Envelope] = @[]
    wakuPeer = peer.state(Waku)
    wakuNet = peer.networkState(Waku)

  for message in wakuNet.queue.items:
    if wakuPeer.received.contains(message.hash):
      # trace "message was already send to peer", hash = $message.hash, peer
      continue

    if message.pow < wakuPeer.powRequirement:
      trace "Message PoW too low for peer", pow = message.pow,
                                            powReq = wakuPeer.powRequirement
      continue

    if not bloomFilterMatch(wakuPeer.bloom, message.bloom):
      trace "Message does not match peer bloom filter"
      continue

    if wakuNet.config.wakuMode == WakuSan and
        wakuPeer.wakuMode == WakuChan:
      if message.env.topic notin wakuPeer.topics:
        trace "Message does not match topics list"
        continue

    trace "Adding envelope"
    envelopes.add(message.env)
    wakuPeer.received.incl(message.hash)

  if envelopes.len() > 0:
    trace "Sending envelopes", amount=envelopes.len
    # Ignore failure of sending messages, this could occur when the connection
    # gets dropped
    traceAsyncErrors peer.messages(envelopes)

proc run(peer: Peer) {.async.} =
  while peer.connectionState notin {Disconnecting, Disconnected}:
    peer.processQueue()
    await sleepAsync(messageInterval)

proc pruneReceived(node: EthereumNode) {.raises: [].} =
  if node.peerPool != nil: # XXX: a bit dirty to need to check for this here ...
    var wakuNet = node.protocolState(Waku)

    for peer in node.protocolPeers(Waku):
      if not peer.initialized:
        continue

      # NOTE: Perhaps alter the queue prune call to keep track of a HashSet
      # of pruned messages (as these should be smaller), and diff this with
      # the received sets.
      peer.received = intersection(peer.received, wakuNet.queue.itemHashes)

proc run(node: EthereumNode, network: WakuNetwork) {.async.} =
  while true:
    # prune message queue every second
    # TTL unit is in seconds, so this should be sufficient?
    network.queue[].prune()
    # pruning the received sets is not necessary for correct workings
    # but simply from keeping the sets growing indefinitely
    node.pruneReceived()
    await sleepAsync(pruneInterval)

# Private EthereumNode calls ---------------------------------------------------

proc sendP2PMessage(node: EthereumNode, peerId: NodeId,
    envelopes: openarray[Envelope]): bool =
  for peer in node.peers(Waku):
    if peer.remote.id == peerId:
      asyncCheck peer.p2pMessage(envelopes)
      return true

proc queueMessage(node: EthereumNode, msg: Message): bool =

  var wakuNet = node.protocolState(Waku)
  # We have to do the same checks here as in the messages proc not to leak
  # any information that the message originates from this node.
  if not msg.allowed(wakuNet.config):
    return false

  trace "Adding message to queue", hash = $msg.hash
  if wakuNet.queue[].add(msg):
    # Also notify our own filters of the message we are sending,
    # e.g. msg from local Dapp to Dapp
    wakuNet.filters.notify(msg)

  return true

# Public EthereumNode calls ----------------------------------------------------

proc postMessage*(node: EthereumNode, pubKey = none[PublicKey](),
                  symKey = none[SymKey](), src = none[PrivateKey](),
                  ttl: uint32, topic: Topic, payload: Bytes,
                  padding = none[Bytes](), powTime = 1'f,
                  powTarget = defaultMinPow,
                  targetPeer = none[NodeId]()): bool =
  ## Post a message on the message queue which will be processed at the
  ## next `messageInterval`.
  ##
  ## NOTE: This call allows a post without encryption. If encryption is
  ## mandatory it should be enforced a layer up
  let payload = encode(Payload(payload: payload, src: src, dst: pubKey,
                               symKey: symKey, padding: padding))
  if payload.isSome():
    var env = Envelope(expiry:epochTime().uint32 + ttl,
                       ttl: ttl, topic: topic, data: payload.get(), nonce: 0)

    # Allow lightnode to post only direct p2p messages
    if targetPeer.isSome():
      return node.sendP2PMessage(targetPeer.get(), [env])
    else:
      # non direct p2p message can not have ttl of 0
      if env.ttl == 0:
        return false
      var msg = initMessage(env, powCalc = false)
      # XXX: make this non blocking or not?
      # In its current blocking state, it could be noticed by a peer that no
      # messages are send for a while, and thus that mining PoW is done, and
      # that next messages contains a message originated from this peer
      # zah: It would be hard to execute this in a background thread at the
      # moment. We'll need a way to send custom "tasks" to the async message
      # loop (e.g. AD2 support for AsyncChannels).
      if not msg.sealEnvelope(powTime, powTarget):
        return false

      # need to check expiry after mining PoW
      if not msg.env.valid():
        return false

      result = node.queueMessage(msg)

      # Allows light nodes to post via untrusted messages packet.
      # Queue gets processed immediatly as the node sends only its own messages,
      # so the privacy ship has already sailed anyhow.
      # TODO:
      # - Could be still a concern in terms of efficiency, if multiple messages
      # need to be send.
      # - For Waku Mode, the checks in processQueue are rather useless as the
      # idea is to connect only to 1 node? Also refactor in that case.
      if node.protocolState(Waku).config.isLightNode:
        for peer in node.peers(Waku):
          peer.processQueue()
  else:
    error "Encoding of payload failed"
    return false

proc subscribeFilter*(node: EthereumNode, filter: Filter,
                      handler:FilterMsgHandler = nil): string =
  ## Initiate a filter for incoming/outgoing messages. Messages can be
  ## retrieved with the `getFilterMessages` call or with a provided
  ## `FilterMsgHandler`.
  ##
  ## NOTE: This call allows for a filter without decryption. If encryption is
  ## mandatory it should be enforced a layer up.
  return node.protocolState(Waku).filters.subscribeFilter(filter, handler)

proc unsubscribeFilter*(node: EthereumNode, filterId: string): bool =
  ## Remove a previously subscribed filter.
  var filter: Filter
  return node.protocolState(Waku).filters.take(filterId, filter)

proc getFilterMessages*(node: EthereumNode, filterId: string): seq[ReceivedMessage] =
  ## Get all the messages currently in the filter queue. This will reset the
  ## filter message queue.
  return node.protocolState(Waku).filters.getFilterMessages(filterId)

proc filtersToBloom*(node: EthereumNode): Bloom =
  ## Returns the bloom filter of all topics of all subscribed filters.
  return node.protocolState(Waku).filters.toBloom()

proc setPowRequirement*(node: EthereumNode, powReq: float64) {.async.} =
  ## Sets the PoW requirement for this node, will also send
  ## this new PoW requirement to all connected peers.
  ##
  ## Failures when sending messages to peers will not be reported.
  # NOTE: do we need a tolerance of old PoW for some time?
  node.protocolState(Waku).config.powRequirement = powReq
  var futures: seq[Future[void]] = @[]
  for peer in node.peers(Waku):
    futures.add(peer.powRequirement(cast[uint64](powReq)))

  # Exceptions from sendMsg will not be raised
  await allFutures(futures)

proc setBloomFilter*(node: EthereumNode, bloom: Bloom) {.async.} =
  ## Sets the bloom filter for this node, will also send
  ## this new bloom filter to all connected peers.
  ##
  ## Failures when sending messages to peers will not be reported.
  # NOTE: do we need a tolerance of old bloom filter for some time?
  node.protocolState(Waku).config.bloom = bloom
  var futures: seq[Future[void]] = @[]
  for peer in node.peers(Waku):
    futures.add(peer.bloomFilterExchange(@bloom))

  # Exceptions from sendMsg will not be raised
  await allFutures(futures)

proc setTopics*(node: EthereumNode, topics: seq[Topic]):
    Future[bool] {.async.} =
  if topics.len > topicInterestMax:
    return false

  node.protocolState(Waku).config.topics = topics
  var futures: seq[Future[void]] = @[]
  for peer in node.peers(Waku):
    futures.add(peer.topicInterest(topics))

  # Exceptions from sendMsg will not be raised
  await allFutures(futures)

  return true

proc setMaxMessageSize*(node: EthereumNode, size: uint32): bool =
  ## Set the maximum allowed message size.
  ## Can not be set higher than ``defaultMaxMsgSize``.
  if size > defaultMaxMsgSize:
    warn "size > defaultMaxMsgSize"
    return false
  node.protocolState(Waku).config.maxMsgSize = size
  return true

proc setPeerTrusted*(node: EthereumNode, peerId: NodeId): bool =
  ## Set a connected peer as trusted.
  for peer in node.peers(Waku):
    if peer.remote.id == peerId:
      peer.state(Waku).trusted = true
      return true

proc setLightNode*(node: EthereumNode, isLightNode: bool) =
  ## Set this node as a Waku light node.
  ##
  ## NOTE: Should be run before connection is made with peers as this
  ## setting is only communicated at peer handshake.
  node.protocolState(Waku).config.isLightNode = isLightNode

proc configureWaku*(node: EthereumNode, config: WakuConfig) =
  ## Apply a Waku configuration.
  ##
  ## NOTE: Should be run before connection is made with peers as some
  ## of the settings are only communicated at peer handshake.
  node.protocolState(Waku).config = config

proc resetMessageQueue*(node: EthereumNode) =
  ## Full reset of the message queue.
  ##
  ## NOTE: Not something that should be run in normal circumstances.
  node.protocolState(Waku).queue[] = initQueue(defaultQueueCapacity)
