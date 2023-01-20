# nim-eth
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[deques, tables],
  chronos,
  ".."/../[rlp, keys], ../../common/eth_types,
  ".."/[enode, kademlia, discovery, rlpxcrypt]

export eth_types.NetworkId

const
  useSnappy* = defined(useSnappy)

type
  EthereumNode* = ref object
    networkId*: NetworkId
    clientId*: string
    connectionState*: ConnectionState
    keys*: KeyPair
    address*: Address # The external address that the node will be advertising
    peerPool*: PeerPool
    bindIp*: IpAddress
    bindPort*: Port

    # Private fields:
    capabilities*: seq[Capability]
    protocols*: seq[ProtocolInfo]
    listeningServer*: StreamServer
    protocolStates*: seq[RootRef]
    discovery*: DiscoveryProtocol
    when useSnappy:
      protocolVersion*: uint
    rng*: ref HmacDrbgContext

  Peer* = ref object
    remote*: Node
    network*: EthereumNode

    # Private fields:
    transport*: StreamTransport
    dispatcher*: Dispatcher
    lastReqId*: int
    secretsState*: SecretState
    connectionState*: ConnectionState
    protocolStates*: seq[RootRef]
    outstandingRequests*: seq[Deque[OutstandingRequest]]
    awaitedMessages*: seq[FutureBase]
    when useSnappy:
      snappyEnabled*: bool

  SeenNode* = object
    nodeId*: NodeId
    stamp*: chronos.Moment

  PeerPool* = ref object
    # Private fields:
    network*: EthereumNode
    keyPair*: KeyPair
    networkId*: NetworkId
    minPeers*: int
    clientId*: string
    discovery*: DiscoveryProtocol
    lastLookupTime*: float
    connQueue*: AsyncQueue[Node]
    seenTable*: Table[NodeId, SeenNode]
    connectedNodes*: Table[Node, Peer]
    connectingNodes*: HashSet[Node]
    running*: bool
    observers*: Table[int, PeerObserver]

  PeerObserver* = object
    onPeerConnected*: proc(p: Peer) {.gcsafe, raises: [].}
    onPeerDisconnected*: proc(p: Peer) {.gcsafe, raises: [].}
    protocol*: ProtocolInfo

  Capability* = object
    name*: string
    version*: int

  UnsupportedProtocol* = object of Defect
    # This is raised when you attempt to send a message from a particular
    # protocol to a peer that doesn't support the protocol.

  MalformedMessageError* = object of CatchableError
  UnsupportedMessageError* = object of CatchableError

  PeerDisconnected* = object of CatchableError
    reason*: DisconnectionReason

  UselessPeerError* = object of CatchableError

  ##
  ## Quasy-private types. Use at your own risk.
  ##

  ProtocolInfoObj* = object
    name*: string
    version*: int
    messages*: seq[MessageInfo]
    index*: int # the position of the protocol in the
                # ordered list of supported protocols

    # Private fields:
    peerStateInitializer*: PeerStateInitializer
    networkStateInitializer*: NetworkStateInitializer
    handshake*: HandshakeStep
    disconnectHandler*: DisconnectionHandler

  ProtocolInfo* = ptr ProtocolInfoObj

  MessageInfo* = object
    id*: int
    name*: string

    # Private fields:
    thunk*: ThunkProc
    printer*: MessageContentPrinter
    requestResolver*: RequestResolver
    nextMsgResolver*: NextMsgResolver

  Dispatcher* = ref object # private
    # The dispatcher stores the mapping of negotiated message IDs between
    # two connected peers. The dispatcher may be shared between connections
    # running with the same set of supported protocols.
    #
    # `protocolOffsets` will hold one slot of each locally supported
    # protocol. If the other peer also supports the protocol, the stored
    # offset indicates the numeric value of the first message of the protocol
    # (for this particular connection). If the other peer doesn't support the
    # particular protocol, the stored offset is -1.
    #
    # `messages` holds a mapping from valid message IDs to their handler procs.
    #
    protocolOffsets*: seq[int]
    messages*: seq[ptr MessageInfo]
    activeProtocols*: seq[ProtocolInfo]

  ##
  ## Private types:
  ##

  OutstandingRequest* = object
    id*: int
    future*: FutureBase
    timeoutAt*: Moment

  # Private types:
  MessageHandlerDecorator* = proc(msgId: int, n: NimNode): NimNode

  ThunkProc* = proc(x: Peer, msgId: int, data: Rlp): Future[void]
    {.gcsafe, raises: [RlpError].}

  MessageContentPrinter* = proc(msg: pointer): string
    {.gcsafe, raises: [].}

  RequestResolver* = proc(msg: pointer, future: FutureBase)
    {.gcsafe, raises: [].}

  NextMsgResolver* = proc(msgData: Rlp, future: FutureBase)
    {.gcsafe, raises: [RlpError].}

  PeerStateInitializer* = proc(peer: Peer): RootRef
    {.gcsafe, raises: [].}

  NetworkStateInitializer* = proc(network: EthereumNode): RootRef
    {.gcsafe, raises: [].}

  HandshakeStep* = proc(peer: Peer): Future[void]
    {.gcsafe, raises: [].}

  DisconnectionHandler* = proc(peer: Peer, reason: DisconnectionReason):
    Future[void] {.gcsafe, raises: [].}

  ConnectionState* = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  # Disconnect message reasons as specified:
  # https://github.com/ethereum/devp2p/blob/master/rlpx.md#disconnect-0x01
  # Receiving values that are too large or that are in the enum hole will
  # trigger `RlpTypeMismatch` error on deserialization.
  DisconnectionReason* = enum
    DisconnectRequested = 0x00,
    TcpError = 0x01,
    BreachOfProtocol = 0x02,
    UselessPeer = 0x03,
    TooManyPeers = 0x04,
    AlreadyConnected = 0x05,
    IncompatibleProtocolVersion = 0x06,
    NullNodeIdentityReceived = 0x07,
    ClientQuitting = 0x08,
    UnexpectedIdentity = 0x09,
    SelfConnection = 0x0A,
    MessageTimeout = 0x0B,
    SubprotocolReason = 0x10

proc `$`*(peer: Peer): string = $peer.remote

proc toENode*(v: EthereumNode): ENode =
  ENode(pubkey: v.keys.pubkey, address: v.address)
