import
  hashes, stint,
  ../enode, enr

const
  authTagSize* = 12
  idNonceSize* = 32
  aesKeySize* = 128 div 8

type
  NodeId* = UInt256
  AuthTag* = array[authTagSize, byte]
  IdNonce* = array[idNonceSize, byte]
  AesKey* = array[aesKeySize, byte]

  HandshakeKey* = object
    nodeId*: NodeId
    address*: string # TODO: Replace with Address, need hash

  WhoareyouObj* = object
    authTag*: AuthTag
    idNonce*: IdNonce
    recordSeq*: uint64

  Whoareyou* = ref WhoareyouObj

  Database* = ref object of RootRef

  PacketKind* = enum
    # TODO This is needed only to make Nim 1.0.4 happy
    #      Without it, the `PacketKind` type cannot be used as
    #      a discriminator in case objects.
    unused = 0x00

    ping = 0x01
    pong = 0x02
    findnode = 0x03
    nodes = 0x04
    regtopic = 0x05
    ticket = 0x06
    regconfirmation = 0x07
    topicquery = 0x08

  RequestId* = uint64

  PingPacket* = object
    enrSeq*: uint64

  PongPacket* = object
    enrSeq*: uint64
    ip*: seq[byte]
    port*: uint16

  FindNodePacket* = object
    distance*: uint32

  NodesPacket* = object
    total*: uint32
    enrs*: seq[Record]

  SomePacket* = PingPacket or PongPacket or FindNodePacket or NodesPacket

  Packet* = object
    reqId*: RequestId
    case kind*: PacketKind
    of ping:
      ping*: PingPacket
    of pong:
      pong*: PongPacket
    of findnode:
      findNode*: FindNodePacket
    of nodes:
      nodes*: NodesPacket
    else:
      # TODO: Define the rest
      discard

template packetKind*(T: typedesc[SomePacket]): PacketKind =
  when T is PingPacket: ping
  elif T is PongPacket: pong
  elif T is FindNodePacket: findNode
  elif T is NodesPacket: nodes

method storeKeys*(db: Database, id: NodeId, address: Address, r, w: AesKey):
    bool {.base, raises: [Defect].} = discard

method loadKeys*(db: Database, id: NodeId, address: Address, r, w: var AesKey):
    bool {.base, raises: [Defect].} = discard

proc toBytes*(id: NodeId): array[32, byte] {.inline.} =
  id.toByteArrayBE()

proc hash*(id: NodeId): Hash {.inline.} =
  result = hashData(unsafeAddr id, sizeof(id))

# TODO: To make this work I think we also need to implement `==` due to case
# fields in object
proc hash*(address: Address): Hash {.inline.} =
  hashData(unsafeAddr address, sizeof(address))

proc hash*(key: HandshakeKey): Hash =
  result = key.nodeId.hash !& key.address.hash
  result = !$result
