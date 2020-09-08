import
  std/hashes,
  stint, chronos,
  eth/[keys, rlp], enr, node

{.push raises: [Defect].}

const
  authTagSize* = 12
  idNonceSize* = 32
  aesKeySize* = 128 div 8

type
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
    pubKey* {.rlpIgnore.}: Option[PublicKey]

  Whoareyou* = ref WhoareyouObj

  MessageKind* = enum
    # TODO This is needed only to make Nim 1.0.4 happy
    #      Without it, the `MessageKind` type cannot be used as
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

  PingMessage* = object
    enrSeq*: uint64

  PongMessage* = object
    enrSeq*: uint64
    ip*: seq[byte]
    port*: uint16

  FindNodeMessage* = object
    distance*: uint32

  NodesMessage* = object
    total*: uint32
    enrs*: seq[Record]

  SomeMessage* = PingMessage or PongMessage or FindNodeMessage or NodesMessage

  Message* = object
    reqId*: RequestId
    case kind*: MessageKind
    of ping:
      ping*: PingMessage
    of pong:
      pong*: PongMessage
    of findnode:
      findNode*: FindNodeMessage
    of nodes:
      nodes*: NodesMessage
    else:
      # TODO: Define the rest
      discard

template messageKind*(T: typedesc[SomeMessage]): MessageKind =
  when T is PingMessage: ping
  elif T is PongMessage: pong
  elif T is FindNodeMessage: findNode
  elif T is NodesMessage: nodes

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

proc read*(rlp: var Rlp, O: type Option[Record]): O
    {.raises: [ValueError, RlpError, Defect].} =
  mixin read
  if not rlp.isList:
    raise newException(
      ValueError, "Could not deserialize optional ENR, expected list")

  # The discovery specification states that in case no ENR is send in the
  # handshake, an empty rlp list instead should be send.
  if rlp.listLen == 0:
    none(Record)
  else:
    some(read(rlp, Record))

proc append*(writer: var RlpWriter, value: Option[Record]) =
  if value.isSome:
    writer.append value.get
  else:
    writer.startList(0)
