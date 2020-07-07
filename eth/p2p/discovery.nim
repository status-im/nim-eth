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
  times,
  chronos, stint, nimcrypto/keccak, chronicles, bearssl,
  eth/[keys, rlp],
  kademlia, enode,
  stew/[objects, results]

export
  Node, results

logScope:
  topics = "discovery"

const
  # UDP packet constants.
  MAC_SIZE = 256 div 8  # 32
  SIG_SIZE = 520 div 8  # 65
  HEAD_SIZE = MAC_SIZE + SIG_SIZE  # 97
  EXPIRATION = 60  # let messages expire after N secondes
  PROTO_VERSION = 4

type
  DiscoveryProtocol* = ref object
    privKey: PrivateKey
    address: Address
    bootstrapNodes*: seq[Node]
    thisNode*: Node
    kademlia: KademliaProtocol[DiscoveryProtocol]
    transp: DatagramTransport

  CommandId = enum
    cmdPing = 1
    cmdPong = 2
    cmdFindNode = 3
    cmdNeighbours = 4

  DiscProtocolError* = object of CatchableError

  DiscResult*[T] = Result[T, cstring]

const MinListLen: array[CommandId, int] = [4, 3, 2, 2]

proc append*(w: var RlpWriter, a: IpAddress) =
  case a.family
  of IpAddressFamily.IPv6:
    w.append(a.address_v6)
  of IpAddressFamily.IPv4:
    w.append(a.address_v4)

proc append(w: var RlpWriter, p: Port) {.inline.} = w.append(p.int)
proc append(w: var RlpWriter, pk: PublicKey) {.inline.} = w.append(pk.toRaw())
proc append(w: var RlpWriter, h: MDigest[256]) {.inline.} = w.append(h.data)

proc pack(cmdId: CommandId, payload: openArray[byte], pk: PrivateKey): seq[byte] =
  ## Create and sign a UDP message to be sent to a remote node.
  ##
  ## See https://github.com/ethereum/devp2p/blob/master/rlpx.md#node-discovery for information on
  ## how UDP packets are structured.

  # TODO: There is a lot of unneeded allocations here
  let encodedData = @[cmdId.byte] & @payload
  let signature = @(pk.sign(encodedData).toRaw())
  let msgHash = keccak256.digest(signature & encodedData)
  result = @(msgHash.data) & signature & encodedData

proc validateMsgHash(msg: openArray[byte]): DiscResult[MDigest[256]] =
  if msg.len > HEAD_SIZE:
    var ret: MDigest[256]
    ret.data[0 .. ^1] = msg.toOpenArray(0, ret.data.high)
    if ret == keccak256.digest(msg.toOpenArray(MAC_SIZE, msg.high)):
      ok(ret)
    else:
      err("disc: invalid message hash")
  else:
    err("disc: msg missing hash")

proc recoverMsgPublicKey(msg: openArray[byte]): DiscResult[PublicKey] =
  if msg.len <= HEAD_SIZE:
    return err("disc: can't get public key")
  let sig = ? Signature.fromRaw(msg.toOpenArray(MAC_SIZE, HEAD_SIZE))
  recover(sig, msg.toOpenArray(HEAD_SIZE, msg.high))

proc unpack(msg: openArray[byte]): tuple[cmdId: CommandId, payload: seq[byte]] =
  # Check against possible RangeError
  if msg[HEAD_SIZE].int < CommandId.low.ord or
     msg[HEAD_SIZE].int > CommandId.high.ord:
    raise newException(DiscProtocolError, "Unsupported packet id")

  result = (cmdId: msg[HEAD_SIZE].CommandId, payload: msg[HEAD_SIZE + 1 .. ^1])

proc expiration(): uint32 =
  result = uint32(epochTime() + EXPIRATION)

# Wire protocol

proc send(d: DiscoveryProtocol, n: Node, data: seq[byte]) =
  let ta = initTAddress(n.node.address.ip, n.node.address.udpPort)
  let f = d.transp.sendTo(ta, data)
  f.callback = proc(data: pointer) {.gcsafe.} =
    if f.failed:
      debug "Discovery send failed", msg = f.readError.msg

proc sendPing*(d: DiscoveryProtocol, n: Node): seq[byte] =
  let payload = rlp.encode((PROTO_VERSION, d.address, n.node.address,
                            expiration()))
  let msg = pack(cmdPing, payload, d.privKey)
  result = msg[0 ..< MAC_SIZE]
  trace ">>> ping ", n
  d.send(n, msg)

proc sendPong*(d: DiscoveryProtocol, n: Node, token: MDigest[256]) =
  let payload = rlp.encode((n.node.address, token, expiration()))
  let msg = pack(cmdPong, payload, d.privKey)
  trace ">>> pong ", n
  d.send(n, msg)

proc sendFindNode*(d: DiscoveryProtocol, n: Node, targetNodeId: NodeId) =
  var data: array[64, byte]
  data[32 .. ^1] = targetNodeId.toByteArrayBE()
  let payload = rlp.encode((data, expiration()))
  let msg = pack(cmdFindNode, payload, d.privKey)
  trace ">>> find_node to ", n#, ": ", msg.toHex()
  d.send(n, msg)

proc sendNeighbours*(d: DiscoveryProtocol, node: Node, neighbours: seq[Node]) =
  const MAX_NEIGHBOURS_PER_PACKET = 12 # TODO: Implement a smarter way to compute it
  type Neighbour = tuple[ip: IpAddress, udpPort, tcpPort: Port, pk: PublicKey]
  var nodes = newSeqOfCap[Neighbour](MAX_NEIGHBOURS_PER_PACKET)
  shallow(nodes)

  template flush() =
    block:
      let payload = rlp.encode((nodes, expiration()))
      let msg = pack(cmdNeighbours, payload, d.privkey)
      trace "Neighbours to", node, nodes
      d.send(node, msg)
      nodes.setLen(0)

  for i, n in neighbours:
    nodes.add((n.node.address.ip, n.node.address.udpPort,
               n.node.address.tcpPort, n.node.pubkey))
    if nodes.len == MAX_NEIGHBOURS_PER_PACKET:
      flush()

  if nodes.len != 0: flush()

proc newDiscoveryProtocol*(privKey: PrivateKey, address: Address,
                           bootstrapNodes: openarray[ENode], rng = newRng()
                           ): DiscoveryProtocol =
  result.new()
  result.privKey = privKey
  result.address = address
  result.bootstrapNodes = newSeqOfCap[Node](bootstrapNodes.len)
  for n in bootstrapNodes: result.bootstrapNodes.add(newNode(n))
  result.thisNode = newNode(privKey.toPublicKey(), address)
  result.kademlia = newKademliaProtocol(result.thisNode, result, rng = rng)

proc recvPing(d: DiscoveryProtocol, node: Node,
              msgHash: MDigest[256]) {.inline.} =
  d.kademlia.recvPing(node, msgHash)

proc recvPong(d: DiscoveryProtocol, node: Node, payload: seq[byte]) {.inline.} =
  let rlp = rlpFromBytes(payload)
  let tok = rlp.listElem(1).toBytes()
  d.kademlia.recvPong(node, tok)

proc recvNeighbours(d: DiscoveryProtocol, node: Node,
                    payload: seq[byte]) {.inline.} =
  let rlp = rlpFromBytes(payload)
  let neighboursList = rlp.listElem(0)
  let sz = neighboursList.listLen()

  var neighbours = newSeqOfCap[Node](16)
  for i in 0 ..< sz:
    let n = neighboursList.listElem(i)
    let ipBlob = n.listElem(0).toBytes
    var ip: IpAddress
    case ipBlob.len
    of 4:
      ip = IpAddress(
        family: IpAddressFamily.IPv4, address_v4: toArray(4, ipBlob))
    of 16:
      ip = IpAddress(
        family: IpAddressFamily.IPv6, address_v6: toArray(16, ipBlob))
    else:
      error "Wrong ip address length!"
      continue

    let udpPort = n.listElem(1).toInt(uint16).Port
    let tcpPort = n.listElem(2).toInt(uint16).Port
    let pk = PublicKey.fromRaw(n.listElem(3).toBytes)
    if pk.isErr:
      warn "Could not parse public key"
      continue

    neighbours.add(newNode(pk[], Address(ip: ip, udpPort: udpPort, tcpPort: tcpPort)))
  d.kademlia.recvNeighbours(node, neighbours)

proc recvFindNode(d: DiscoveryProtocol, node: Node, payload: openArray[byte]) {.inline, gcsafe.} =
  let rlp = rlpFromBytes(payload)
  trace "<<< find_node from ", node
  let rng = rlp.listElem(0).toBytes
  # Check for pubkey len
  if rng.len == 64:
    let nodeId = readUIntBE[256](rng[32 .. ^1])
    d.kademlia.recvFindNode(node, nodeId)
  else:
    trace "Invalid target public key received"

proc expirationValid(cmdId: CommandId, rlpEncodedPayload: openArray[byte]):
    bool {.inline, raises:[DiscProtocolError, RlpError].} =
  ## Can only raise `DiscProtocolError` and all of `RlpError`
  # Check if there is a payload
  if rlpEncodedPayload.len <= 0:
    raise newException(DiscProtocolError, "RLP stream is empty")
  let rlp = rlpFromBytes(rlpEncodedPayload)
  # Check payload is an RLP list and if the list has the minimum items required
  # for this packet type
  if rlp.isList and rlp.listLen >= MinListLen[cmdId]:
    # Expiration is always the last mandatory item of the list
    let expiration = rlp.listElem(MinListLen[cmdId] - 1).toInt(uint32)
    result = epochTime() <= expiration.float
  else:
    raise newException(DiscProtocolError, "Invalid RLP list for this packet id")

proc receive*(d: DiscoveryProtocol, a: Address, msg: openArray[byte]) {.gcsafe.} =
  ## Can raise `DiscProtocolError` and all of `RlpError`
  # Note: export only needed for testing
  let msgHash = validateMsgHash(msg)
  if msgHash.isOk():
    let remotePubkey = recoverMsgPublicKey(msg)
    if remotePubkey.isOk:
      let (cmdId, payload) = unpack(msg)

      if expirationValid(cmdId, payload):
        let node = newNode(remotePubkey[], a)
        case cmdId
        of cmdPing:
          d.recvPing(node, msgHash[])
        of cmdPong:
          d.recvPong(node, payload)
        of cmdNeighbours:
          d.recvNeighbours(node, payload)
        of cmdFindNode:
          d.recvFindNode(node, payload)
      else:
        trace "Received msg already expired", cmdId, a
    else:
      notice "Wrong public key from ", a, err = remotePubkey.error
  else:
    notice "Wrong msg mac from ", a

proc processClient(transp: DatagramTransport,
                   raddr: TransportAddress): Future[void] {.async, gcsafe.} =
  var proto = getUserData[DiscoveryProtocol](transp)
  try:
    # TODO: Maybe here better to use `peekMessage()` to avoid allocation,
    # but `Bytes` object is just a simple seq[byte], and `ByteRange` object
    # do not support custom length.
    var buf = transp.getMessage()
    let a = Address(ip: raddr.address, udpPort: raddr.port, tcpPort: raddr.port)
    proto.receive(a, buf)
  except RlpError as e:
    debug "Receive failed", exc = e.name, err = e.msg
  except DiscProtocolError as e:
    debug "Receive failed", exc = e.name, err = e.msg
  except Exception as e:
    debug "Receive failed", exc = e.name, err = e.msg
    raise e

proc open*(d: DiscoveryProtocol) =
  # TODO allow binding to specific IP / IPv6 / etc
  let ta = initTAddress(IPv4_any(), d.address.udpPort)
  d.transp = newDatagramTransport(processClient, udata = d, local = ta)

proc lookupRandom*(d: DiscoveryProtocol): Future[seq[Node]] {.inline.} =
  d.kademlia.lookupRandom()

proc run(d: DiscoveryProtocol) {.async.} =
  while true:
    discard await d.lookupRandom()
    await sleepAsync(3000)
    trace "Discovered nodes", nodes = d.kademlia.nodesDiscovered

proc bootstrap*(d: DiscoveryProtocol) {.async.} =
  await d.kademlia.bootstrap(d.bootstrapNodes)
  discard d.run()

proc resolve*(d: DiscoveryProtocol, n: NodeId): Future[Node] =
  d.kademlia.resolve(n)

proc randomNodes*(d: DiscoveryProtocol, count: int): seq[Node] {.inline.} =
  d.kademlia.randomNodes(count)

when isMainModule:
  import logging, stew/byteutils

  const LOCAL_BOOTNODES = [
    "enode://6456719e7267e061161c88720287a77b80718d2a3a4ff5daeba614d029dc77601b75e32190aed1c9b0b9ccb6fac3bcf000f48e54079fa79e339c25d8e9724226@127.0.0.1:30301"
  ]

  addHandler(newConsoleLogger())

  block:
    let m = hexToSeqByte"79664bff52ee17327b4a2d8f97d8fb32c9244d719e5038eb4f6b64da19ca6d271d659c3ad9ad7861a928ca85f8d8debfbe6b7ade26ad778f2ae2ba712567fcbd55bc09eb3e74a893d6b180370b266f6aaf3fe58a0ad95f7435bf3ddf1db940d20102f2cb842edbd4d182944382765da0ab56fb9e64a85a597e6bb27c656b4f1afb7e06b0fd4e41ccde6dba69a3c4a150845aaa4de2"
    discard validateMsgHash(m).expect("valid hash")
    var remotePubkey = recoverMsgPublicKey(m).expect("valid key")

    let (cmdId, payload) = unpack(m)
    doAssert(payload == hexToSeqByte"f2cb842edbd4d182944382765da0ab56fb9e64a85a597e6bb27c656b4f1afb7e06b0fd4e41ccde6dba69a3c4a150845aaa4de2")
    doAssert(cmdId == cmdPong)
    doAssert(remotePubkey == PublicKey.fromHex(
      "78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d")[])

  let privKey = PrivateKey.fromHex("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]

  # echo privKey

  # block:
  #   var b = @[1.byte, 2, 3]
  #   let m = pack(cmdPing, b.initBytesRange, privKey)
  #   let (remotePubkey, cmdId, payload) = unpack(m)
  #   doAssert(remotePubkey.raw_key.toHex == privKey.public_key.raw_key.toHex)

  var bootnodes = newSeq[ENode]()
  for item in LOCAL_BOOTNODES:
    bootnodes.add(ENode.fromString(item)[])

  let listenPort = Port(30310)
  var address = Address(udpPort: listenPort, tcpPort: listenPort)
  address.ip.family = IpAddressFamily.IPv4
  let discovery = newDiscoveryProtocol(privkey, address, bootnodes)

  echo discovery.thisNode.node.pubkey
  echo "this_node.id: ", discovery.thisNode.id.toHex()

  discovery.open()

  proc test() {.async.} =
    {.gcsafe.}:
      await discovery.bootstrap()

  waitFor test()
