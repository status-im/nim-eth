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
  chronos, stint, nimcrypto, chronicles,
  eth/common/eth_types_json_serialization, eth/[keys, rlp],
  kademlia, enode

export
  Node

logScope:
  topics = "discovery"

const
  MAINNET_BOOTNODES* = [
    "enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@52.16.188.185:30303",  # noqa: E501
    "enode://aa36fdf33dd030378a0168efe6ed7d5cc587fafa3cdd375854fe735a2e11ea3650ba29644e2db48368c46e1f60e716300ba49396cd63778bf8a818c09bded46f@13.93.211.84:30303",  # noqa: E501
    "enode://78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d@191.235.84.50:30303",  # noqa: E501
    "enode://158f8aab45f6d19c6cbf4a089c2670541a8da11978a2f90dbf6a502a4a3bab80d288afdbeb7ec0ef6d92de563767f3b1ea9e8e334ca711e9f8e2df5a0385e8e6@13.75.154.138:30303",  # noqa: E501
    "enode://1118980bf48b0a3640bdba04e0fe78b1add18e1cd99bf22d53daac1fd9972ad650df52176e7c7d89d1114cfef2bc23a2959aa54998a46afcf7d91809f0855082@52.74.57.123:30303",   # noqa: E501
  ]
  ROPSTEN_BOOTNODES* = [
    "enode://30b7ab30a01c124a6cceca36863ece12c4f5fa68e3ba9b0b51407ccc002eeed3b3102d20a88f1c1d3c3154e2449317b8ef95090e77b312d5cc39354f86d5d606@52.176.7.10:30303",     # noqa: E501
    "enode://865a63255b3bb68023b6bffd5095118fcc13e79dcf014fe4e47e065c350c7cc72af2e53eff895f11ba1bbb6a2b33271c1116ee870f266618eadfc2e78aa7349c@52.176.100.77:30303",   # noqa: E501
    "enode://6332792c4a00e3e4ee0926ed89e0d27ef985424d97b6a45bf0f23e51f0dcb5e66b875777506458aea7af6f9e4ffb69f43f3778ee73c81ed9d34c51c4b16b0b0f@52.232.243.152:30303",  # noqa: E501
    "enode://94c15d1b9e2fe7ce56e458b9a3b672ef11894ddedd0c6f247e0f1d3487f52b66208fb4aeb8179fce6e3a749ea93ed147c37976d67af557508d199d9594c35f09@192.81.208.223:30303",  # noqa: E501
  ]
  LOCAL_BOOTNODES = [
    "enode://6456719e7267e061161c88720287a77b80718d2a3a4ff5daeba614d029dc77601b75e32190aed1c9b0b9ccb6fac3bcf000f48e54079fa79e339c25d8e9724226@127.0.0.1:30301"
  ]

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

const MaxDgramSize = 1280

proc append*(w: var RlpWriter, a: IpAddress) =
  case a.family
  of IpAddressFamily.IPv6:
    w.append(a.address_v6.toMemRange)
  of IpAddressFamily.IPv4:
    w.append(a.address_v4.toMemRange)

proc append(w: var RlpWriter, p: Port) {.inline.} = w.append(p.int)
proc append(w: var RlpWriter, pk: PublicKey) {.inline.} = w.append(pk.getRaw())
proc append(w: var RlpWriter, h: MDigest[256]) {.inline.} = w.append(h.data)

proc pack(cmdId: CommandId, payload: BytesRange, pk: PrivateKey): Bytes =
  ## Create and sign a UDP message to be sent to a remote node.
  ##
  ## See https://github.com/ethereum/devp2p/blob/master/rlpx.md#node-discovery for information on
  ## how UDP packets are structured.

  # TODO: There is a lot of unneeded allocations here
  let encodedData = @[cmdId.byte] & payload.toSeq()
  let signature = @(pk.signMessage(encodedData).getRaw())
  let msgHash = keccak256.digest(signature & encodedData)
  result = @(msgHash.data) & signature & encodedData

proc validateMsgHash(msg: Bytes, msgHash: var MDigest[256]): bool =
  if msg.len > HEAD_SIZE:
    msgHash.data[0 .. ^1] = msg.toOpenArray(0, msgHash.data.high)
    result = msgHash == keccak256.digest(msg.toOpenArray(MAC_SIZE, msg.high))

proc recoverMsgPublicKey(msg: Bytes, pk: var PublicKey): bool =
  msg.len > HEAD_SIZE and
    recoverSignatureKey(msg.toOpenArray(MAC_SIZE, HEAD_SIZE),
      keccak256.digest(msg.toOpenArray(HEAD_SIZE, msg.high)).data,
      pk) == EthKeysStatus.Success

proc unpack(msg: Bytes): tuple[cmdId: CommandId, payload: Bytes] =
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
                            expiration())).toRange
  let msg = pack(cmdPing, payload, d.privKey)
  result = msg[0 ..< MAC_SIZE]
  trace ">>> ping ", n
  d.send(n, msg)

proc sendPong*(d: DiscoveryProtocol, n: Node, token: MDigest[256]) =
  let payload = rlp.encode((n.node.address, token, expiration())).toRange
  let msg = pack(cmdPong, payload, d.privKey)
  trace ">>> pong ", n
  d.send(n, msg)

proc sendFindNode*(d: DiscoveryProtocol, n: Node, targetNodeId: NodeId) =
  var data: array[64, byte]
  data[32 .. ^1] = targetNodeId.toByteArrayBE()
  let payload = rlp.encode((data, expiration())).toRange
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
      let payload = rlp.encode((nodes, expiration())).toRange
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
                           bootstrapNodes: openarray[ENode]
                           ): DiscoveryProtocol =
  result.new()
  result.privKey = privKey
  result.address = address
  result.bootstrapNodes = newSeqOfCap[Node](bootstrapNodes.len)
  for n in bootstrapNodes: result.bootstrapNodes.add(newNode(n))
  result.thisNode = newNode(privKey.getPublicKey(), address)
  result.kademlia = newKademliaProtocol(result.thisNode, result)

proc recvPing(d: DiscoveryProtocol, node: Node,
              msgHash: MDigest[256]) {.inline.} =
  d.kademlia.recvPing(node, msgHash)

proc recvPong(d: DiscoveryProtocol, node: Node, payload: Bytes) {.inline.} =
  let rlp = rlpFromBytes(payload.toRange)
  let tok = rlp.listElem(1).toBytes().toSeq()
  d.kademlia.recvPong(node, tok)

proc recvNeighbours(d: DiscoveryProtocol, node: Node,
                    payload: Bytes) {.inline.} =
  let rlp = rlpFromBytes(payload.toRange)
  let neighboursList = rlp.listElem(0)
  let sz = neighboursList.listLen()

  var neighbours = newSeqOfCap[Node](16)
  for i in 0 ..< sz:
    let n = neighboursList.listElem(i)
    let ipBlob = n.listElem(0).toBytes
    var ip: IpAddress
    case ipBlob.len
    of 4:
      ip = IpAddress(family: IpAddressFamily.IPv4)
      copyMem(addr ip.address_v4[0], baseAddr ipBlob, 4)
    of 16:
      ip = IpAddress(family: IpAddressFamily.IPv6)
      copyMem(addr ip.address_v6[0], baseAddr ipBlob, 16)
    else:
      error "Wrong ip address length!"
      continue

    let udpPort = n.listElem(1).toInt(uint16).Port
    let tcpPort = n.listElem(2).toInt(uint16).Port
    var pk: PublicKey
    if recoverPublicKey(n.listElem(3).toBytes.toOpenArray(), pk) != EthKeysStatus.Success:
      warn "Could not parse public key"
      continue

    neighbours.add(newNode(pk, Address(ip: ip, udpPort: udpPort, tcpPort: tcpPort)))
  d.kademlia.recvNeighbours(node, neighbours)

proc recvFindNode(d: DiscoveryProtocol, node: Node, payload: Bytes) {.inline, gcsafe.} =
  let rlp = rlpFromBytes(payload.toRange)
  trace "<<< find_node from ", node
  let rng = rlp.listElem(0).toBytes
  let nodeId = readUIntBE[256](rng[32 .. ^1].toOpenArray())
  d.kademlia.recvFindNode(node, nodeId)

proc expirationValid(rlpEncodedPayload: seq[byte]): bool {.inline.} =
  let rlp = rlpFromBytes(rlpEncodedPayload.toRange)
  let expiration = rlp.listElem(rlp.listLen - 1).toInt(uint32)
  result = epochTime() <= expiration.float

proc receive(d: DiscoveryProtocol, a: Address, msg: Bytes) {.gcsafe.} =
  var msgHash: MDigest[256]
  if validateMsgHash(msg, msgHash):
    var remotePubkey: PublicKey
    if recoverMsgPublicKey(msg, remotePubkey):
      let (cmdId, payload) = unpack(msg)
      # echo "received cmd: ", cmdId, ", from: ", a
      # echo "pubkey: ", remotePubkey.raw_key.toHex()
      if expirationValid(payload):
        let node = newNode(remotePubkey, a)
        case cmdId
        of cmdPing:
          d.recvPing(node, msgHash)
        of cmdPong:
          d.recvPong(node, payload)
        of cmdNeighbours:
          d.recvNeighbours(node, payload)
        of cmdFindNode:
          d.recvFindNode(node, payload)
      else:
        trace "Received msg already expired", cmdId, a
    else:
      error "Wrong public key from ", a
  else:
    error "Wrong msg mac from ", a

proc processClient(transp: DatagramTransport,
                   raddr: TransportAddress): Future[void] {.async, gcsafe.} =
  var proto = getUserData[DiscoveryProtocol](transp)
  var buf: seq[byte]
  try:
    # TODO: Maybe here better to use `peekMessage()` to avoid allocation,
    # but `Bytes` object is just a simple seq[byte], and `ByteRange` object
    # do not support custom length.
    var buf = transp.getMessage()
    let a = Address(ip: raddr.address, udpPort: raddr.port, tcpPort: raddr.port)
    proto.receive(a, buf)
  except:
    debug "Receive failed", err = getCurrentExceptionMsg()

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
  import logging, byteutils

  addHandler(newConsoleLogger())

  block:
    let m = hexToSeqByte"79664bff52ee17327b4a2d8f97d8fb32c9244d719e5038eb4f6b64da19ca6d271d659c3ad9ad7861a928ca85f8d8debfbe6b7ade26ad778f2ae2ba712567fcbd55bc09eb3e74a893d6b180370b266f6aaf3fe58a0ad95f7435bf3ddf1db940d20102f2cb842edbd4d182944382765da0ab56fb9e64a85a597e6bb27c656b4f1afb7e06b0fd4e41ccde6dba69a3c4a150845aaa4de2"
    var msgHash: MDigest[256]
    doAssert(validateMsgHash(m, msgHash))
    var remotePubkey: PublicKey
    doAssert(recoverMsgPublicKey(m, remotePubkey))

    let (cmdId, payload) = unpack(m)
    doAssert(payload == hexToSeqByte"f2cb842edbd4d182944382765da0ab56fb9e64a85a597e6bb27c656b4f1afb7e06b0fd4e41ccde6dba69a3c4a150845aaa4de2")
    doAssert(cmdId == cmdPong)
    doAssert(remotePubkey == initPublicKey("78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d"))

  let privKey = initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")

  # echo privKey

  # block:
  #   var b = @[1.byte, 2, 3]
  #   let m = pack(cmdPing, b.initBytesRange, privKey)
  #   let (remotePubkey, cmdId, payload) = unpack(m)
  #   doAssert(remotePubkey.raw_key.toHex == privKey.public_key.raw_key.toHex)

  var bootnodes = newSeq[ENode]()
  for item in LOCAL_BOOTNODES:
    bootnodes.add(initENode(item))

  let listenPort = Port(30310)
  var address = Address(udpPort: listenPort, tcpPort: listenPort)
  address.ip.family = IpAddressFamily.IPv4
  let discovery = newDiscoveryProtocol(privkey, address, bootnodes)

  echo discovery.thisNode.node.pubkey
  echo "this_node.id: ", discovery.thisNode.id.toHex()

  discovery.open()

  proc test() {.async.} =
    await discovery.bootstrap()

  waitFor test()
