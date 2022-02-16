# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Everything below the handling of ordinary messages
import
  std/[tables, options],
  chronos,
  chronicles,
  stew/shims/net,
  "."/[node, encoding, sessions]

const
  handshakeTimeout* = 2.seconds ## timeout for the reply on the
  ## whoareyou message
  responseTimeout* = 4.seconds ## timeout for the response of a request-response
  ## call

type
  Transport* [Client] = ref object
    client: Client
    bindAddress: Address ## UDP binding address
    transp: DatagramTransport
    pendingRequests: Table[AESGCMNonce, PendingRequest]
    codec*: Codec    
    rng: ref BrHmacDrbgContext

  PendingRequest = object
    node: Node
    message: seq[byte]

proc sendToA(t: Transport, a: Address, data: seq[byte]) =
  let ta = initTAddress(a.ip, a.port)
  let f = t.transp.sendTo(ta, data)
  f.callback = proc(data: pointer) {.gcsafe.} =
    if f.failed:
      # Could be `TransportUseClosedError` in case the transport is already
      # closed, or could be `TransportOsError` in case of a socket error.
      # In the latter case this would probably mostly occur if the network
      # interface underneath gets disconnected or similar.
      # TODO: Should this kind of error be propagated upwards? Probably, but
      # it should not stop the process as that would reset the discovery
      # progress in case there is even a small window of no connection.
      # One case that needs this error available upwards is when revalidating
      # nodes. Else the revalidation might end up clearing the routing tabl
      # because of ping failures due to own network connection failure.
      warn "Discovery send failed", msg = f.readError.msg

proc send(t: Transport, n: Node, data: seq[byte]) =
  doAssert(n.address.isSome())
  t.sendToA(n.address.get(), data)

proc sendMessage*(t: Transport, toId: NodeId, toAddr: Address, message: seq[byte]) =
  let (data, _) = encodeMessagePacket(t.rng[], t.codec, toId, toAddr,
    message)
  t.sendToA(toAddr, data)

# TODO: This could be improved to do the clean-up immediatily in case a non
# whoareyou response does arrive, but we would need to store the AuthTag
# somewhere
proc registerRequest(t: Transport, n: Node, message: seq[byte],
    nonce: AESGCMNonce) =
  let request = PendingRequest(node: n, message: message)
  if not t.pendingRequests.hasKeyOrPut(nonce, request):
    sleepAsync(responseTimeout).addCallback() do(data: pointer):
      t.pendingRequests.del(nonce)

##Todo: remove dependence on message. This should be higher
proc sendMessage*(t: Transport, toNode: Node, address: Address, message: seq[byte]) =
  let (data, nonce) = encodeMessagePacket(t.rng[], t.codec, toNode.id,
    address, message)

  t.registerRequest(toNode, message, nonce)
  t.send(toNode, data)

proc sendWhoareyou(t: Transport, toId: NodeId, a: Address,
    requestNonce: AESGCMNonce, node: Option[Node]) =
  let key = HandshakeKey(nodeId: toId, address: a)
  if not t.codec.hasHandshake(key):
    let
      recordSeq = if node.isSome(): node.get().record.seqNum
                  else: 0
      pubkey = if node.isSome(): some(node.get().pubkey)
              else: none(PublicKey)

    let data = encodeWhoareyouPacket(t.rng[], t.codec, toId, a, requestNonce,
      recordSeq, pubkey)
    sleepAsync(handshakeTimeout).addCallback() do(data: pointer):
    # TODO: should we still provide cancellation in case handshake completes
    # correctly?
      t.codec.handshakes.del(key)

    trace "Send whoareyou", dstId = toId, address = a
    t.sendToA(a, data)
  else:
    debug "Node with this id already has ongoing handshake, ignoring packet"

proc receive*(t: Transport, a: Address, packet: openArray[byte]) =
  let decoded = t.codec.decodePacket(a, packet)
  if decoded.isOk:
    let packet = decoded[]
    case packet.flag
    of OrdinaryMessage:
      if packet.messageOpt.isSome():
        let message = packet.messageOpt.get()
        trace "Received message packet", srcId = packet.srcId, address = a,
          kind = message.kind
        t.client.handleMessage(packet.srcId, a, message)
      else:
        trace "Not decryptable message packet received",
          srcId = packet.srcId, address = a
        t.sendWhoareyou(packet.srcId, a, packet.requestNonce,
          t.client.getNode(packet.srcId))

    of Flag.Whoareyou:
      trace "Received whoareyou packet", address = a
      var pr: PendingRequest
      if t.pendingRequests.take(packet.whoareyou.requestNonce, pr):
        let toNode = pr.node
        # This is a node we previously contacted and thus must have an address.
        doAssert(toNode.address.isSome())
        let address = toNode.address.get()
        let data = encodeHandshakePacket(t.rng[], t.codec, toNode.id,
          address, pr.message, packet.whoareyou, toNode.pubkey)

        trace "Send handshake message packet", dstId = toNode.id, address
        t.send(toNode, data)
      else:
        debug "Timed out or unrequested whoareyou packet", address = a
    of HandshakeMessage:
      trace "Received handshake message packet", srcId = packet.srcIdHs,
        address = a, kind = packet.message.kind
      t.client.handleMessage(packet.srcIdHs, a, packet.message)
      # For a handshake message it is possible that we received an newer ENR.
      # In that case we can add/update it to the routing table.
      if packet.node.isSome():
        let node = packet.node.get()
        # Lets not add nodes without correct IP in the ENR to the routing table.
        # The ENR could contain bogus IPs and although they would get removed
        # on the next revalidation, one could spam these as the handshake
        # message occurs on (first) incoming messages.
        if node.address.isSome() and a == node.address.get():
          if t.client.addNode(node):
            trace "Added new node to routing table after handshake", node
  else:
    trace "Packet decoding error", error = decoded.error, address = a

proc processClient[T](transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async.} =
  let t = getUserData[Transport[T]](transp)

  # TODO: should we use `peekMessage()` to avoid allocation?
  let buf = try: transp.getMessage()
            except TransportOsError as e:
              # This is likely to be local network connection issues.
              warn "Transport getMessage", exception = e.name, msg = e.msg
              return

  let ip = try: raddr.address()
           except ValueError as e:
             error "Not a valid IpAddress", exception = e.name, msg = e.msg
             return
  let a = Address(ip: ValidIpAddress.init(ip), port: raddr.port)

  t.receive(a, buf)

proc open*[T](t: Transport[T]) {.raises: [Defect, CatchableError].} =
  info "Starting transport", bindAddress = t.bindAddress

  # TODO allow binding to specific IP / IPv6 / etc
  let ta = initTAddress(t.bindAddress.ip, t.bindAddress.port)
  t.transp = newDatagramTransport(processClient[T], udata = t, local = ta)

proc close*(t: Transport) =
  t.transp.close

proc closed*(t: Transport) : bool =
  t.transp.closed

proc closeWait*(t: Transport) {.async.} =
  await t.transp.closeWait

proc newTransport*[T](
    client: T,
    privKey: PrivateKey,
    localNode: Node,
    bindPort: Port,
    bindIp = IPv4_any(),
    rng = newRng()):
    Transport[T]=

  # TODO Consider whether this should be a Defect
  doAssert rng != nil, "RNG initialization failed"

  Transport[T](
    client: client,
    bindAddress: Address(ip: ValidIpAddress.init(bindIp), port: bindPort),
    codec: Codec(localNode: localNode, privKey: privKey,
      sessions: Sessions.init(256)),
    rng: rng)
