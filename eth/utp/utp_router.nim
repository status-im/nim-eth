import
  std/[tables, options, hashes],
  chronos, bearssl, chronicles,
  ../keys,
  ./utp_socket,
  ./packets

logScope:
  topics = "utp_router"

export utp_socket

type
  # New remote client connection callback
  # ``server`` - UtpProtocol object.
  # ``client`` - accepted client utp socket.
  AcceptConnectionCallback* = proc(server: UtpRouter,
                         client: UtpSocket): Future[void] {.gcsafe, raises: [Defect].}

  # Oject responsible for creating and maintaing table of of utp sockets.
  # caller should use `processIncomingBytes` proc to feed it with incoming byte 
  # packets, based this input, proper utp sockets will be created, closed, or will
  # receive data 
  UtpRouter* = ref object
   sockets: Table[UtpSocketKey, UtpSocket]
   socketConfig: SocketConfig
   acceptConnection: AcceptConnectionCallback
   sendCb*: SendCallback
   rng*: ref BrHmacDrbgContext

# This should probably be defined in TransportAddress module, as hash function should
# be consitent with equality function
# in nim zero arrays always have hash equal to 0, irrespectively of array size, to
# avoid clashes betweend different types of addresses, each type have mixed different
# magic number
proc hash(x: TransportAddress): Hash =
  var h: Hash = 0
  case x.family
  of AddressFamily.None:
    h = h !& 31
    !$h
  of AddressFamily.IPv4:
    h = h !& x.address_v4.hash
    h = h !& x.port.hash
    h = h !& 37
    !$h
  of AddressFamily.IPv6:
    h = h !& x.address_v6.hash
    h = h !& x.port.hash
    h = h !& 41
    !$h
  of AddressFamily.Unix:
    h = h !& x.address_un.hash
    h = h !& 43
    !$h

# Required to use socketKey as key in hashtable
proc hash(x: UtpSocketKey): Hash =
  var h = 0
  h = h !& x.remoteAddress.hash
  h = h !& x.rcvId.hash
  !$h

proc getUtpSocket(s: UtpRouter, k: UtpSocketKey): Option[UtpSocket] =
  let s = s.sockets.getOrDefault(k)
  if s == nil:
    none[UtpSocket]()
  else:
    some(s)

proc deRegisterUtpSocket(s: UtpRouter, socket: UtpSocket) =
  s.sockets.del(socket.socketKey)

iterator allSockets(s: UtpRouter): UtpSocket =
  for socket in s.sockets.values():
    yield socket

proc len*(s: UtpRouter): int =
  len(s.sockets)

proc registerUtpSocket(p: UtpRouter, s: UtpSocket) =
  # TODO Handle duplicates
  p.sockets[s.socketKey] = s
  # Install deregister handler, so when socket will get closed, in will be promptly
  # removed from open sockets table
  s.registerCloseCallback(proc () = p.deRegisterUtpSocket(s))

proc new*(
  T: type UtpRouter, 
  acceptConnectionCb: AcceptConnectionCallback, 
  socketConfig: SocketConfig = SocketConfig.init(),
  rng = newRng()): UtpRouter {.raises: [Defect, CatchableError].} =
  doAssert(not(isNil(acceptConnectionCb)))
  UtpRouter(
    sockets: initTable[UtpSocketKey, UtpSocket](),
    acceptConnection: acceptConnectionCb,
    socketConfig: socketConfig,
    rng: rng
  )

proc processPacket(r: UtpRouter, p: Packet, sender: TransportAddress) {.async.}=
  notice "Received packet ", packet = p
  let socketKey = UtpSocketKey.init(sender, p.header.connectionId)
  let maybeSocket = r.getUtpSocket(socketKey)

  if (maybeSocket.isSome()):
    let socket = maybeSocket.unsafeGet()
    await socket.processPacket(p)
  else:
    # We got packet for which we do not have active socket. If the packet is not a
    # SynPacket we should reject it and send rst packet to sender in some cases
    if (p.header.pType == ST_SYN):
      # Initial ackNr is set to incoming packer seqNr
      let incomingSocket = initIncomingSocket(sender, r.sendCb, p.header.connectionId, p.header.seqNr, r.rng[])
      await incomingSocket.startIncomingSocket()
      r.registerUtpSocket(incomingSocket)
      # TODO By default (when we have utp over udp) socket here is passed to upper layer
      # in SynRecv state, which is not writeable i.e user of socket cannot write
      # data to it unless some data will be received. This is counter measure to
      # amplification attacks.
      # During integration with discovery v5 (i.e utp over discovv5), we must re-think
      # this.
      asyncSpawn r.acceptConnection(r, incomingSocket)
      notice "Received ST_SYN and socket is not known"
    else:
      # TODO not implemented
      notice "Received not ST_SYN and socket is not know"

proc processIncomingBytes*(r: UtpRouter, bytes: seq[byte], sender: TransportAddress) {.async.} = 
  let dec = decodePacket(bytes)
  if (dec.isOk()):
    await r.processPacket(dec.get(), sender)
  else:
    warn "failed to decode packet from address", address = sender

# Connect to provided address
# Reference implementation: https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L2732
proc connectTo*(r: UtpRouter, address: TransportAddress): Future[UtpSocket] {.async.}=
  let socket = initOutgoingSocket(address, r.sendCb, r.socketConfig, r.rng[])
  await socket.startOutgoingSocket()
  r.registerUtpSocket(socket)
  await socket.waitFotSocketToConnect()
  return socket

proc close*(r: UtpRouter) =
  # TODO Rething all this when working on FIN and RESET packets and proper handling
  # of resources
  for s in r.allSockets():
    s.close()
