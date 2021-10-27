import
  std/[tables, options],
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
  AcceptConnectionCallback*[A] = proc(server: UtpRouter[A],
                         client: UtpSocket[A]): Future[void] {.gcsafe, raises: [Defect].}

  # Oject responsible for creating and maintaing table of of utp sockets.
  # caller should use `processIncomingBytes` proc to feed it with incoming byte 
  # packets, based this input, proper utp sockets will be created, closed, or will
  # receive data 
  UtpRouter*[A] = ref object
   sockets: Table[UtpSocketKey[A], UtpSocket[A]]
   socketConfig: SocketConfig
   acceptConnection: AcceptConnectionCallback[A]
   sendCb*: SendCallback[A]
   rng*: ref BrHmacDrbgContext

proc getUtpSocket[A](s: UtpRouter[A], k: UtpSocketKey[A]): Option[UtpSocket[A]] =
  let s = s.sockets.getOrDefault(k)
  if s == nil:
    none[UtpSocket[A]]()
  else:
    some(s)

proc deRegisterUtpSocket[A](s: UtpRouter[A], socket: UtpSocket[A]) =
  s.sockets.del(socket.socketKey)

iterator allSockets[A](s: UtpRouter[A]): UtpSocket[A] =
  for socket in s.sockets.values():
    yield socket

proc len*[A](s: UtpRouter[A]): int =
  len(s.sockets)

proc registerUtpSocket[A](p: UtpRouter, s: UtpSocket[A]) =
  # TODO Handle duplicates
  p.sockets[s.socketKey] = s
  # Install deregister handler, so when socket will get closed, in will be promptly
  # removed from open sockets table
  s.registerCloseCallback(proc () = p.deRegisterUtpSocket(s))

proc new*[A](
  T: type UtpRouter[A], 
  acceptConnectionCb: AcceptConnectionCallback[A], 
  socketConfig: SocketConfig = SocketConfig.init(),
  rng = newRng()): UtpRouter[A] {.raises: [Defect, CatchableError].} =
  doAssert(not(isNil(acceptConnectionCb)))
  UtpRouter[A](
    sockets: initTable[UtpSocketKey[A], UtpSocket[A]](),
    acceptConnection: acceptConnectionCb,
    socketConfig: socketConfig,
    rng: rng
  )

proc processPacket[A](r: UtpRouter[A], p: Packet, sender: A) {.async.}=
  notice "Received packet ", packet = p
  let socketKey = UtpSocketKey[A].init(sender, p.header.connectionId)
  let maybeSocket = r.getUtpSocket(socketKey)

  if (maybeSocket.isSome()):
    let socket = maybeSocket.unsafeGet()
    await socket.processPacket(p)
  else:
    # We got packet for which we do not have active socket. If the packet is not a
    # SynPacket we should reject it and send rst packet to sender in some cases
    if (p.header.pType == ST_SYN):
      # Initial ackNr is set to incoming packer seqNr
      let incomingSocket = initIncomingSocket[A](sender, r.sendCb, p.header.connectionId, p.header.seqNr, r.rng[])
      r.registerUtpSocket(incomingSocket)
      await incomingSocket.startIncomingSocket()
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

proc processIncomingBytes*[A](r: UtpRouter[A], bytes: seq[byte], sender: A) {.async.} = 
  let dec = decodePacket(bytes)
  if (dec.isOk()):
    await processPacket[A](r, dec.get(), sender)
  else:
    warn "failed to decode packet from address", address = sender

# Connect to provided address
# Reference implementation: https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L2732
proc connectTo*[A](r: UtpRouter[A], address: A): Future[UtpSocket[A]] {.async.}=
  let socket = initOutgoingSocket[A](address, r.sendCb, r.socketConfig, r.rng[])
  await socket.startOutgoingSocket()
  r.registerUtpSocket(socket)
  await socket.waitFotSocketToConnect()
  return socket

proc close*[A](r: UtpRouter[A]) =
  # TODO Rething all this when working on FIN and RESET packets and proper handling
  # of resources
  for s in r.allSockets():
    s.close()
