import
  std/[tables, options, sugar],
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

# this should probably be in standard lib, it allows lazy composition of options i.e
# one can write: O1 orElse O2 orElse O3, and chain will be evaluated to first option
# which isSome()
template orElse[A](a: Option[A], b: Option[A]): Option[A] =
  if (a.isSome()):
    a
  else:
    b

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
  ## returns number of active sockets
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

# There are different possiblites how connection was established, and we need to 
# check every case
proc getSocketOnReset[A](r: UtpRouter[A], sender: A, id: uint16): Option[UtpSocket[A]] =
  # id is our recv id
  let recvKey = UtpSocketKey[A].init(sender, id)

  # id is our send id, and we did nitiate the connection, our recv id is id - 1
  let sendInitKey = UtpSocketKey[A].init(sender, id - 1)

  # id is our send id, and we did not initiate the connection, so our recv id is id + 1
  let sendNoInitKey = UtpSocketKey[A].init(sender, id + 1)

  r.getUtpSocket(recvKey)
  .orElse(r.getUtpSocket(sendInitKey).filter(s => s.connectionIdSnd == id))
  .orElse(r.getUtpSocket(sendNoInitKey).filter(s => s.connectionIdSnd == id))

proc processPacket[A](r: UtpRouter[A], p: Packet, sender: A) {.async.}=
  notice "Received packet ", packet = p

  case p.header.pType
  of ST_RESET:
    let maybeSocket = r.getSocketOnReset(sender, p.header.connectionId)
    if maybeSocket.isSome():
      notice "Received rst packet on known connection closing"
      let socket = maybeSocket.unsafeGet()
      # reference implementation acutally changes the socket state to reset state unless
      # user explicitly closed socket before. The only difference between reset and destroy
      # state is that socket in destroy state is ultimatly deleted from active connection
      # list but socket in reset state lingers there until user of library closes it
      # explictly.
      socket.close()
    else:
      notice "Received rst packet for not known connection"
  of ST_SYN:
    # Syn packet are special, and we need to add 1 to header connectionId
    let socketKey = UtpSocketKey[A].init(sender, p.header.connectionId + 1)
    let maybeSocket = r.getUtpSocket(socketKey)
    if (maybeSocket.isSome()):
      notice "Ignoring SYN for already existing connection"
    else:
      notice "Received SYN for not known connection. Initiating incoming connection"
      # Initial ackNr is set to incoming packer seqNr
      let incomingSocket = initIncomingSocket[A](sender, r.sendCb, r.socketConfig ,p.header.connectionId, p.header.seqNr, r.rng[])
      r.registerUtpSocket(incomingSocket)
      await incomingSocket.startIncomingSocket()
      # TODO By default (when we have utp over udp) socket here is passed to upper layer
      # in SynRecv state, which is not writeable i.e user of socket cannot write
      # data to it unless some data will be received. This is counter measure to
      # amplification attacks.
      # During integration with discovery v5 (i.e utp over discovv5), we must re-think
      # this.
      asyncSpawn r.acceptConnection(r, incomingSocket)
  else:
    let socketKey = UtpSocketKey[A].init(sender, p.header.connectionId)
    let maybeSocket = r.getUtpSocket(socketKey)
    if (maybeSocket.isSome()):
      let socket = maybeSocket.unsafeGet()
      await socket.processPacket(p)
    else:
      # TODO add keeping track of recently send reset packets and do not send reset
      # to peers which we recently send reset to.
      notice "Recevied FIN/DATA/ACK on not known socket sending reset"
      let rstPacket = resetPacket(randUint16(r.rng[]), p.header.connectionId, p.header.seqNr)
      await r.sendCb(sender, encodePacket(rstPacket))

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
  r.registerUtpSocket(socket)
  await socket.startOutgoingSocket()
  await socket.waitFotSocketToConnect()
  return socket

proc close*[A](r: UtpRouter[A]) =
  # TODO Rething all this when working on FIN and RESET packets and proper handling
  # of resources
  for s in r.allSockets():
    s.close()
