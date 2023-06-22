# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[tables, options, sugar],
  chronos, chronicles, metrics,
  ../keys,
  ./utp_socket,
  ./packets

export utp_socket

logScope:
  topics = "eth utp utp_router"

declareCounter utp_received_packets,
  "All correct received uTP packets"
declareCounter utp_failed_packets,
  "All received uTP packets which failed decoding"
declareGauge utp_established_connections,
  "Current number of established uTP sockets"
declareCounter utp_allowed_incoming,
  "Total number of allowed incoming connections"
declareCounter utp_declined_incoming,
  "Total number of declined incoming connections"
declareCounter utp_success_outgoing,
  "Total number of successful outgoing connections"
declareCounter utp_failed_outgoing,
  "Total number of failed outgoing connections"

type
  # New remote client connection callback
  # ``server`` - UtpProtocol object.
  # ``client`` - accepted client utp socket.
  AcceptConnectionCallback*[A] = proc(server: UtpRouter[A],
    client: UtpSocket[A]): Future[void] {.gcsafe, raises: [].}

  # Callback to act as firewall for incoming peers. Should return true if peer
  # is allowed to connect.
  AllowConnectionCallback*[A] = proc(r: UtpRouter[A], remoteAddress: A,
    connectionId: uint16): bool {.gcsafe, raises: [], noSideEffect.}

  # Object responsible for creating and maintaining table of utp sockets.
  # Caller should use `processIncomingBytes` proc to feed it with incoming byte
  # packets. Based on this input, proper utp sockets will be created, closed,
  # or will receive data.
  UtpRouter*[A] = ref object
   sockets: Table[UtpSocketKey[A], UtpSocket[A]]
   socketConfig: SocketConfig
   acceptConnection: AcceptConnectionCallback[A]
   closed: bool
   sendCb*: SendCallback[A]
   allowConnection*: AllowConnectionCallback[A]
   udata: pointer
   rng*: ref HmacDrbgContext

const
  # Maximal number of tries to generate unique socket while establishing
  # outgoing connection.
  maxSocketGenerationTries = 1000

# This should probably be in standard lib, it allows lazy composition of options
# i.e one can write: O1 orElse O2 orElse O3, and chain will be evaluated to
# first option which isSome()
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
  utp_established_connections.set(int64(len(s.sockets)))
  debug "Removed utp socket", dst = socket.socketKey, lenSockets = len(s.sockets)

iterator allSockets[A](s: UtpRouter[A]): UtpSocket[A] =
  for socket in s.sockets.values():
    yield socket

proc len*[A](s: UtpRouter[A]): int =
  ## returns number of active sockets
  len(s.sockets)

proc registerUtpSocket[A](p: UtpRouter, s: UtpSocket[A]) =
  ## Register socket, overwriting already existing one
  p.sockets[s.socketKey] = s
  utp_established_connections.set(int64(len(p.sockets)))
  debug "Registered new uTP socket",
    dst = s.socketKey, totalSockets = len(p.sockets)
  # Install deregister handler so that when the socket gets closed, it gets
  # removed from open sockets table.
  s.registerCloseCallback(proc () = p.deRegisterUtpSocket(s))

proc registerIfAbsent[A](p: UtpRouter, s: UtpSocket[A]): bool =
  ## Registers socket only if it's not already existing in the active sockets
  ## table. Returns true if socket has been successfully registered.
  if p.sockets.hasKey(s.socketKey):
    false
  else:
    p.registerUtpSocket(s)
    true

proc new*[A](
    T: type UtpRouter[A],
    acceptConnectionCb: AcceptConnectionCallback[A],
    allowConnectionCb: AllowConnectionCallback[A],
    udata: pointer,
    socketConfig: SocketConfig = SocketConfig.init(),
    rng = newRng()): UtpRouter[A] =
  doAssert(not(isNil(acceptConnectionCb)))
  UtpRouter[A](
    sockets: initTable[UtpSocketKey[A], UtpSocket[A]](),
    acceptConnection: acceptConnectionCb,
    allowConnection: allowConnectionCb,
    socketConfig: socketConfig,
    udata: udata,
    rng: rng
  )

proc new*[A](
    T: type UtpRouter[A],
    acceptConnectionCb: AcceptConnectionCallback[A],
    socketConfig: SocketConfig = SocketConfig.init(),
    rng = newRng()): UtpRouter[A] =
  UtpRouter[A].new(acceptConnectionCb, nil, nil, socketConfig, rng)

proc new*[A](
    T: type UtpRouter[A],
    acceptConnectionCb: AcceptConnectionCallback[A],
    allowConnectionCb: AllowConnectionCallback[A],
    udata: ref,
    socketConfig: SocketConfig = SocketConfig.init(),
    rng = newRng()): UtpRouter[A] =
  doAssert(not(isNil(acceptConnectionCb)))
  GC_ref(udata)
  UtpRouter[A].new(
    acceptConnectionCb, allowConnectionCb,
    cast[pointer](udata), socketConfig, rng)

proc new*[A](
    T: type UtpRouter[A],
    acceptConnectionCb: AcceptConnectionCallback[A],
    udata: ref,
    socketConfig: SocketConfig = SocketConfig.init(),
    rng = newRng()): UtpRouter[A] =
  UtpRouter[A].new(acceptConnectionCb, nil, udata, socketConfig, rng)

proc getUserData*[A, T](router: UtpRouter[A]): T =
  ## Obtain user data stored in ``router`` object.
  cast[T](router.udata)

# There are different possibilities on how the connection got established, need
# to check every case.
proc getSocketOnReset[A](
    r: UtpRouter[A], sender: A, id: uint16): Option[UtpSocket[A]] =
  # id is our recv id
  let recvKey = UtpSocketKey[A].init(sender, id)

  # id is our send id, and we did initiate the connection, our recv id is id - 1
  let sendInitKey = UtpSocketKey[A].init(sender, id - 1)

  # id is our send id, and we did not initiate the connection,
  # our recv id is id + 1
  let sendNoInitKey = UtpSocketKey[A].init(sender, id + 1)

  r.getUtpSocket(recvKey)
  .orElse(r.getUtpSocket(sendInitKey).filter(s => s.connectionIdSnd == id))
  .orElse(r.getUtpSocket(sendNoInitKey).filter(s => s.connectionIdSnd == id))

proc shouldAllowConnection[A](
    r: UtpRouter[A], remoteAddress: A, connectionId: uint16): bool =
  if r.allowConnection == nil:
    # if the callback is not configured all incoming connections are allowed
    true
  else:
    r.allowConnection(r, remoteAddress, connectionId)

proc processPacket[A](r: UtpRouter[A], p: Packet, sender: A) {.async.}=
  debug "Received packet ",
    sender = sender,
    packetType = p.header.pType

  case p.header.pType
  of ST_RESET:
    let maybeSocket = r.getSocketOnReset(sender, p.header.connectionId)
    if maybeSocket.isSome():
      debug "Received RST packet on known connection, closing socket"
      let socket = maybeSocket.unsafeGet()
      # The reference implementation actually changes the socket state to reset
      # state unless the user explicitly closed the socket before. The only
      # difference between the reset and the destroy state is that a socket in
      # the destroy state is ultimately deleted from active connection list but
      # a socket in reset state lingers there until the user of library closes
      # it explicitly.
      socket.destroy()
    else:
      debug "Received RST packet for unknown connection, ignoring"
  of ST_SYN:
    # SYN packets are special and need an addition of 1 to header connectionId
    let socketKey = UtpSocketKey[A].init(sender, p.header.connectionId + 1)
    let maybeSocket = r.getUtpSocket(socketKey)
    if (maybeSocket.isSome()):
      debug "Ignoring SYN for already existing connection"
    else:
      if (len(r.sockets) >= r.socketConfig.maxNumberOfOpenConnections):
        debug "New incoming connection not allowed due to connection limit",
          lenConnections = len(r.sockets),
          limit = r.socketConfig.maxNumberOfOpenConnections

        utp_declined_incoming.inc()
        return

      if (r.shouldAllowConnection(sender, p.header.connectionId)):
        debug "Received SYN for new connection. Initiating incoming connection",
          synSeqNr = p.header.seqNr
        # Initial ackNr is set to incoming packet seqNr
        let incomingSocket = newIncomingSocket[A](
          sender, r.sendCb, r.socketConfig,
          p.header.connectionId, p.header.seqNr, r.rng[])
        r.registerUtpSocket(incomingSocket)
        incomingSocket.startIncomingSocket()
        # Based on configuration, socket is passed to upper layer either in
        # SynRecv or Connected state
        utp_allowed_incoming.inc()
        debug "Accepting incoming connection", src = incomingSocket.socketKey
        asyncSpawn r.acceptConnection(r, incomingSocket)
      else:
        utp_declined_incoming.inc()
        debug "Connection declined"
  else:
    let socketKey = UtpSocketKey[A].init(sender, p.header.connectionId)
    let maybeSocket = r.getUtpSocket(socketKey)
    if (maybeSocket.isSome()):
      debug "Received FIN/DATA/ACK packet on existing socket"
      let socket = maybeSocket.unsafeGet()
      await socket.processPacket(p)
    else:
      # TODO: add keeping track of recently send reset packets and do not send
      # reset to peers which we recently send reset to.
      debug "Received FIN/DATA/ACK on unknown socket, sending reset"
      let rstPacket = resetPacket(
        randUint16(r.rng[]), p.header.connectionId, p.header.seqNr)
      await r.sendCb(sender, encodePacket(rstPacket))

proc processIncomingBytes*[A](
    r: UtpRouter[A], bytes: seq[byte], sender: A) {.async.} =
  if (not r.closed):
    let decoded = decodePacket(bytes)
    if (decoded.isOk()):
      utp_received_packets.inc()
      await processPacket[A](r, decoded.get(), sender)
    else:
      utp_failed_packets.inc()
      let err = decoded.error()
      warn "Failed to decode packet from address", address = sender, msg = err

proc generateNewUniqueSocket[A](
    r: UtpRouter[A], address: A):Option[UtpSocket[A]] =
  ## Try to generate unique socket, give up after maxSocketGenerationTries tries
  var tryCount = 0

  while tryCount < maxSocketGenerationTries:
    let rcvId = randUint16(r.rng[])
    let socket = newOutgoingSocket[A](
      address, r.sendCb, r.socketConfig, rcvId, r.rng[])

    if r.registerIfAbsent(socket):
      return some(socket)

    inc tryCount

  return none[UtpSocket[A]]()

proc innerConnect[A](s: UtpSocket[A]): Future[ConnectionResult[A]] {.async.} =
    try:
      await s.startOutgoingSocket()
      utp_success_outgoing.inc()
      debug "Outgoing connection successful", dst = s.socketKey
      return ok(s)
    except ConnectionError:
      utp_failed_outgoing.inc()
      debug "Outgoing connection timed-out", dst = s.socketKey
      s.destroy()
      return err(OutgoingConnectionError(kind: ConnectionTimedOut))
    except CancelledError as exc:
      s.destroy()
      debug "Connection cancelled", dst = s.socketKey
      raise exc

proc connect[A](s: UtpSocket[A]): Future[ConnectionResult[A]] =
  debug "Initiating connection", dst = s.socketKey

  s.innerConnect()

proc socketAlreadyExists[A](): ConnectionResult[A] =
  return err(OutgoingConnectionError(kind: SocketAlreadyExists))

proc socketAlreadyExistsFut[A](): Future[ConnectionResult[A]] =
  let fut = newFuture[ConnectionResult[A]]()
  fut.complete(socketAlreadyExists[A]())
  return fut

# Connect to provided address
# Reference implementation:
# https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L2732
proc connectTo*[A](
    r: UtpRouter[A], address: A): Future[ConnectionResult[A]] =
  let maybeSocket = r.generateNewUniqueSocket(address)

  if (maybeSocket.isNone()):
    return socketAlreadyExistsFut[A]()
  else:
    let socket = maybeSocket.unsafeGet()
    let connFut = socket.connect()
    return connFut

# Connect to provided address with provided connection id. If the socket with
# this id and address already exists, return error
proc connectTo*[A](
    r: UtpRouter[A], address: A, connectionId: uint16):
    Future[ConnectionResult[A]] =
  let socket = newOutgoingSocket[A](
    address, r.sendCb, r.socketConfig, connectionId, r.rng[])

  if (r.registerIfAbsent(socket)):
    let connFut = socket.connect()
    return connFut
  else:
    return socketAlreadyExistsFut[A]()

proc shutdown*[A](r: UtpRouter[A]) =
  # stop processing any new packets and close all sockets in background without
  # notifying remote peers
  r.closed = true
  for s in r.allSockets():
    s.destroy()

proc shutdownWait*[A](r: UtpRouter[A]) {.async.} =
  var activeSockets: seq[UtpSocket[A]] = @[]
  # stop processing any new packets and close all sockets without
  # notifying remote peers
  r.closed = true

  # Need to make a copy as calling socket.destroyWait() removes the socket from
  # the table and iterator throws error. Another option would be to wait until
  # the number of open sockets drops to 0
  for s in r.allSockets():
    activeSockets.add(s)

  for s in activeSockets:
    yield s.destroyWait()
