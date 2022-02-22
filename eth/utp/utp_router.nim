# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

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

  # Callback to act as firewall for incoming peers. Should return true if peer
  # is allowed to connect.
  AllowConnectionCallback*[A] = proc(r: UtpRouter[A], remoteAddress: A,
    connectionId: uint16): bool {.gcsafe, raises: [Defect], noSideEffect.}

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
   rng*: ref BrHmacDrbgContext

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

iterator allSockets[A](s: UtpRouter[A]): UtpSocket[A] =
  for socket in s.sockets.values():
    yield socket

proc len*[A](s: UtpRouter[A]): int =
  ## returns number of active sockets
  len(s.sockets)

proc registerUtpSocket[A](p: UtpRouter, s: UtpSocket[A]) =
  ## Register socket, overwriting already existing one
  p.sockets[s.socketKey] = s
  # Install deregister handler, so when socket gets closed, in will be promptly
  # removed from open sockets table
  s.registerCloseCallback(proc () = p.deRegisterUtpSocket(s))

proc registerIfAbsent[A](p: UtpRouter, s: UtpSocket[A]): bool =
  ## Registers socket only if it's not already existing in the active sockets
  ## table. Returns true if socket has been succesfuly registered.
  if p.sockets.hasKey(s.socketKey):
    false
  else:
    p.registerUtpSocket(s)
    true

proc new*[A](
    T: type UtpRouter[A],
    acceptConnectionCb: AcceptConnectionCallback[A],
    allowConnectionCb: AllowConnectionCallback[A],
    socketConfig: SocketConfig = SocketConfig.init(),
    rng = newRng()): UtpRouter[A] =
  doAssert(not(isNil(acceptConnectionCb)))
  UtpRouter[A](
    sockets: initTable[UtpSocketKey[A], UtpSocket[A]](),
    acceptConnection: acceptConnectionCb,
    allowConnection: allowConnectionCb,
    socketConfig: socketConfig,
    rng: rng
  )

proc new*[A](
    T: type UtpRouter[A],
    acceptConnectionCb: AcceptConnectionCallback[A],
    socketConfig: SocketConfig = SocketConfig.init(),
    rng = newRng()): UtpRouter[A] =
  UtpRouter[A].new(acceptConnectionCb, nil, socketConfig, rng)

# There are different possibilities on how the connection got established, need
# to check every case.
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

proc shouldAllowConnection[A](r: UtpRouter[A], remoteAddress: A, connectionId: uint16): bool =
  if r.allowConnection == nil:
    # if the callback is not configured it means all incoming connections are allowed
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
      # reference implementation acutally changes the socket state to reset state unless
      # user explicitly closed socket before. The only difference between reset and destroy
      # state is that socket in destroy state is ultimatly deleted from active connection
      # list but socket in reset state lingers there until user of library closes it
      # explictly.
      socket.destroy()
    else:
      debug "Received RST packet for unknown connection, ignoring"
  of ST_SYN:
    # Syn packet are special, and we need to add 1 to header connectionId
    let socketKey = UtpSocketKey[A].init(sender, p.header.connectionId + 1)
    let maybeSocket = r.getUtpSocket(socketKey)
    if (maybeSocket.isSome()):
      debug "Ignoring SYN for already existing connection"
    else:
      if (r.shouldAllowConnection(sender, p.header.connectionId)):
        debug "Received SYN for new connection. Initiating incoming connection",
          synSeqNr = p.header.seqNr
        # Initial ackNr is set to incoming packer seqNr
        let incomingSocket = newIncomingSocket[A](sender, r.sendCb, r.socketConfig ,p.header.connectionId, p.header.seqNr, r.rng[])
        r.registerUtpSocket(incomingSocket)
        incomingSocket.startIncomingSocket()
        # Based on configuration, socket is passed to upper layer either in SynRecv
        # or Connected state
        info "Accepting incoming connection",
          to = incomingSocket.socketKey
        asyncSpawn r.acceptConnection(r, incomingSocket)
      else:
        debug "Connection declined"
  else:
    let socketKey = UtpSocketKey[A].init(sender, p.header.connectionId)
    let maybeSocket = r.getUtpSocket(socketKey)
    if (maybeSocket.isSome()):
      debug "Received FIN/DATA/ACK packet on existing socket"
      let socket = maybeSocket.unsafeGet()
      await socket.processPacket(p)
    else:
      # TODO add keeping track of recently send reset packets and do not send reset
      # to peers which we recently send reset to.
      debug "Received FIN/DATA/ACK on not known socket sending reset"
      let rstPacket = resetPacket(randUint16(r.rng[]), p.header.connectionId, p.header.seqNr)
      await r.sendCb(sender, encodePacket(rstPacket))

proc processIncomingBytes*[A](r: UtpRouter[A], bytes: seq[byte], sender: A) {.async.} =
  if (not r.closed):
    let dec = decodePacket(bytes)
    if (dec.isOk()):
      await processPacket[A](r, dec.get(), sender)
    else:
      let err = dec.error()
      warn "failed to decode packet from address", address = sender, msg = err

proc generateNewUniqueSocket[A](r: UtpRouter[A], address: A): Option[UtpSocket[A]] =
  ## Tries to generate unique socket, gives up after maxSocketGenerationTries tries
  var tryCount = 0

  while tryCount < maxSocketGenerationTries:
    let rcvId = randUint16(r.rng[])
    let socket = newOutgoingSocket[A](address, r.sendCb, r.socketConfig, rcvId, r.rng[])

    if r.registerIfAbsent(socket):
      return some(socket)

    inc tryCount

  return none[UtpSocket[A]]()

proc connect[A](s: UtpSocket[A]): Future[ConnectionResult[A]] {.async.}=
    info "Initiating connection",
      to = s.socketKey

    let startFut = s.startOutgoingSocket()

    startFut.cancelCallback = proc(udata: pointer) {.gcsafe.} =
      # if for some reason future will be cancelled, destory socket to clear it from
      # active socket list
      s.destroy()

    try:
      await startFut
      info "Outgoing connection successful",
        to = s.socketKey
      return ok(s)
    except ConnectionError:
      info "Outgoing connection timed-out",
        to = s.socketKey
      s.destroy()
      return err(OutgoingConnectionError(kind: ConnectionTimedOut))

# Connect to provided address
# Reference implementation: https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L2732
proc connectTo*[A](r: UtpRouter[A], address: A): Future[ConnectionResult[A]] {.async.} =
  let maybeSocket = r.generateNewUniqueSocket(address)

  if (maybeSocket.isNone()):
    return err(OutgoingConnectionError(kind: SocketAlreadyExists))
  else:
    let socket = maybeSocket.unsafeGet()
    return await socket.connect()

# Connect to provided address with provided connection id, if socket with this id
# and address already exsits return error
proc connectTo*[A](r: UtpRouter[A], address: A, connectionId: uint16): Future[ConnectionResult[A]] {.async.} =
  let socket = newOutgoingSocket[A](address, r.sendCb, r.socketConfig, connectionId, r.rng[])

  if (r.registerIfAbsent(socket)):
    return await socket.connect()
  else:
    return err(OutgoingConnectionError(kind: SocketAlreadyExists))

proc shutdown*[A](r: UtpRouter[A]) =
  # stop processing any new packets and close all sockets in background without
  # notifing remote peers
  r.closed = true
  for s in r.allSockets():
    s.destroy()

proc shutdownWait*[A](r: UtpRouter[A]) {.async.} =
  var activeSockets: seq[UtpSocket[A]] = @[]
  # stop processing any new packets and close all sockets without
  # notifing remote peers
  r.closed = true

  # we need to make copy as calling socket.destroyWait() removes socket from the table
  # and iterator throws error. Antother option would be to wait until number of opensockets
  # go to 0
  for s in r.allSockets():
    activeSockets.add(s)

  for s in activeSockets:
    yield s.destroyWait()
