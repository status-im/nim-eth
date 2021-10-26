# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, options, hashes, sugar, math],
  chronos, chronicles, bearssl,
  ./packets,
  ./growable_buffer,
  ./utp_socket,
  ../keys

logScope:
  topics = "utp"

type
  UtpSocketsContainerRef = ref object
    sockets: Table[UtpSocketKey, UtpSocket]

  # For now utp protocol is tied to udp transport, but ultimatly we would like to
  # abstract underlying transport to be able to run utp over udp, discoveryv5 or
  # maybe some test transport
  UtpProtocol* = ref object
    transport: DatagramTransport
    sendCb: SendCallback
    activeSockets: UtpSocketsContainerRef
    acceptConnectionCb: AcceptConnectionCallback
    socketConfig: SocketConfig
    rng*: ref BrHmacDrbgContext

  # New remote client connection callback
  # ``server`` - UtpProtocol object.
  # ``client`` - accepted client utp socket.
  AcceptConnectionCallback* = proc(server: UtpProtocol,
                         client: UtpSocket): Future[void] {.gcsafe, raises: [Defect].}

proc new(T: type UtpSocketsContainerRef): T =
  UtpSocketsContainerRef(sockets: initTable[UtpSocketKey, UtpSocket]())

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

proc getUtpSocket(s: UtpSocketsContainerRef, k: UtpSocketKey): Option[UtpSocket] =
  let s = s.sockets.getOrDefault(k)
  if s == nil:
    none[UtpSocket]()
  else:
    some(s)

proc registerUtpSocket(s: UtpSocketsContainerRef, socket: UtpSocket) =
  # TODO Handle duplicates
  s.sockets[socket.socketKey] = socket

proc deRegisterUtpSocket(s: UtpSocketsContainerRef, socket: UtpSocket) =
  s.sockets.del(socket.socketKey)

iterator allSockets(s: UtpSocketsContainerRef): UtpSocket =
  for socket in s.sockets.values():
    yield socket

proc len(s: UtpSocketsContainerRef): int =
  len(s.sockets)

proc registerSocket(p: UtpProtocol, s: UtpSocket) =
  p.activeSockets.registerUtpSocket(s)
  # Install deregister handler, so when socket will get closed, in will be promptly
  # removed from open sockets table
  s.registerCloseCallback(proc () = p.activeSockets.deRegisterUtpSocket(s))

proc processPacket(prot: UtpProtocol, p: Packet, sender: TransportAddress) {.async.}=
  notice "Received packet ", packet = p
  let socketKey = UtpSocketKey.init(sender, p.header.connectionId)
  let maybeSocket = prot.activeSockets.getUtpSocket(socketKey)

  if (maybeSocket.isSome()):
    let socket = maybeSocket.unsafeGet()
    await socket.processPacket(p)
  else:
    # We got packet for which we do not have active socket. If the packet is not a
    # SynPacket we should reject it and send rst packet to sender in some cases
    if (p.header.pType == ST_SYN):
      # Initial ackNr is set to incoming packer seqNr
      let incomingSocket = initIncomingSocket(sender, prot.sendCb, p.header.connectionId, p.header.seqNr, prot.rng[])
      await incomingSocket.startIncomingSocket()
      prot.registerSocket(incomingSocket)
      # TODO By default (when we have utp over udp) socket here is passed to upper layer
      # in SynRecv state, which is not writeable i.e user of socket cannot write
      # data to it unless some data will be received. This is counter measure to
      # amplification attacks.
      # During integration with discovery v5 (i.e utp over discovv5), we must re-think
      # this.
      asyncSpawn prot.acceptConnectionCb(prot, incomingSocket)
      notice "Received ST_SYN and socket is not known"
    else:
      # TODO not implemented
      notice "Received not ST_SYN and socket is not know"

proc processIncomingBytes(prot: UtpProtocol, bytes: seq[byte], sender: TransportAddress) {.async.} = 
  let dec = decodePacket(bytes)
  if (dec.isOk()):
    await processPacket(prot, dec.get(), sender)
  else:
    warn "failed to decode packet from address", address = sender

proc openSockets*(p: UtpProtocol): int =
  ## Returns number of currently active sockets
  len(p.activeSockets)

# Connect to provided address
# Reference implementation: https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L2732
proc connectTo*(p: UtpProtocol, address: TransportAddress): Future[UtpSocket] {.async.}=
  let socket = initOutgoingSocket(address, p.sendCb, p.socketConfig, p.rng[])
  await socket.startOutgoingSocket()
  p.registerSocket(socket)
  await socket.waitFotSocketToConnect()
  return socket

proc processDatagram(transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async.} =
  let utpProt = getUserData[UtpProtocol](transp)
  # TODO: should we use `peekMessage()` to avoid allocation?
  let buf = try: transp.getMessage()
            except TransportOsError as e:
              # This is likely to be local network connection issues.
              return
  await utpProt.processIncomingBytes(buf, raddr)

proc initSendCallback(t: DatagramTransport): SendCallback =
  return (
    proc (to: TransportAddress, data: seq[byte]): Future[void] = 
      t.sendTo(to, data)
  )

proc new*(
  T: type UtpProtocol, 
  acceptConnectionCb: AcceptConnectionCallback, 
  address: TransportAddress,
  socketConfig: SocketConfig = SocketConfig.init(),
  rng = newRng()): UtpProtocol {.raises: [Defect, CatchableError].} =
  doAssert(not(isNil(acceptConnectionCb)))
  let activeSockets = UtpSocketsContainerRef.new()
  let utp = UtpProtocol(
    activeSockets: activeSockets,
    acceptConnectionCb: acceptConnectionCb,
    socketConfig: socketConfig,
    rng: rng
  )
  let ta = newDatagramTransport(processDatagram, udata = utp, local = address)
  let sendCb = initSendCallback(ta)
  utp.sendCb = sendCb
  utp.transport = ta
  utp

proc closeWait*(p: UtpProtocol): Future[void] {.async.} =
  # TODO Rething all this when working on FIN and RESET packets and proper handling
  # of resources
  await p.transport.closeWait()
  for s in p.activeSockets.allSockets():
    s.close()
