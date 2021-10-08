# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, options, hashes],
  chronos, chronicles, bearssl,
  ./packets,
  ../keys

logScope:
  topics = "utp"

type
  ConnectionState = enum
    Uninitialized,
    Idle,
    SynSent,
    SynRecv,
    Connected,
    ConnectedFull,
    Reset,
    Destory

  UtpSocketKey = object
    remoteAddress: TransportAddress
    rcvId: uint16

  UtpSocket* = ref object
    remoteAddress*: TransportAddress
    state: ConnectionState
    # Connection id for packets we receive
    connectionIdRcv: uint16
    # Connection id for packets we send
    connectionIdSnd: uint16
    # Sequence number for the next packet to be sent.
    seqNr: uint16
    # All seq number up to this havve been correctly acked by us
    ackNr: uint16

    # Should be completed after succesful connection to remote host.
    # TODO check if nim gc handles properly cyclic references, as this future will
    # contain reference to socket which hold this future.
    # If that is not the case, then this future will need to be hold independly
    connectionFuture: Future[UtpSocket]

  UtpSocketsContainerRef = ref object
    sockets: TableRef[UtpSocketKey, UtpSocket]

  # For now utp protocol is tied to udp transport, but ultimatly we would like to
  # abstract underlying transport to be able to run utp over udp, discoveryv5 or
  # maybe some test transport
  UtpProtocol* = ref object
    transport: DatagramTransport
    activeSockets: UtpSocketsContainerRef
    rng*: ref BrHmacDrbgContext

proc new(T: type UtpSocketsContainerRef): T =
  UtpSocketsContainerRef(sockets: newTable[UtpSocketKey, UtpSocket]())

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

proc registerUtpSocket(s: UtpSocketsContainerRef, k: UtpSocketKey, socket: UtpSocket) =
  # TODO Handle duplicates
  s.sockets[k] = socket

proc initOutgoingSocket(to: TransportAddress, rng: var BrHmacDrbgContext): UtpSocket =
  # TODO handle possible clashes and overflows
  let rcvConnectionId = randUint16(rng)
  let sndConnectionId = rcvConnectionId + 1
  let initalSeqNr = randUint16(rng)
  UtpSocket(
    remoteAddress: to,
    state: SynSent,
    connectionIdRcv: rcvConnectionId,
    connectionIdSnd: sndConnectionId,
    seqNr: initalSeqNr,
    connectionFuture: newFuture[UtpSocket]()
  )

proc initIncomingSocket(to: TransportAddress, connectionId: uint16, ackNr: uint16, rng: var BrHmacDrbgContext): UtpSocket =
  let initalSeqNr = randUint16(rng)
  UtpSocket(
    remoteAddress: to,
    state: SynRecv,
    connectionIdRcv: connectionId + 1,
    connectionIdSnd: connectionId,
    seqNr: initalSeqNr,
    ackNr: ackNr,
    connectionFuture: newFuture[UtpSocket]()
  )

proc ack(socket: UtpSocket): Packet =
  ackPacket(socket.seqNr, socket.connectionIdSnd, socket.ackNr, 1048576)

proc isConnected*(socket: UtpSocket): bool =
  socket.state == Connected

# TODO not implemented
# for now just log incoming packets
proc processPacket(prot: UtpProtocol, p: Packet, sender: TransportAddress) =
  notice "Received packet ", packet = p
  let socketKey = UtpSocketKey(remoteAddress: sender, rcvId: p.header.connectionId)
  let maybeSocket = prot.activeSockets.getUtpSocket(socketKey)
  if (maybeSocket.isSome()):
    let socket = maybeSocket.unsafeGet()
    case p.header.pType
    of ST_DATA:
      # TODO not implemented
      notice "Received ST_DATA on known socket"
    of ST_FIN:
      # TODO not implemented
      notice "Received ST_FIN on known socket"
    of ST_STATE:
      notice "Received ST_STATE on known socket"
      if (socket.state == SynSent):
        socket.state = Connected
        socket.ackNr = p.header.seqNr
        socket.connectionFuture.complete(socket)
      # TODO to finish handhske we should respond with ST_DATA packet, without it
      # socket is left in half-open state
    of ST_RESET:
      # TODO not implemented
      notice "Received ST_RESET on known socket"
    of ST_SYN:
      # TODO not implemented
      notice "Received ST_SYN on known socket"
  else:
    # We got packet for which we do not have active socket. If the packet is not a
    # SynPacket we should reject it and send rst packet to sender in some cases
    if (p.header.pType == ST_SYN):
      # Initial ackNr is set to incoming packer seqNr
      let incomingSocket = initIncomingSocket(sender, p.header.connectionId, p.header.seqNr, prot.rng[])
      let socketKey = UtpSocketKey(remoteAddress: incomingSocket.remoteAddress, rcvId: incomingSocket.connectionIdRcv)
      prot.activeSockets.registerUtpSocket(socketKey, incomingSocket)
      let synAck = incomingSocket.ack()
      let encoded = encodePacket(synAck)
      # TODO sending should be done from UtpSocket context
      discard prot.transport.sendTo(sender, encoded)
      notice "Received ST_SYN and socket is not known"
    else:
      # TODO not implemented
      notice "Received not ST_SYN and socket is not know"

# Connect to provided address
# Reference implementation: https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L2732
# TODO not implemented
proc connectTo*(p: UtpProtocol, address: TransportAddress): Future[UtpSocket] =
  let socket = initOutgoingSocket(address, p.rng[])
  let socketKey = UtpSocketKey(remoteAddress: socket.remoteAddress, rcvId: socket.connectionIdRcv)
  # TODO Buffer in syn packet should be based on our current buffer size
  let packet = synPacket(socket.seqNr, socket.connectionIdRcv, 1048576)
  notice "Sending packet", packet = packet
  let packetEncoded = encodePacket(packet)
  p.activeSockets.registerUtpSocket(socketKey, socket)
  # TODO add callback to handle errors and cancellation i.e unregister socket on
  # send error and finish connection future with failure
  # sending should be done from UtpSocketContext
  discard p.transport.sendTo(address, packetEncoded)
  return socket.connectionFuture

proc processDatagram(transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async.} =
  let utpProt = getUserData[UtpProtocol](transp)
  # TODO: should we use `peekMessage()` to avoid allocation?
  let buf = try: transp.getMessage()
            except TransportOsError as e:
              # This is likely to be local network connection issues.
              return

  let dec = decodePacket(buf)
  if (dec.isOk()):
    processPacket(utpProt, dec.get(), raddr)
  else:
    warn "failed to decode packet from address", address = raddr

proc new*(T: type UtpProtocol, address: TransportAddress, rng = newRng()): UtpProtocol {.raises: [Defect, CatchableError].} =
  let activeSockets = UtpSocketsContainerRef.new()
  let utp = UtpProtocol(activeSockets: activeSockets, rng: rng)
  let ta = newDatagramTransport(processDatagram, udata = utp, local = address)
  utp.transport = ta
  utp

proc closeWait*(p: UtpProtocol): Future[void] =
  p.transport.closeWait()
