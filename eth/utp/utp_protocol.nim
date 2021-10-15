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
  ./growable_buffer,
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
    Destroy

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
    
    # the number of packets in the send queue. Packets that haven't
    # yet been sent count as well as packets marked as needing resend
    # the oldest un-acked packet in the send queue is seq_nr - cur_window_packets
    curWindowPackets: uint16

    # out going buffer for all send packets
    outBuffer: GrowableCircularBuffer[Packet]

    # incoming buffer for out of order packets
    inBuffer: GrowableCircularBuffer[Packet]

  UtpSocketsContainerRef = ref object
    sockets: Table[UtpSocketKey, UtpSocket]

  AckResult = enum
    PacketAcked, PacketAlreadyAcked, PacketNotSentYet

  # For now utp protocol is tied to udp transport, but ultimatly we would like to
  # abstract underlying transport to be able to run utp over udp, discoveryv5 or
  # maybe some test transport
  UtpProtocol* = ref object
    transport: DatagramTransport
    activeSockets: UtpSocketsContainerRef
    rng*: ref BrHmacDrbgContext

proc new(T: type UtpSocketsContainerRef): T =
  UtpSocketsContainerRef(sockets: initTable[UtpSocketKey, UtpSocket]())

proc init(T: type UtpSocketKey, remoteAddress: TransportAddress, rcvId: uint16): T =
  UtpSocketKey(remoteAddress: remoteAddress, rcvId: rcvId)

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
  let initialSeqNr = randUint16(rng)
  UtpSocket(
    remoteAddress: to,
    state: SynSent,
    connectionIdRcv: rcvConnectionId,
    connectionIdSnd: sndConnectionId,
    seqNr: initialSeqNr,
    connectionFuture: newFuture[UtpSocket](),
    outBuffer: GrowableCircularBuffer[Packet].init(),
    inBuffer: GrowableCircularBuffer[Packet].init()
  )

proc initIncomingSocket(to: TransportAddress, connectionId: uint16, ackNr: uint16, rng: var BrHmacDrbgContext): UtpSocket =
  let initialSeqNr = randUint16(rng)
  UtpSocket(
    remoteAddress: to,
    state: SynRecv,
    connectionIdRcv: connectionId + 1,
    connectionIdSnd: connectionId,
    seqNr: initialSeqNr,
    ackNr: ackNr,
    connectionFuture: newFuture[UtpSocket](),
    outBuffer: GrowableCircularBuffer[Packet].init(),
    inBuffer: GrowableCircularBuffer[Packet].init()
  )

proc getAckPacket(socket: UtpSocket): Packet =
  ackPacket(socket.seqNr, socket.connectionIdSnd, socket.ackNr, 1048576)

proc ackPacket(socket: UtpSocket, seqNr: uint16): AckResult =
  let packetOpt = socket.outBuffer.get(seqNr)
  if packetOpt.isSome():
    let packet = packetOpt.get()
    # TODO Add number of transmision to each packet to track which packet was sent
    # how many times, and handle here case when we try to ack packet which was not
    # sent yet
    socket.outBuffer.delete(seqNr)
    # TODO Update estimates about roundtrip time, when we are acking packed which
    # acked without re sends
    PacketAcked
  else:
    # the packet has already been acked (or not sent)
    PacketAlreadyAcked

proc ackPackets(socket: UtpSocket, nrPacketsToAck: uint16) = 
  var i = 0
  while i < int(nrPacketsToack):
    let result = socket.ackPacket(socket.seqNr - socket.curWindowPackets)
    case result
    of PacketAcked:
      dec socket.curWindowPackets
    of PacketAlreadyAcked:
      dec socket.curWindowPackets
    of PacketNotSentYet:
      debug "Tried to ack packed which was not sent yet"
      break

    inc i

proc getSocketKey(socket: UtpSocket): UtpSocketKey =
  UtpSocketKey.init(socket.remoteAddress, socket.connectionIdRcv)

proc initSynPacket(socket: UtpSocket): seq[byte] =
  assert(socket.state == SynSent)
  let packet = synPacket(socket.seqNr, socket.connectionIdRcv, 1048576)
  socket.outBuffer.ensureSize(socket.seqNr, socket.curWindowPackets)
  socket.outBuffer.put(socket.seqNr, packet)
  inc socket.seqNr
  inc socket.curWindowPackets
  encodePacket(packet)

proc isConnected*(socket: UtpSocket): bool =
  socket.state == Connected

# Check how many packets are still in the out going buffer, usefull for tests or
# debugging.
# It throws assertion error when number of elements in buffer do not equal kept counter
proc numPacketsInOutGoingBuffer*(socket: UtpSocket): int =
  var num = 0
  for e in socket.outBuffer.items():
    if e.isSome():
      inc num
  assert(num == int(socket.curWindowPackets))
  num

# TODO not implemented
# for now just log incoming packets
proc processPacket(prot: UtpProtocol, p: Packet, sender: TransportAddress) =
  notice "Received packet ", packet = p
  let socketKey = UtpSocketKey.init(sender, p.header.connectionId)
  let maybeSocket = prot.activeSockets.getUtpSocket(socketKey)
  let pkSeqNr = p.header.seqNr
  let pkAckNr = p.header.ackNr
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
      # acks is the number of packets that was acked, in normal case - no selective
      # acks, no losses, no resends, it will usually be equal to 1
      let acks = pkAckNr - (socket.seqNr - 1 - socket.curWindowPackets)
      socket.ackPackets(acks)

      if (socket.state == SynSent):
        socket.state = Connected
        # TODO reference implementation sets ackNr (p.header.seqNr - 1), although
        # spec mention that it should be equal p.header.seqNr. For now follow the
        # reference impl to be compatible with it. Later investigate trin compatibility.
        socket.ackNr = p.header.seqNr - 1
        # In case of SynSent complate the future as last thing to make sure user of libray will
        # receive socket in correct state
        socket.connectionFuture.complete(socket)

        # number of packets past the expected
        # ack_nr is the last acked, seq_nr is the
        # current. Subtracring 1 makes 0 mean "this is the next expected packet"
        let pastExpected = pkSeqNr - socket.ackNr - 1

        # TODO to finish handhske we should respond with ST_DATA packet, without it
        # socket is left in half-open state.
        # Actual reference implementation waits for user to send data, as it assumes
        # existence of application level handshake over utp. We may need to modify this
        # to automaticly send ST_DATA .
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
      prot.activeSockets.registerUtpSocket(incomingSocket.getSocketKey(), incomingSocket)
      let encodedAck= encodePacket(incomingSocket.getAckPacket())
      # TODO sending should be done from UtpSocket context
      discard prot.transport.sendTo(sender, encodedAck)
      notice "Received ST_SYN and socket is not known"
    else:
      # TODO not implemented
      notice "Received not ST_SYN and socket is not know"

# Connect to provided address
# Reference implementation: https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L2732
# TODO not implemented
proc connectTo*(p: UtpProtocol, address: TransportAddress): Future[UtpSocket] =
  let socket = initOutgoingSocket(address, p.rng[])
  p.activeSockets.registerUtpSocket(socket.getSocketKey(), socket)
  let synEncoded = socket.initSynPacket()
  notice "Sending packet", packet = synEncoded
  # TODO add callback to handle errors and cancellation i.e unregister socket on
  # send error and finish connection future with failure
  # sending should be done from UtpSocketContext
  discard p.transport.sendTo(address, synEncoded)
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
