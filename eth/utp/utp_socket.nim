# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/sugar,
  chronos, chronicles, bearssl,
  ./growable_buffer,
  ./packets

logScope:
  topics = "utp_socket"

type
  ConnectionState = enum
    SynSent,
    SynRecv,
    Connected,
    ConnectedFull,
    Reset,
    Destroy

  ConnectionDirection = enum
   Outgoing, Incoming

  UtpSocketKey*[A] = object
    remoteAddress*: A
    rcvId*: uint16
  
  OutgoingPacket = object
    packetBytes: seq[byte]
    transmissions: uint16
    needResend: bool
    timeSent: Moment

  AckResult = enum
    PacketAcked, PacketAlreadyAcked, PacketNotSentYet

  # Socket callback to send data to remote peer
  SendCallback*[A] = proc (to: A, data: seq[byte]): Future[void] {.gcsafe, raises: [Defect]}

  SocketConfig* = object
    # This is configurable (in contrast to reference impl), as with standard 2 syn resends 
    # default timeout set to 3seconds and doubling of timeout with each re-send, it
    # means that initial connection would timeout after 21s, which seems rather long
    initialSynTimeout*: Duration

    # Number of resend re-tries of each data packet, before daclaring connection
    # failed
    dataResendsBeforeFailure*: uint16

  UtpSocket*[A] = ref object
    remoteAddress*: A
    state: ConnectionState
    direction: ConnectionDirection
    socketConfig: SocketConfig

    # Connection id for packets we receive
    connectionIdRcv: uint16
    # Connection id for packets we send
    connectionIdSnd: uint16
    # Sequence number for the next packet to be sent.
    seqNr: uint16
    # All seq number up to this havve been correctly acked by us
    ackNr: uint16
    
    # Should be completed after succesful connection to remote host or after timeout
    # for the first syn packet
    connectionFuture: Future[void]
    
    # the number of packets in the send queue. Packets that haven't
    # yet been sent count as well as packets marked as needing resend
    # the oldest un-acked packet in the send queue is seq_nr - cur_window_packets
    curWindowPackets: uint16

    # out going buffer for all send packets
    outBuffer: GrowableCircularBuffer[OutgoingPacket]

    # incoming buffer for out of order packets
    inBuffer: GrowableCircularBuffer[Packet]

    # Number of packets waiting in reorder buffer
    reorderCount: uint16

    # current retransmit Timeout used to calculate rtoTimeout
    retransmitTimeout: Duration
    
    # calculated round trip time during communication with remote peer
    rtt: Duration
    # calculated round trip time variance
    rttVar: Duration
    # Round trip timeout dynamicaly updated based on acks received from remote
    # peer
    rto: Duration

    # RTO timeout will happen when currenTime > rtoTimeout
    rtoTimeout: Moment

    # rcvBuffer 
    buffer: AsyncBuffer

    # loop called every 500ms to check for on going timeout status
    checkTimeoutsLoop: Future[void]

    # number on consecutive re-transsmisions
    retransmitCount: uint32

    # Event which will complete whenever socket gets in destory statate
    closeEvent: AsyncEvent

    # All callback to be called whenever socket gets in destroy state
    closeCallbacks: seq[Future[void]]

    # socket identifier
    socketKey*: UtpSocketKey[A]

    send: SendCallback[A]

  # User driven call back to be called whenever socket is permanently closed i.e
  # reaches destroy state
  SocketCloseCallback* = proc (): void {.gcsafe, raises: [Defect].}

  ConnectionError* = object of CatchableError

const
  # Maximal number of payload bytes per packet. Total packet size will be equal to
  # mtuSize + sizeof(header) = 600 bytes
  # TODO for now it is just some random value. Ultimatly this value should be dynamically
  # adjusted based on traffic.
  mtuSize = 580

  # How often each socket check its different on going timers
  checkTimeoutsLoopInterval = milliseconds(500)

  # Defualt initial timeout for first Syn packet 
  defaultInitialSynTimeout = milliseconds(3000)

  # Initial timeout to receive first Data data packet after receiving initial Syn
  # packet. (TODO it should only be set when working over udp)
  initialRcvRetransmitTimeout = milliseconds(10000)

  # Number of times each data packet will be resend before declaring connection
  # dead. 4 is taken from reference implementation
  defaultDataResendsBeforeFailure = 4'u16

  reorderBufferMaxSize = 1024

proc init*[A](T: type UtpSocketKey, remoteAddress: A, rcvId: uint16): T =
  UtpSocketKey[A](remoteAddress: remoteAddress, rcvId: rcvId)

proc init(T: type OutgoingPacket, packetBytes: seq[byte], transmissions: uint16, needResend: bool, timeSent: Moment = Moment.now()): T =
  OutgoingPacket(
    packetBytes: packetBytes,
    transmissions: transmissions,
    needResend: needResend,
    timeSent: timeSent
  )

proc init*(
  T: type SocketConfig, 
  initialSynTimeout: Duration = defaultInitialSynTimeout,
  dataResendsBeforeFailure: uint16 = defaultDataResendsBeforeFailure
  ): T =
  SocketConfig(
    initialSynTimeout: initialSynTimeout,
    dataResendsBeforeFailure: dataResendsBeforeFailure
  )

proc registerOutgoingPacket(socket: UtpSocket, oPacket: OutgoingPacket) =
  ## Adds packet to outgoing buffer and updates all related fields
  socket.outBuffer.ensureSize(socket.seqNr, socket.curWindowPackets)
  socket.outBuffer.put(socket.seqNr, oPacket)
  inc socket.seqNr
  inc socket.curWindowPackets

proc sendData(socket: UtpSocket, data: seq[byte]): Future[void] =
  socket.send(socket.remoteAddress, data)

proc sendAck(socket: UtpSocket): Future[void] =
  ## Creates and sends ack, based on current socket state. Acks are different from
  ## other packets as we do not track them in outgoing buffet

  let ackPacket = ackPacket(socket.seqNr, socket.connectionIdSnd, socket.ackNr, 1048576)
  socket.sendData(encodePacket(ackPacket))

proc sendSyn(socket: UtpSocket): Future[void] =
  doAssert(socket.state == SynSent , "syn can only be send when in SynSent state")
  let packet = synPacket(socket.seqNr, socket.connectionIdRcv, 1048576)
  notice "Sending syn packet packet", packet = packet
  # set number of transmissions to 1 as syn packet will be send just after
  # initiliazation
  let outgoingPacket = OutgoingPacket.init(encodePacket(packet), 1, false)
  socket.registerOutgoingPacket(outgoingPacket)
  socket.sendData(outgoingPacket.packetBytes)

# Should be called before sending packet
proc setSend(p: var OutgoingPacket): seq[byte] =
  inc p.transmissions
  p.needResend = false
  p.timeSent = Moment.now()
  return p.packetBytes

proc flushPackets(socket: UtpSocket) {.async.} =
  var i: uint16 = socket.seqNr - socket.curWindowPackets
  while i != socket.seqNr:
    # sending only packet which were not transmitted yet or need a resend
    let shouldSendPacket = socket.outBuffer.exists(i, (p: OutgoingPacket) => (p.transmissions == 0 or p.needResend == true))
    if (shouldSendPacket):
      let toSend = setSend(socket.outBuffer[i])
      await socket.sendData(toSend)
    inc i

proc markAllPacketAsLost(s: UtpSocket) =
  var i = 0'u16
  while i < s.curWindowPackets:

    let packetSeqNr = s.seqNr - 1 - i
    if (s.outBuffer.exists(packetSeqNr, (p: OutgoingPacket) => p. transmissions > 0 and p.needResend == false)):
      s.outBuffer[packetSeqNr].needResend = true
      # TODO here we should also decrease number of bytes in flight. This should be
      # done when working on congestion control

    inc i

proc isOpened(socket:UtpSocket): bool =
  return (
    socket.state == SynRecv or 
    socket.state == SynSent or 
    socket.state == Connected or 
    socket.state == ConnectedFull
  )

proc shouldDisconnectFromFailedRemote(socket: UtpSocket): bool = 
  (socket.state == SynSent and socket.retransmitCount >= 2) or 
  (socket.retransmitCount >= socket.socketConfig.dataResendsBeforeFailure)

proc checkTimeouts(socket: UtpSocket) {.async.} =
  let currentTime = Moment.now()
  # flush all packets which needs to be re-send
  if socket.state != Destroy:
    await socket.flushPackets()

  if socket.isOpened():
    if (currentTime > socket.rtoTimeout):
      
      # TODO add handling of probe time outs. Reference implemenation has mechanism
      # of sending probes to determine mtu size. Probe timeouts do not count to standard
      # timeouts calculations

      # client initiated connections, but did not send following data packet in rto
      # time. TODO this should be configurable
      if (socket.state == SynRecv):
        socket.state = Destroy
        socket.closeEvent.fire()
        return
      
      if socket.shouldDisconnectFromFailedRemote():
        if socket.state == SynSent and (not socket.connectionFuture.finished()):
          # TODO standard stream interface result in failed future in case of failed connections,
          # but maybe it would be more clean to use result
          socket.connectionFuture.fail(newException(ConnectionError, "Connection to peer timed out"))

        socket.state = Destroy
        socket.closeEvent.fire()
        return

      let newTimeout = socket.retransmitTimeout * 2
      socket.retransmitTimeout = newTimeout
      socket.rtoTimeout = currentTime + newTimeout
      
      # TODO Add handling of congestion control 

      # This will have much more sense when we will add handling of selective acks
      # as then every selecivly acked packet restes timeout timer and removes packet
      # from out buffer.
      markAllPacketAsLost(socket)
      
      # resend oldest packet if there are some packets in flight
      if (socket.curWindowPackets > 0):
        notice "resending oldest packet in outBuffer"
        inc socket.retransmitCount
        let oldestPacketSeqNr = socket.seqNr - socket.curWindowPackets
        # TODO add handling of fast timeout

        doAssert(
          socket.outBuffer.get(oldestPacketSeqNr).isSome(),
          "oldest packet should always be available when there is data in flight"
        )
        let dataToSend = setSend(socket.outBuffer[oldestPacketSeqNr])
        await socket.sendData(dataToSend)

    # TODO add sending keep alives when necessary

proc checkTimeoutsLoop(s: UtpSocket) {.async.} =
  ## Loop that check timeoutsin the socket.
  try:
    while true:
      await sleepAsync(checkTimeoutsLoopInterval)
      await s.checkTimeouts()
  except CancelledError:
    trace "checkTimeoutsLoop canceled"

proc startTimeoutLoop(s: UtpSocket) =
  s.checkTimeoutsLoop = checkTimeoutsLoop(s)

proc new[A](
  T: type UtpSocket[A],
  to: A,
  snd: SendCallback[A],
  state: ConnectionState,
  cfg: SocketConfig,
  direction: ConnectionDirection,
  rcvId: uint16,
  sndId: uint16,
  initialSeqNr: uint16,
  initialAckNr: uint16
): T =
  let initialTimeout = 
    if direction == Outgoing:
      cfg.initialSynTimeout
    else :
      initialRcvRetransmitTimeout

  T(
    remoteAddress: to,
    state: state,
    direction: direction,
    socketConfig: cfg,
    connectionIdRcv: rcvId,
    connectionIdSnd: sndId,
    seqNr: initialSeqNr,
    ackNr: initialAckNr,
    connectionFuture: newFuture[void](),
    outBuffer: GrowableCircularBuffer[OutgoingPacket].init(),
    inBuffer: GrowableCircularBuffer[Packet].init(),
    retransmitTimeout: initialTimeout,
    rtoTimeout: Moment.now() + initialTimeout,
    # Initial timeout values taken from reference implemntation
    rtt: milliseconds(0),
    rttVar: milliseconds(800),
    rto: milliseconds(3000),
    # Default 1MB buffer
    # TODO add posibility to configure buffer size
    buffer: AsyncBuffer.init(1024 * 1024),
    closeEvent: newAsyncEvent(),
    closeCallbacks: newSeq[Future[void]](),
    socketKey: UtpSocketKey.init(to, rcvId),
    send: snd
  )

proc initOutgoingSocket*[A](
  to: A,
  snd: SendCallback[A],
  cfg: SocketConfig,
  rng: var BrHmacDrbgContext
): UtpSocket[A] =
  # TODO handle possible clashes and overflows
  let rcvConnectionId = randUint16(rng)
  let sndConnectionId = rcvConnectionId + 1
  let initialSeqNr = randUint16(rng)

  UtpSocket[A].new(
    to,
    snd,
    SynSent,
    cfg,
    Outgoing,
    rcvConnectionId,
    sndConnectionId,
    initialSeqNr,
    # Initialy ack nr is 0, as we do not know remote inital seqnr
    0
  )

proc initIncomingSocket*[A](
  to: A,
  snd: SendCallback[A],
  cfg: SocketConfig,
  connectionId: uint16,
  ackNr: uint16,
  rng: var BrHmacDrbgContext
): UtpSocket[A] =
  let initialSeqNr = randUint16(rng)

  UtpSocket[A].new(
    to,
    snd,
    SynRecv,
    cfg,
    Incoming,
    connectionId + 1,
    connectionId,
    initialSeqNr,
    ackNr
  )

proc startOutgoingSocket*(socket: UtpSocket): Future[void] {.async.} =
  doAssert(socket.state == SynSent)
  # TODO add callback to handle errors and cancellation i.e unregister socket on
  # send error and finish connection future with failure
  # sending should be done from UtpSocketContext
  await socket.sendSyn()
  socket.startTimeoutLoop()

proc waitFotSocketToConnect*(socket: UtpSocket): Future[void] {.async.} =
  await socket.connectionFuture
  
proc startIncomingSocket*(socket: UtpSocket) {.async.} =
  doAssert(socket.state == SynRecv)
  # Make sure ack was flushed before movig forward
  await socket.sendAck()
  socket.startTimeoutLoop()

proc isConnected*(socket: UtpSocket): bool =
  socket.state == Connected or socket.state == ConnectedFull

proc close*(s: UtpSocket) =
  # TODO Rething all this when working on FIN and RESET packets and proper handling
  # of resources
  s.checkTimeoutsLoop.cancel()
  s.closeEvent.fire()

proc setCloseCallback(s: UtpSocket, cb: SocketCloseCallback) {.async.} =
  ## Set callback which will be called whenever the socket is permanently closed
  try:
    await s.closeEvent.wait()
    cb()
  except CancelledError:
    trace "closeCallback cancelled"

proc registerCloseCallback*(s: UtpSocket, cb: SocketCloseCallback) =
  s.closeCallbacks.add(s.setCloseCallback(cb))

proc max(a, b: Duration): Duration =
  if (a > b):
    a
  else:
    b

proc updateTimeouts(socket: UtpSocket, timeSent: Moment, currentTime: Moment) =
  ## Update timeouts according to spec:
  ## delta = rtt - packet_rtt
  ## rtt_var += (abs(delta) - rtt_var) / 4;
  ## rtt += (packet_rtt - rtt) / 8;
  
  let packetRtt = currentTime - timeSent

  if (socket.rtt.isZero):
    socket.rtt = packetRtt
    socket.rttVar = packetRtt div 2
  else:
    let packetRttMicro = packetRtt.microseconds()
    let rttVarMicro = socket.rttVar.microseconds()
    let rttMicro = socket.rtt.microseconds()

    let delta = rttMicro - packetRttMicro

    let newVar = microseconds(rttVarMicro + (abs(delta) - rttVarMicro) div 4)
    let newRtt = socket.rtt - (socket.rtt div 8) + (packetRtt div 8)

    socket.rttVar = newVar
    socket.rtt = newRtt
  
  # according to spec it should be: timeout = max(rtt + rtt_var * 4, 500)
  # but usually spec lags after implementation so milliseconds(1000) is used
  socket.rto = max(socket.rtt + (socket.rttVar * 4), milliseconds(1000))

proc ackPacket(socket: UtpSocket, seqNr: uint16): AckResult =
  let packetOpt = socket.outBuffer.get(seqNr)
  if packetOpt.isSome():
    let packet = packetOpt.get()

    if packet.transmissions == 0:
      # according to reference impl it can happen when we get an ack_nr that 
      # does not exceed what we have stuffed into the outgoing buffer, 
      # but does exceed what we have sent
      # TODO analyze if this case can happen with our impl
      return PacketNotSentYet
    
    let currentTime = Moment.now()

    socket.outBuffer.delete(seqNr)

    # from spec: The rtt and rtt_var is only updated for packets that were sent only once. 
    # This avoids problems with figuring out which packet was acked, the first or the second one.
    # it is standard solution to retransmission ambiguity problem
    if packet.transmissions == 1:
      socket.updateTimeouts(packet.timeSent, currentTime)

    socket.retransmitTimeout = socket.rto
    socket.rtoTimeout = currentTime + socket.rto

    # TODO Add handlig of decreasing bytes window, whenadding handling of congestion control

    socket.retransmitCount = 0
    PacketAcked
  else:
    # the packet has already been acked (or not sent)
    PacketAlreadyAcked

proc ackPackets(socket: UtpSocket, nrPacketsToAck: uint16) =
  ## Ack packets in outgoing buffer based on ack number in the received packet
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

proc initializeAckNr(socket: UtpSocket, packetSeqNr: uint16) =
  if (socket.state == SynSent):
    socket.ackNr = packetSeqNr - 1

# TODO at socket level we should handle only FIN/DATA/ACK packets. Refactor to make
# it enforcable by type system
# TODO re-think synchronization of this procedure, as each await inside gives control
# to scheduler which means there could be potentialy several processPacket procs
# running
proc processPacket*(socket: UtpSocket, p: Packet) {.async.} =
  ## Updates socket state based on received packet, and sends ack when necessary.
  ## Shoyuld be called in main packet receiving loop
  let pkSeqNr = p.header.seqNr
  let pkAckNr = p.header.ackNr

  socket.initializeAckNr(pkSeqNr)

  # number of packets past the expected
  # ack_nr is the last acked, seq_nr is the
  # current. Subtracring 1 makes 0 mean "this is the next expected packet"
  let pastExpected = pkSeqNr - socket.ackNr - 1

  # acks is the number of packets that was acked, in normal case - no selective
  # acks, no losses, no resends, it will usually be equal to 1
  # we can calculate it here and not only for ST_STATE packet, as each utp
  # packet has info about remote side last acked packet.
  var acks = pkAckNr - (socket.seqNr - 1 - socket.curWindowPackets)

  if acks > socket.curWindowPackets:
    # this case happens if the we already received this ack nr
    acks = 0
  
  # If packet is totally of the mark short circout the processing
  if pastExpected >= reorderBufferMaxSize:
    notice "Received packet is totally of the mark"
    return

  socket.ackPackets(acks)

  case p.header.pType
    of ST_DATA:
      # To avoid amplification attacks, server socket is in SynRecv state until
      # it receices first data transfer
      # https://www.usenix.org/system/files/conference/woot15/woot15-paper-adamsky.pdf
      # TODO when intgrating with discv5 this need to be configurable
      if (socket.state == SynRecv):
        socket.state = Connected

      notice "Received ST_DATA on known socket"

      if (pastExpected == 0):
        # we are getting in order data packet, we can flush data directly to the incoming buffer
        await upload(addr socket.buffer, unsafeAddr p.payload[0], p.payload.len())

        # Bytes have been passed to upper layer, we can increase number of last 
        # acked packet
        inc socket.ackNr

        # check if the following packets are in reorder buffer
        while true:
          if socket.reorderCount == 0:
            break
          
          # TODO Handle case when we have reached eof becouse of fin packet
          let nextPacketNum = socket.ackNr + 1
          let maybePacket = socket.inBuffer.get(nextPacketNum)
          
          if maybePacket.isNone():
            break
          
          let packet = maybePacket.unsafeGet()

          await upload(addr socket.buffer, unsafeAddr packet.payload[0], packet.payload.len())

          socket.inBuffer.delete(nextPacketNum)

          inc socket.ackNr
          dec socket.reorderCount

        # TODO for now we just schedule concurrent task with ack sending. It may
        # need improvement, as with this approach there is no direct control over
        # how many concurrent tasks there are and how to cancel them when socket
        # is closed
        asyncSpawn socket.sendAck()
      else:
        # TODO Handle case when out of order is out of eof range
        notice "Got out of order packet"

        # growing buffer before checking the packet is already there to avoid 
        # looking at older packet due to indices wrap aroud
        socket.inBuffer.ensureSize(pkSeqNr + 1, pastExpected + 1)

        if (socket.inBuffer.get(pkSeqNr).isSome()):
          notice "packet already received"
        else:
          socket.inBuffer.put(pkSeqNr, p)
          inc socket.reorderCount
          notice "added out of order packet in reorder buffer"
          # TODO for now we do not sent any ack as we do not handle selective acks
          # add sending of selective acks
    of ST_FIN:
      # TODO not implemented
      notice "Received ST_FIN on known socket"
    of ST_STATE:
      notice "Received ST_STATE on known socket"

      if (socket.state == SynSent and (not socket.connectionFuture.finished())):
        socket.state = Connected
        # TODO reference implementation sets ackNr (p.header.seqNr - 1), although
        # spec mention that it should be equal p.header.seqNr. For now follow the
        # reference impl to be compatible with it. Later investigate trin compatibility.
        socket.ackNr = p.header.seqNr - 1
        # In case of SynSent complate the future as last thing to make sure user of libray will
        # receive socket in correct state
        socket.connectionFuture.complete()
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

template readLoop(body: untyped): untyped =
  while true:
    # TODO error handling
    let (consumed, done) = body
    socket.buffer.shift(consumed)
    if done:
      break
    else:
      # TODO add condition to handle socket closing
      await socket.buffer.wait()

proc getPacketSize(socket: UtpSocket): int =
  # TODO currently returning constant, ultimatly it should be bases on mtu estimates
  mtuSize

proc resetSendTimeout(socket: UtpSocket) =
  socket.retransmitTimeout = socket.rto
  socket.rtoTimeout = Moment.now() + socket.retransmitTimeout

proc write*(socket: UtpSocket, data: seq[byte]): Future[int] {.async.} = 
  var bytesWritten = 0
  # TODO 
  # Handle different socket state i.e do not write when socket is full or not
  # connected
  # Handle growing of send window

  if len(data) == 0:
    return bytesWritten

  if socket.curWindowPackets == 0:
    socket.resetSendTimeout()

  let pSize = socket.getPacketSize()
  let endIndex = data.high()
  var i = 0
  while i <= data.high:
    let lastIndex = i + pSize - 1
    let lastOrEnd = min(lastIndex, endIndex)
    let dataSlice = data[i..lastOrEnd]
    let dataPacket = dataPacket(socket.seqNr, socket.connectionIdSnd, socket.ackNr, 1048576, dataSlice)
    socket.registerOutgoingPacket(OutgoingPacket.init(encodePacket(dataPacket), 0, false))
    bytesWritten = bytesWritten + len(dataSlice)
    i = lastOrEnd + 1
  await socket.flushPackets()
  return bytesWritten

proc read*(socket: UtpSocket, n: Natural): Future[seq[byte]] {.async.}=
  ## Read all bytes `n` bytes from socket ``socket``.
  ##
  ## This procedure allocates buffer seq[byte] and return it as result.
  var bytes = newSeq[byte]()

  if n == 0:
    return bytes

  readLoop():
    # TODO Add handling of socket closing
    let count = min(socket.buffer.dataLen(), n - len(bytes))
    bytes.add(socket.buffer.buffer.toOpenArray(0, count - 1))
    (count, len(bytes) == n)

  return bytes

# Check how many packets are still in the out going buffer, usefull for tests or
# debugging.
# It throws assertion error when number of elements in buffer do not equal kept counter
proc numPacketsInOutGoingBuffer*(socket: UtpSocket): int =
  var num = 0
  for e in socket.outBuffer.items():
    if e.isSome():
      inc num
  doAssert(num == int(socket.curWindowPackets))
  num

# Check how many packets are still in the reorder buffer, usefull for tests or
# debugging.
# It throws assertion error when number of elements in buffer do not equal kept counter
proc numPacketsInReordedBuffer*(socket: UtpSocket): int =
  var num = 0
  for e in socket.inBUffer.items():
    if e.isSome():
      inc num
  doAssert(num == int(socket.reorderCount))
  num
