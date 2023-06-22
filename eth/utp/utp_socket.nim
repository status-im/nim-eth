# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sugar, deques],
  chronos, chronicles, metrics,
  stew/[results, bitops2],
  ./growable_buffer,
  ./packets,
  ./ledbat_congestion_control,
  ./delay_histogram,
  ./utp_utils,
  ./clock_drift_calculator

export
  chronicles

logScope:
  topics = "eth utp utp_socket"

type
  ConnectionState* = enum
    SynSent,
    SynRecv,
    Connected,
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
    payloadLength: uint32
    timeSent: Moment

  AckResult = enum
    PacketAcked, PacketAlreadyAcked, PacketNotSentYet

  # Socket callback to send data to remote peer
  SendCallback*[A] =
    proc (to: A, data: seq[byte]): Future[void] {.gcsafe, raises: []}

  SocketConfig* = object
    # This is configurable (in contrast to reference impl), as with standard 2
    # SYN resends, the default timeout of 3 seconds and the doubling of the
    # timeout with each resend, it means that the initial connection would
    # timeout only after 21s, which seems rather long.
    initialSynTimeout*: Duration

    # Number of resend retries of each data packet, before declaring the
    # connection as failed.
    dataResendsBeforeFailure*: uint16

    # Maximal size of receive buffer in bytes
    optRcvBuffer*: uint32

    # Maximal size of send buffer in bytes
    optSndBuffer*: uint32

    # If set to some(`Duration`), the incoming socket will be initialized in
    # `SynRecv` state and the remote peer will have `Duration` to transfer data
    # to move the socket in `Connected` state.
    # If set to none, the incoming socket will immediately be set to `Connected`
    # state and will be able to transfer data.
    incomingSocketReceiveTimeout*: Option[Duration]

    # Timeout after which the send window will be reset to its minimal value
    # after it dropped to zero.
    # i.e when a packet is received from a peer with `wndSize` set to 0.
    remoteWindowResetTimeout*: Duration

    # Size of reorder buffer calculated as fraction of optRcvBuffer
    maxSizeOfReorderBuffer: uint32

    # Maximal number of payload bytes per data packet. Total packet size will be
    # equal to payloadSize + 20 (size of header of data packet).
    # TODO: for now we enable only static configuration of packet sizes. In the
    # future it would be nice to add option which enables automatic packet size
    # discovery based on traffic.
    payloadSize*: uint32

    # Maximal number of open uTP connections. When hit, no more incoming
    # connections will be allowed, but it will still be possible to open new
    # outgoing uTP connections.
    maxNumberOfOpenConnections*: int

  WriteErrorType* = enum
    SocketNotWriteable,
    FinSent

  WriteError* = object
    case kind*: WriteErrorType
    of SocketNotWriteable:
      currentState*: ConnectionState
    of FinSent:
      discard

  WriteResult* = Result[int, WriteError]

  WriteRequestType = enum
   Data, Close

  WriteRequest = object
    case kind: WriteRequestType
    of Data:
      data: seq[byte]
      writer: Future[WriteResult]
    of Close:
      discard

  SocketEventType = enum
    NewPacket, CheckTimeouts, CloseReq, WriteReq, ReadReqType

  ReadReq = object
    bytesToRead: int
    bytesAvailable: seq[uint8]
    reader: Future[seq[uint8]]

  ReadResult = enum
    ReadCancelled, ReadFinished, ReadNotFinished, SocketAlreadyFinished

  SocketEvent = object
    case kind: SocketEventType
    of CheckTimeouts:
      discard
    of NewPacket:
      packet: Packet
    of CloseReq:
      discard
    of WriteReq:
      data: seq[byte]
      writer: Future[WriteResult]
    of ReadReqType:
      readReq: ReadReq

  UtpSocket*[A] = ref object
    remoteAddress*: A
    state: ConnectionState
    direction: ConnectionDirection
    socketConfig: SocketConfig

    # Connection id for received packets
    connectionIdRcv*: uint16
    # Connection id for send packets
    connectionIdSnd*: uint16
    # Sequence number for the next packet to be sent.
    seqNr: uint16
    # All sequence numbers up to this have been correctly acked by us.
    ackNr: uint16

    # Should be completed after successful connection to remote host or after
    # timeout for the first SYN packet.
    connectionFuture: Future[void]

    # The number of packets in the send queue. Packets that haven't
    # been sent yet and packets marked as needing to be resend count.
    # The oldest un-acked packet in the send queue is seq_nr - cur_window_packets
    curWindowPackets: uint16

    # outgoing buffer for all send packets
    outBuffer: GrowableCircularBuffer[OutgoingPacket]

    # current number of bytes in send buffer
    outBufferBytes: uint32

    # current number of bytes in flight
    currentWindow: uint32

    # current max window broadcasted by remote peer
    maxRemoteWindow: uint32

    # current max window calculated by ledbat congestion controller
    maxWindow: uint32

    # incoming buffer for out of order packets
    inBuffer: GrowableCircularBuffer[Packet]

    # number of bytes in reorder buffer
    inBufferBytes: uint32

    # Number of packets waiting in reorder buffer
    reorderCount: uint16

    # current retransmit Timeout used to calculate rtoTimeout
    retransmitTimeout: Duration

    # calculated round trip time during communication with remote peer
    rtt: Duration
    # calculated round trip time variance
    rttVar: Duration
    # Round trip timeout dynamically updated based on acks received from remote
    # peer
    rto: Duration

    # RTO timeout happens when currentTime > rtoTimeout
    rtoTimeout: Moment

    # rcvBuffer
    rcvBuffer: seq[byte]

    # current size of rcv buffer
    offset: int

    # readers waiting for data
    pendingReads: Deque[ReadReq]

    # loop called every 500ms to check for timeouts
    checkTimeoutsLoop: Future[void]

    # number on consecutive re-transmissions
    retransmitCount: uint32

    # Event which will complete whenever socket gets in destroy state
    closeEvent: AsyncEvent

    # All callback to be called whenever socket gets in destroy state
    closeCallbacks: seq[Future[void]]

    # socket is closed for reading
    readShutdown: bool

    # we sent out fin packet
    finSent: bool

    # we requested to close the socket by sending fin packet
    sendFinRequested: bool

    # have our fin been acked
    finAcked: bool

    # have we received remote fin
    gotFin: bool

    # have we reached remote fin packet
    reachedFin: bool

    # sequence number of remoted fin packet
    eofPktNr: uint16

    pendingWrites: Deque[WriteRequest]

    eventQueue: AsyncQueue[SocketEvent]

    eventLoop: Future[void]

    # timer which is started when peer max window drops below current packet size
    zeroWindowTimer: Option[Moment]

    # last measured delay between current local timestamp and remote sent
    # timestamp, in microseconds.
    replayMicro: uint32

    # indicator if socket is in in slow-start (exponential growth) phase
    slowStart: bool

    # indicator if socket is in fast time-out mode, i.e will resend oldest
    # not ACK'ed packet when newer packet is received.
    fastTimeout: bool

    # Sequence number of the next packet we are allowed to fast-resend. This is
    # necessary to make sure we only fast resend once per packet
    fastResendSeqNr: uint16

    # last time we decreased max window
    lastWindowDecay: Moment

    # counter of duplicate acks
    duplicateAck: uint16

    # the slow-start threshold, in bytes
    slowStartThreshold: uint32

    # history of our delays
    ourHistogram: DelayHistogram

    # history of remote delays
    remoteHistogram: DelayHistogram

    # calculator of drifting between local and remote clocks
    driftCalculator: ClockDriftCalculator

    # socket identifier
    socketKey*: UtpSocketKey[A]

    send: SendCallback[A]

  # User driven callback to be called whenever socket is permanently closed,
  # i.e reaches the destroy state
  SocketCloseCallback* = proc (): void {.gcsafe, raises: [].}

  ConnectionError* = object of CatchableError

  OutgoingConnectionErrorType* = enum
    SocketAlreadyExists, ConnectionTimedOut

  OutgoingConnectionError* = object
    case kind*: OutgoingConnectionErrorType
    of SocketAlreadyExists, ConnectionTimedOut:
      discard

  ConnectionResult*[A] = Result[UtpSocket[A], OutgoingConnectionError]

chronicles.formatIt(UtpSocketKey): $it

const
  # Default maximum size of the data packet payload. With this configuration
  # data packets will have 508 bytes (488 + 20 header).
  # 508 bytes of UDP payload can translate into 576 bytes UDP packet i.e
  # 508 bytes + 60 bytes (max IP header) + 8 bytes (UDP header) = 576 bytes.
  # 576 bytes is defined as minimum reassembly buffer size, i.e the minimum
  # datagram size that any implementation must support.
  # From RFC791: All hosts must be prepared to accept datagrams of up to 576
  # octets (whether they arrive whole or in fragments).
  defaultPayloadSize = 488

  # How often each socket check its different ongoing timers
  checkTimeoutsLoopInterval = milliseconds(500)

  # Default initial timeout for first SYN packet
  defaultInitialSynTimeout = milliseconds(3000)

  # Initial timeout to receive first Data data packet after receiving initial
  # SYN packet.
  defaultRcvRetransmitTimeout = milliseconds(10000)

  # Number of times each data packet will be resend before declaring connection
  # dead. 4 is taken from reference implementation.
  defaultDataResendsBeforeFailure = 4'u16

  # default size of rcv buffer in bytes
  # rationale form C reference impl:
  # 1 MB of receive buffer (i.e. max bandwidth delay product)
  # means that from  a peer with 200 ms RTT, we cannot receive
  # faster than 5 MB/s
  # from a peer with 10 ms RTT, we cannot receive faster than
  # 100 MB/s. This is assumed to be good enough, since bandwidth
  # often is proportional to RTT anyway
  defaultOptRcvBuffer: uint32 = 1024 * 1024

  # rationale from C reference impl:
  # Allow a reception window of at least 3 ack_nrs behind seq_nr
  # A non-SYN packet with an ack_nr difference greater than this is
  # considered suspicious and ignored
  allowedAckWindow*: uint16 = 3

  # Timeout after which the send window will be reset to its minimal value after
  # it dropped lower than our current packet size. i.e when we received a packet
  # from remote peer with `wndSize` set to number <= current packet size.
  defaultResetWindowTimeout = seconds(15)

  reorderBufferMaxSize = 1024

  duplicateAcksBeforeResend = 3

  # minimal time before subsequent window decays
  maxWindowDecay = milliseconds(100)

  # Maximal size of reorder buffer as fraction of optRcvBuffer size.
  # Following semantics apply based on a rcvBuffer set to 1000 bytes:
  #  - if there are already 1000 bytes in rcvBuffer no more bytes will be
  # accepted to reorder buffer
  # - if there are already 500 bytes in reorder buffer, no more bytes will be
  # accepted to it, and only 500 bytes can be accepted to rcvBuffer
  # This way there is always a space in rcvBuffer to fit new data if the
  # reordering happens.
  maxReorderBufferSize = 0.5

  # Default number of of open utp connections
  # - libutp uses 3000
  # - libtorrent uses ~16000
  defaultMaxOpenConnections = 8000

proc init*[A](T: type UtpSocketKey, remoteAddress: A, rcvId: uint16): T =
  UtpSocketKey[A](remoteAddress: remoteAddress, rcvId: rcvId)

proc init(
  T: type OutgoingPacket,
  packetBytes: seq[byte],
  transmissions: uint16,
  needResend: bool,
  payloadLength: uint32,
  timeSent: Moment = getMonoTimestamp().moment): T =
  OutgoingPacket(
    packetBytes: packetBytes,
    transmissions: transmissions,
    needResend: needResend,
    payloadLength: payloadLength,
    timeSent: timeSent
  )

proc init*(
  T: type SocketConfig,
  initialSynTimeout: Duration = defaultInitialSynTimeout,
  dataResendsBeforeFailure: uint16 = defaultDataResendsBeforeFailure,
  optRcvBuffer: uint32 = defaultOptRcvBuffer,
  incomingSocketReceiveTimeout: Option[Duration] = some(defaultRcvRetransmitTimeout),
  remoteWindowResetTimeout: Duration = defaultResetWindowTimeout,
  optSndBuffer: uint32 = defaultOptRcvBuffer,
  payloadSize: uint32 = defaultPayloadSize,
  maxNumberOfOpenConnections: int = defaultMaxOpenConnections
  ): T =
  # Make sure there is always some payload in data packets, and that packets are
  # not to large. With 1480 packet boundary, data packets will have 1500 bytes
  # which seems reasonable.
  doAssert(payloadSize > 0 and payloadSize <= 1480,
    "payloadSize should always be positive number <= 1480")
  # TODO make sure optRcvBuffer is nicely divisible by maxReorderBufferSize
  let reorderBufferSize = uint32(maxReorderBufferSize * float64(optRcvBuffer))
  SocketConfig(
    initialSynTimeout: initialSynTimeout,
    dataResendsBeforeFailure: dataResendsBeforeFailure,
    optRcvBuffer: optRcvBuffer,
    optSndBuffer: optSndBuffer,
    incomingSocketReceiveTimeout: incomingSocketReceiveTimeout,
    remoteWindowResetTimeout: remoteWindowResetTimeout,
    maxSizeOfReorderBuffer: reorderBufferSize,
    payloadSize: payloadSize,
    maxNumberOfOpenConnections: maxNumberOfOpenConnections
  )

# number of bytes which will fit in current send window
proc freeWindowBytes(socket: UtpSocket): uint32 =
  let maxSend = min(socket.maxRemoteWindow, socket.maxWindow)
  if (maxSend <= socket.currentWindow):
    return 0
  else:
    return maxSend - socket.currentWindow

proc getRcvWindowSize(socket: UtpSocket): uint32 =
  let currentDataSize = socket.offset
  if currentDataSize > int(socket.socketConfig.optRcvBuffer):
    0'u32
  else:
    socket.socketConfig.optRcvBuffer - uint32(currentDataSize)

proc registerOutgoingPacket(socket: UtpSocket, oPacket: OutgoingPacket) =
  ## Adds packet to outgoing buffer and updates all related fields
  socket.outBuffer.ensureSize(socket.seqNr, socket.curWindowPackets)
  socket.outBuffer.put(socket.seqNr, oPacket)
  socket.outBufferBytes = socket.outBufferBytes + oPacket.payloadLength
  inc socket.seqNr
  inc socket.curWindowPackets

proc sendData(socket: UtpSocket, data: seq[byte]) =
  let f = socket.send(socket.remoteAddress, data)
  f.callback = proc(data: pointer) {.gcsafe.} =
    if f.failed:
      warn "UTP send failed", msg = f.readError.msg

proc sendPacket(socket: UtpSocket, seqNr: uint16) =
  proc setSend(p: var OutgoingPacket): seq[byte] =
    let timestampInfo = getMonoTimestamp()

    if p.transmissions == 0 or p.needResend:
      socket.currentWindow = socket.currentWindow + p.payloadLength

    inc p.transmissions
    p.needResend = false
    p.timeSent = timestampInfo.moment
    # all bytearrays in outgoing buffer should be properly encoded utp packets
    # so it is safe to directly modify fields
    modifyTimeStampAndAckNr(p.packetBytes, timestampInfo.timestamp, socket.ackNr)

    return p.packetBytes

  socket.sendData(setSend(socket.outBuffer[seqNr]))

proc resetSendTimeout(socket: UtpSocket) =
  socket.retransmitTimeout = socket.rto
  socket.rtoTimeout = getMonoTimestamp().moment + socket.retransmitTimeout

proc flushPackets(socket: UtpSocket) =
  let oldestOutgoingPacketSeqNr = socket.seqNr - socket.curWindowPackets
  var i: uint16 = oldestOutgoingPacketSeqNr
  while i != socket.seqNr:
    # sending only packet which were not transmitted yet or need a resend
    let shouldSendPacket = socket.outBuffer.exists(
      i, (p: OutgoingPacket) => (p.transmissions == 0 or p.needResend == true))
    if (shouldSendPacket):
      if (socket.freeWindowBytes() > 0):
        # this our first send packet reset rto timeout
        if i == oldestOutgoingPacketSeqNr and
            socket.curWindowPackets == 1 and
            socket.outBuffer[i].transmissions == 0:
          socket.resetSendTimeout()

        debug "Flushing packet",
          pkSeqNr = i
        socket.sendPacket(i)
      else:
        debug "Should resend packet during flush but there is no place in send window",
          currentBytesWindow = socket.currentWindow,
          maxRemoteWindow = socket.maxRemoteWindow,
          maxWindow = socket.maxWindow,
          pkSeqNr = i
        # there is no place in send buffer, stop flushing
        return
    inc i

proc markAllPacketAsLost(s: UtpSocket) =
  var i = 0'u16
  while i < s.curWindowPackets:
    let packetSeqNr = s.seqNr - 1 - i
    if (s.outBuffer.exists(
        packetSeqNr,
        (p: OutgoingPacket) => p.transmissions > 0 and p.needResend == false)):
      debug "Marking packet as lost",
        pkSeqNr = packetSeqNr
      s.outBuffer[packetSeqNr].needResend = true
      let packetPayloadLength = s.outBuffer[packetSeqNr].payloadLength
      doAssert(s.currentWindow >= packetPayloadLength,
        "Window should always be larger than packet length")
      s.currentWindow = s.currentWindow - packetPayloadLength

    inc i

proc isOpened(socket:UtpSocket): bool =
  return (
    socket.state == SynRecv or
    socket.state == SynSent or
    socket.state == Connected
  )

proc shouldDisconnectFromFailedRemote(socket: UtpSocket): bool =
  (socket.state == SynSent and socket.retransmitCount >= 2) or
  (socket.retransmitCount >= socket.socketConfig.dataResendsBeforeFailure)

proc checkTimeouts(socket: UtpSocket) =
  let currentTime = getMonoTimestamp().moment
  # flush all packets which needs to be re-send
  if socket.state != Destroy:
    socket.flushPackets()

  if socket.isOpened():
    let currentPacketSize = socket.getPacketSize()

    if (socket.zeroWindowTimer.isSome() and
        currentTime > socket.zeroWindowTimer.unsafeGet()):
      if socket.maxRemoteWindow <= currentPacketSize:
        # Reset maxRemoteWindow to minimal value which will fit at least two
        # packets
        let remoteWindow = 2 * socket.socketConfig.payloadSize
        socket.maxRemoteWindow = remoteWindow
        debug "Reset remote window to minimal value", remoteWindow
      socket.zeroWindowTimer = none[Moment]()

    if (currentTime > socket.rtoTimeout):
      debug "CheckTimeouts rto timeout",
        socketKey = socket.socketKey,
        state = socket.state,
        maxWindow = socket.maxWindow,
        curWindowPackets = socket.curWindowPackets,
        curWindowBytes = socket.currentWindow

      # TODO:
      # Add handling of probing on timeouts. The reference implementation has
      # a mechanism of sending probes to determine MTU size. Probe timeouts are
      # not taking into account for the timeout calculation.

      # For client initiated connections: SYN received but did not receive
      # following data packet in rto time and the socket is configured to start
      # in SynRecv state (to avoid amplifcation by IP spoofing).
      if (socket.state == SynRecv):
        socket.destroy()
        return

      if socket.shouldDisconnectFromFailedRemote():
        debug "Remote host failed",
          state = socket.state,
          retransmitCount = socket.retransmitCount

        if socket.state == SynSent and (not socket.connectionFuture.finished()):
          # Note: The socket connect code will already call socket.destroy when
          # ConnectionError gets raised, no need to do it here.
          socket.connectionFuture.fail(newException(
            ConnectionError, "Connection to peer timed out"))
        else:
          socket.destroy()

        return

      let newTimeout = socket.retransmitTimeout * 2
      socket.retransmitTimeout = newTimeout
      socket.rtoTimeout = currentTime + newTimeout

      # on timeout, reset the duplicate ack counter
      socket.duplicateAck = 0

      if (socket.curWindowPackets == 0 and socket.maxWindow > currentPacketSize):
        # There are no packets in flight even though there is space for more
        # than a full packet. This means the connection is just idling.
        # Reset window by 1/3'rd but no more than to fit at least one packet.
        let oldMaxWindow = socket.maxWindow
        let newMaxWindow = max((oldMaxWindow * 2) div 3,  currentPacketSize)

        debug "Decaying max window due to socket idling",
          oldMaxWindow = oldMaxWindow,
          newMaxWindow = newMaxWindow

        socket.maxWindow = newMaxWindow
      elif (socket.maxWindow < currentPacketSize):
        # due to high delay window has shrunk below packet size
        # which means that we cannot send more data
        # reset it to fit at least one packet
        debug "Resetting window size do fit a least one packet",
          oldWindowSize = socket.maxWindow,
          newWindowSize = currentPacketSize

        # delay was so high that window has shrunk below one packet. Reset window
        # to fit a least one packet and start with slow start
        socket.maxWindow = currentPacketSize
        socket.slowStart = true

      # Note: with selective acks enabled, every selectively acked packet resets
      # the timeout timer and removes te packet from the outBuffer.
      markAllPacketAsLost(socket)

      let oldestPacketSeqNr = socket.seqNr - socket.curWindowPackets
      # resend the oldest packet if there are some packets in flight and the
      # oldest packet was already sent
      if (socket.curWindowPackets > 0 and
          socket.outBuffer[oldestPacketSeqNr].transmissions > 0):
        inc socket.retransmitCount
        socket.fastTimeout = true

        debug "Resending oldest packet",
          pkSeqNr = oldestPacketSeqNr,
          retransmitCount = socket.retransmitCount,
          curWindowPackets = socket.curWindowPackets

        # Oldest packet should always be present, so it is safe to force resend
        socket.sendPacket(oldestPacketSeqNr)

    # TODO: add sending keep alives when necessary

proc checkTimeoutsLoop(s: UtpSocket) {.async.} =
  ## Loop that check timeouts in the socket.
  try:
    while true:
      await sleepAsync(checkTimeoutsLoopInterval)
      s.eventQueue.putNoWait(SocketEvent(kind: CheckTimeouts))
  except CancelledError as exc:
    # checkTimeoutsLoop is the last running future managed by the socket, when
    # it's cancelled the closeEvent can be fired.
    s.closeEvent.fire()
    trace "checkTimeoutsLoop canceled"
    raise exc

proc startTimeoutLoop(s: UtpSocket) =
  s.checkTimeoutsLoop = checkTimeoutsLoop(s)

proc getPacketSize*(socket: UtpSocket): uint32 =
  socket.socketConfig.payloadSize

proc handleDataWrite(socket: UtpSocket, data: seq[byte]): int =
  let pSize = int(socket.getPacketSize())
  let endIndex = data.high()
  var i = 0
  var bytesWritten = 0

  while i <= endIndex:
    let lastIndex = i + pSize - 1
    let lastOrEnd = min(lastIndex, endIndex)
    let dataSlice = data[i..lastOrEnd]
    let payloadLength =  uint32(len(dataSlice))
    if (socket.outBufferBytes + payloadLength <= socket.socketConfig.optSndBuffer):
      let wndSize = socket.getRcvWindowSize()
      let dataPacket =
        dataPacket(
          socket.seqNr,
          socket.connectionIdSnd,
          socket.ackNr,
          wndSize,
          dataSlice,
          socket.replayMicro
        )
      let outgoingPacket = OutgoingPacket.init(
        encodePacket(dataPacket), 0, false, payloadLength)
      socket.registerOutgoingPacket(outgoingPacket)
      bytesWritten = bytesWritten + len(dataSlice)
      # TODO: When flushPackets early ended because of send window being full,
      # it keeps trying here again for each dataSlice. Sounds waistfull?
      socket.flushPackets()
    else:
      debug "No more place in write buffer",
        currentBufferSize = socket.outBufferBytes,
        maxBufferSize = socket.socketConfig.optSndBuffer,
        nexPacketSize = payloadLength
      break

    i = lastOrEnd + 1

  return bytesWritten

proc handleClose(socket: UtpSocket) =
  let finEncoded =
    encodePacket(
      finPacket(
        socket.seqNr,
        socket.connectionIdSnd,
        socket.ackNr,
        socket.getRcvWindowSize(),
        socket.replayMicro
      )
    )
  socket.finSent = true
  socket.registerOutgoingPacket(OutgoingPacket.init(finEncoded, 0, false, 0))
  socket.flushPackets()

proc isConnected*(socket: UtpSocket): bool =
  socket.state == Connected

proc isClosed*(socket: UtpSocket): bool =
  socket.state == Destroy and socket.closeEvent.isSet()

proc isClosedAndCleanedUpAllResources*(socket: UtpSocket): bool =
  ## Test Api to check that all resources are properly cleaned up
  socket.isClosed() and socket.eventLoop.cancelled() and
    socket.checkTimeoutsLoop.cancelled()

proc destroy*(s: UtpSocket) =
  debug "Destroying socket", to = s.socketKey
  ## Moves socket to destroy state and clean all resources.
  ## Remote is not notified in any way about socket end of life.
  s.state = Destroy
  s.eventLoop.cancel()
  # This procedure initiate cleanup process which goes like:
  # Cancel EventLoop -> Cancel timeoutsLoop -> Fire closeEvent
  # This is necessary due to how evenLoop look like i.e it has only one await
  # point on `eventQueue.get` which trigger cancellation exception only when
  # someone will try run `eventQueue.put`. Without `eventQueue.put` , eventLoop
  # future shows as cancelled, but handler for CancelledError is not run

proc destroyWait*(s: UtpSocket) {.async.} =
  ## Moves socket to destroy state and clean all resources and wait for all
  ## registered callbacks to fire,
  ## Remote is not notified in any way about socket end of life.
  s.destroy()
  await s.closeEvent.wait()
  await allFutures(s.closeCallbacks)

proc setCloseCallback(s: UtpSocket, cb: SocketCloseCallback) {.async.} =
  ## Set callback which will be called whenever the socket is permanently closed
  try:
    await s.closeEvent.wait()
    cb()
  except CancelledError:
    trace "closeCallback cancelled"

proc registerCloseCallback*(s: UtpSocket, cb: SocketCloseCallback) =
  s.closeCallbacks.add(s.setCloseCallback(cb))

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

proc ackPacket(socket: UtpSocket, seqNr: uint16, currentTime: Moment): AckResult =
  let packetOpt = socket.outBuffer.get(seqNr)
  if packetOpt.isSome():
    let packet = packetOpt.get()

    if packet.transmissions == 0:
      # according to reference impl it can happen when we get an ack_nr that
      # does not exceed what we have stuffed into the outgoing buffer,
      # but does exceed what we have sent
      # TODO analyze if this case can happen with our impl
      return PacketNotSentYet

    socket.outBuffer.delete(seqNr)

    debug "Acked packet (deleted from outgoing buffer)",
      pkSeqNr = seqNr,
      pkTransmissions = packet.transmissions,
      pkNeedResend = packet.needResend

    # from spec: The rtt and rtt_var is only updated for packets that were sent
    # only once. This avoids the problem of figuring out which packet was acked,
    # the first or the second one. It is standard solution to the retransmission
    # ambiguity problem.
    if packet.transmissions == 1:
      socket.updateTimeouts(packet.timeSent, currentTime)

    socket.retransmitTimeout = socket.rto
    socket.rtoTimeout = currentTime + socket.rto

    # if need_resend is set, this packet has already
    # been considered timed-out, and is not included in
    # the cur_window anymore
    if (not packet.needResend):
      doAssert(socket.currentWindow >= packet.payloadLength,
        "Window should always be larger than packet length")
      socket.currentWindow = socket.currentWindow - packet.payloadLength

    # recalculate as packet was removed from the outgoing buffer
    socket.outBufferBytes = socket.outBufferBytes - packet.payloadLength

    socket.retransmitCount = 0
    PacketAcked
  else:
    debug "Tried to ack packet which was already acked or not sent yet"
    # the packet has already been acked (or not sent)
    PacketAlreadyAcked

proc ackPackets(socket: UtpSocket, nrPacketsToAck: uint16, currentTime: Moment) =
  ## Ack packets in outgoing buffer based on ack number in the received packet
  var i = 0
  while i < int(nrPacketsToAck):
    let result = socket.ackPacket(
      socket.seqNr - socket.curWindowPackets, currentTime)
    case result
    of PacketAcked:
      dec socket.curWindowPackets
    of PacketAlreadyAcked:
      dec socket.curWindowPackets
    of PacketNotSentYet:
      debug "Tried to ack packed which was not sent yet"
      break

    inc i

proc calculateAckedbytes(
    socket: UtpSocket, nrPacketsToAck: uint16, now: Moment):
    (uint32, Duration) =
  var i: uint16 = 0
  var ackedBytes: uint32 = 0
  var minRtt: Duration = InfiniteDuration
  while i < nrPacketsToAck:
    let seqNr = socket.seqNr - socket.curWindowPackets + i
    let packetOpt = socket.outBuffer.get(seqNr)
    if (packetOpt.isSome() and packetOpt.unsafeGet().transmissions > 0):
      let packet = packetOpt.unsafeGet()

      ackedBytes = ackedBytes + packet.payloadLength

      # safety check in case clock is not monotonic
      if packet.timeSent < now:
        minRtt = min(minRtt, now - packet.timeSent)
      else:
        minRtt = min(minRtt, microseconds(50000))

    inc i
  (ackedBytes, minRtt)

proc initializeAckNr(socket: UtpSocket, packetSeqNr: uint16) =
  if (socket.state == SynSent):
    # Different from the uTP spec but in accordance with libutp and libtorrent.
    # When receiving the ACK of a SYN packet, the socket ackNr gets initialized
    # as the packet seqNr - 1. This way, the socket ackNr is set up as one less
    # the next seqNr for an incoming DATA packet. The seqNr in STATE packets
    # should basically be seen as the seqNr for the next DATA or FIN packet.
    # See also:
    # - libutp: https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L1874
    # - libtorrent: https://github.com/arvidn/libtorrent/blob/RC_2_0/src/utp_stream.cpp#L2924
    socket.ackNr = packetSeqNr - 1

proc isAckNrInvalid(socket: UtpSocket, packet: Packet): bool =
  let ackWindow = max(socket.curWindowPackets + allowedAckWindow, allowedAckWindow)
  (
    (packet.header.pType != ST_SYN or socket.state != SynRecv) and
    (
      # packet ack number must be smaller than our last send packet i.e
      # remote should not ack packets from the future
      wrapCompareLess(socket.seqNr - 1, packet.header.ackNr) or
      # packet ack number should not be too old
      wrapCompareLess(packet.header.ackNr, socket.seqNr - 1 - ackWindow)
    )
  )

# counts the number of bytes acked by selective ack header
proc calculateSelectiveAckBytes*(
    socket: UtpSocket, receivedPackedAckNr: uint16, ext: SelectiveAckExtension):
    uint32 =
  # Add 2, as the first bit in the mask represents ackNr + 2 because ackNr + 1
  # (i.e next expected packet) is considered lost.
  let base = receivedPackedAckNr + 2

  if socket.curWindowPackets == 0:
    return 0

  var ackedBytes = 0'u32

  var bits = (len(ext.acks)) * 8 - 1

  while bits >= 0:
    let v = base + uint16(bits)

    if (socket.seqNr - v - 1) >= socket.curWindowPackets - 1:
      dec bits
      continue

    let maybePacket = socket.outBuffer.get(v)

    if (maybePacket.isNone() or maybePacket.unsafeGet().transmissions == 0):
      dec bits
      continue

    let pkt = maybePacket.unsafeGet()

    if (getBit(ext.acks, bits)):
      ackedBytes = ackedBytes + pkt.payloadLength

    dec bits

  return ackedBytes

# decays maxWindow size by half if time is right i.e it is at least 100m since
# last window decay
proc tryDecayWindow(socket: UtpSocket, now: Moment) =
  if (now - socket.lastWindowDecay >= maxWindowDecay):
    socket.lastWindowDecay = now
    let newMaxWindow =
      max(uint32(0.5 * float64(socket.maxWindow)), uint32(minWindowSize))

    debug "Decaying maxWindow",
      oldWindow = socket.maxWindow,
      newWindow = newMaxWindow

    socket.maxWindow = newMaxWindow
    socket.slowStart = false
    socket.slowStartThreshold = newMaxWindow

# ack packets (removes them from out going buffer) based on selective ack
# extension header
proc selectiveAckPackets(
    socket: UtpSocket, receivedPackedAckNr: uint16, ext: SelectiveAckExtension,
    currentTime: Moment): void =
  # Add 2, as the first bit in the mask represents ackNr + 2 because ackNr + 1
  # (i.e next expected packet) is considered lost.
  let base = receivedPackedAckNr + 2

  if socket.curWindowPackets == 0:
    return

  var bits = (len(ext.acks)) * 8 - 1

  # number of packets acked by this selective ack, it also works as duplicate
  # ack counter.
  # from spec: Each packet that is acked in the selective ack message counts as
  # one duplicate ack
  var counter = 0

  # sequence numbers of packets which should be resend
  var resends: seq[uint16] = @[]

  while bits >= 0:
    let v = base + uint16(bits)

    if (socket.seqNr - v - 1) >= socket.curWindowPackets - 1:
      dec bits
      continue

    let bitSet: bool = getBit(ext.acks, bits)

    if bitSet:
      inc counter

    let maybePacket = socket.outBuffer.get(v)

    if (maybePacket.isNone() or maybePacket.unsafeGet().transmissions == 0):
      dec bits
      continue

    let pkt = maybePacket.unsafeGet()

    if bitSet:
      debug "Packet acked by selective ack",
        pkSeqNr = v
      discard socket.ackPacket(v, currentTime)
      dec bits
      continue

    if counter >= duplicateAcksBeforeResend and
        (v - socket.fastResendSeqNr) <= reorderBufferMaxSize:
      debug "No ack for packet",
        pkAckNr = v,
        dupAckCounter = counter,
        fastResSeqNr = socket.fastResendSeqNr
      resends.add(v)

    dec bits

  # When resending packets, the first packet should be the first unacked packet,
  # ie. base - 1
  let nextExpectedPacketSeqNr = base - 1'u16
  if counter >= duplicateAcksBeforeResend and
      (nextExpectedPacketSeqNr - socket.fastResendSeqNr) <= reorderBufferMaxSize:
    debug "No ack for packet",
      pkAckNr = nextExpectedPacketSeqNr,
      dupAckCounter = counter,
      fastResSeqNr = socket.fastResendSeqNr
    resends.add(nextExpectedPacketSeqNr)

  var i = high(resends)
  var registerLoss: bool = false
  var packetsSent = 0
  while i >= 0:
    let seqNrToResend: uint16 = resends[i]

    let maybePkt = socket.outBuffer.get(seqNrToResend)

    if maybePkt.isNone():
      # packet is no longer in send buffer ignore whole further processing
      dec i
      continue

    registerLoss = true
    # it is safe to call as we already checked that packet is in send buffer

    socket.sendPacket(seqNrToResend)
    socket.fastResendSeqNr = seqNrToResend + 1

    debug "Resent packet",
      pkSeqNr = seqNrToResend,
      fastResendSeqNr = socket.fastResendSeqNr

    inc packetsSent

    # resend max 4 packets, this is not defined in spec but reference impl has
    # that check
    if packetsSent >= 4:
      break

    dec i

  if registerLoss:
    socket.tryDecayWindow(Moment.now())

  socket.duplicateAck = uint16(counter)

# Public mainly for test purposes
# Generates bit mask which indicates which packets are already in socket
# reorder buffer.
# From spec:
# The bitmask has reverse byte order. The first byte represents packets
# [ack_nr + 2, ack_nr + 2 + 7] in reverse order.
# The least significant bit in the byte represents ack_nr + 2, the most
# significant bit in the byte represents ack_nr + 2 + 7. The next byte in the
# mask represents [ack_nr + 2 + 8, ack_nr + 2 + 15] in reverse order, and so on.
proc generateSelectiveAckBitMask*(socket: UtpSocket): array[4, byte] =
  let window = min(32, socket.inBuffer.len())
  var arr: array[4, uint8] = [0'u8, 0, 0, 0]
  var i = 0
  while i < window:
    if (socket.inBuffer.get(socket.ackNr + uint16(i) + 2).isSome()):
      setBit(arr, i)
    inc i
  return arr

# Generates ack packet based on current state of the socket.
proc generateAckPacket*(socket: UtpSocket): Packet =
    let bitmask =
      if (socket.reorderCount != 0 and (not socket.reachedFin)):
        some(socket.generateSelectiveAckBitMask())
      else:
        none[array[4, byte]]()

    let bufferSize = socket.getRcvWindowSize()

    ackPacket(
      socket.seqNr,
      socket.connectionIdSnd,
      socket.ackNr,
      bufferSize,
      socket.replayMicro,
      bitmask
    )

proc sendAck(socket: UtpSocket) =
  ## Creates and sends ack, based on current socket state. Acks are different
  ## from other packets as we do not track them in outgoing buffer.
  let ackPacket = socket.generateAckPacket()

  debug "Sending STATE packet",
    pkSeqNr = ackPacket.header.seqNr,
    pkAckNr = ackPacket.header.ackNr,
    gotEACK = ackPacket.eack.isSome()

  socket.sendData(encodePacket(ackPacket))


proc tryfinalizeConnection(socket: UtpSocket, p: Packet) =
  # To avoid amplification attacks, server socket is in SynRecv state until
  # it receives first data transfer
  # https://www.usenix.org/system/files/conference/woot15/woot15-paper-adamsky.pdf
  # Socket is in SynRecv state only when recv timeout is configured
  if (socket.state == SynRecv and p.header.pType == ST_DATA):
    socket.state = Connected

  if (socket.state == SynSent and p.header.pType == ST_STATE):
    socket.state = Connected
    socket.ackNr = p.header.seqNr - 1

    debug "Received Syn-Ack finalizing connection",
      socketAckNr = socket.ackNr

    if (not socket.connectionFuture.finished()):
      socket.connectionFuture.complete()

# TODO: at socket level we should handle only FIN/DATA/ACK packets. Refactor to
# make it enforceable by type system
proc processPacketInternal(socket: UtpSocket, p: Packet) =
  debug "Process packet",
    socketKey = socket.socketKey,
    socketAckNr = socket.ackNr,
    socketSeqNr = socket.seqNr,
    windowPackets = socket.curWindowPackets,
    rcvBufferSize = socket.offset,
    packetType = p.header.pType,
    seqNr = p.header.seqNr,
    ackNr = p.header.ackNr,
    timestamp = p.header.timestamp,
    timestampDiff = p.header.timestampDiff,
    remoteWindow = p.header.wndSize

  let timestampInfo = getMonoTimestamp()

  if socket.isAckNrInvalid(p):
    debug "Received packet with invalid ack number",
      ackNr = p.header.ackNr,
      localSeqNr = socket.seqNr,
      lastUnacked = socket.seqNr - socket.curWindowPackets

    return

  ## Updates socket state based on received packet, and sends ack when necessary.
  ## Should be called in main packet receiving loop
  let pkSeqNr = p.header.seqNr
  let pkAckNr = p.header.ackNr

  socket.initializeAckNr(pkSeqNr)

  # number of packets past the expected
  # ack_nr is the last acked, seq_nr is the
  # current. Subtracting 1 makes 0 mean "this is the next expected packet"
  let pastExpected = pkSeqNr - socket.ackNr - 1

  # acks is the number of packets that was acked, in normal case - no selective
  # acks, no losses, no resends, it will usually be equal to 1
  # we can calculate it here and not only for ST_STATE packet, as each utp
  # packet has info about remote side last acked packet.
  var acks = pkAckNr - (socket.seqNr - 1 - socket.curWindowPackets)

  if acks > socket.curWindowPackets:
    # this case happens if the we already received this ack nr
    acks = 0

  # rationale from c reference impl:
  # if we get the same ack_nr as in the last packet
  # increase the duplicate_ack counter, otherwise reset
  # it to 0.
  # It's important to only count ACKs in ST_STATE packets. Any other
  # packet (primarily ST_DATA) is likely to have been sent because of the
  # other end having new outgoing data, not in response to incoming data.
  # For instance, if we're receiving a steady stream of payload with no
  # outgoing data, and we suddently have a few bytes of payload to send (say,
  # a bittorrent HAVE message), we're very likely to see 3 duplicate ACKs
  # immediately after sending our payload packet. This effectively disables
  # the fast-resend on duplicate-ack logic for bi-directional connections
  # (except in the case of a selective ACK). This is in line with BSD4.4 TCP
  # implementation.
  if socket.curWindowPackets > 0 and
    pkAckNr == socket.seqNr - socket.curWindowPackets - 1 and
    p.header.pType == ST_STATE:
      inc socket.duplicateAck

      debug "Received duplicated ack",
        pkAckNr = pkAckNr,
        duplicateAckCounter = socket.duplicateAck
  else:
    socket.duplicateAck = 0
  # Spec states that in case of a duplicate ack counter larger than
  # `duplicateAcksBeforeResend` the oldest packet should be resend. However, the
  # reference implementation has the code path which does this commented out
  # with a todo. Currently the reference implementation is follow and packets
  # are not resend in this case.

  debug "Packet state variables",
    pastExpected = pastExpected,
    acks = acks

  # If packet is totally off the mark, short-circuit the processing
  if pastExpected >= reorderBufferMaxSize:
    # if `pastExpected` is a really big number (for example: uint16.high) then
    # most probably we are receiving packet which we already received.
    # example: socket already received packet with `seqNr = 10` so the
    # `socket.ackNr = 10`.
    # Then when this packet is received once again then
    # `pastExpected = 10 - 10 - 1` which equals (due to wrapping) 65535.
    # This means that remote most probably did not receive our ack, so we need
    # to resend it. We are doing it for last `reorderBufferMaxSize` packets.
    let isPossibleDuplicatedOldPacket =
      pastExpected >= (int(uint16.high) + 1) - reorderBufferMaxSize

    if (isPossibleDuplicatedOldPacket and p.header.pType != ST_STATE):
      socket.sendAck()

    debug "Got an invalid packet sequence number, too far off",
      pastExpected = pastExpected
    return

  var (ackedBytes, minRtt) =
    socket.calculateAckedbytes(acks, timestampInfo.moment)

  debug "Bytes acked by classic ack",
      bytesAcked = ackedBytes

  if (p.eack.isSome()):
    let selectiveAckedBytes =
      socket.calculateSelectiveAckBytes(pkAckNr, p.eack.unsafeGet())
    debug "Bytes acked by selective ack",
      bytesAcked = selectiveAckedBytes
    ackedBytes = ackedBytes + selectiveAckedBytes

  let sentTimeRemote = p.header.timestamp

  # we are using uint32 not a Duration, to wrap a round in case of
  # sentTimeRemote > receipTimestamp. This can happen as local and remote
  # clock can be not synchronized or even using different system clock.
  # i.e this number itself does not tell anything and is only used to feedback
  # it to remote peer with each sent packet
  let remoteDelay =
    if (sentTimeRemote == 0):
      0'u32
    else:
      timestampInfo.timestamp - sentTimeRemote

  socket.replayMicro = remoteDelay

  let prevRemoteDelayBase = socket.remoteHistogram.delayBase

  if (remoteDelay != 0):
    socket.remoteHistogram.addSample(remoteDelay, timestampInfo.moment)

  # remote new delay base is less than previous
  # shift our delay base in other direction to take clock skew into account
  # but no more than 10ms
  if (prevRemoteDelayBase != 0 and
      wrapCompareLess(socket.remoteHistogram.delayBase, prevRemoteDelayBase) and
      prevRemoteDelayBase - socket.remoteHistogram.delayBase <= 10000'u32):
        socket.ourHistogram.shift(
          prevRemoteDelayBase - socket.remoteHistogram.delayBase)

  let actualDelay = p.header.timestampDiff

  if actualDelay != 0:
    socket.ourHistogram.addSample(actualDelay, timestampInfo.moment)
    socket.driftCalculator.addSample(actualDelay, timestampInfo.moment)

  # adjust base delay if delay estimates exceeds rtt
  if (socket.ourHistogram.getValue() > minRtt):
    let diff = uint32((socket.ourHistogram.getValue() - minRtt).microseconds())
    socket.ourHistogram.shift(diff)

  let currentPacketSize = socket.getPacketSize()
  let (newMaxWindow, newSlowStartThreshold, newSlowStart) =
    applyCongestionControl(
      socket.maxWindow,
      socket.slowStart,
      socket.slowStartThreshold,
      socket.socketConfig.optSndBuffer,
      currentPacketSize,
      microseconds(actualDelay),
      ackedBytes,
      minRtt,
      socket.ourHistogram.getValue(),
      socket.driftCalculator.clockDrift
    )

  # update remote window size and max window
  socket.maxWindow = newMaxWindow
  socket.maxRemoteWindow = p.header.wndSize
  socket.slowStart = newSlowStart
  socket.slowStartThreshold = newSlowStartThreshold

  debug "Applied ledbat congestion controller",
    maxWindow = newMaxWindow,
    remoteWindow = p.header.wndSize,
    slowStartThreshold = newSlowStartThreshold,
    slowstart = newSlowStart

  if (socket.zeroWindowTimer.isNone() and
      socket.maxRemoteWindow <= currentPacketSize):
    # when zeroWindowTimer is hit and maxRemoteWindow still is equal
    # to 0 then it will be reset to the minimal value
    socket.zeroWindowTimer =
      some(timestampInfo.moment + socket.socketConfig.remoteWindowResetTimeout)

    debug "Remote window size dropped below packet size",
      currentTime = timestampInfo.moment,
      resetZeroWindowTime = socket.zeroWindowTimer,
      currentPacketSize = currentPacketSize

  socket.tryfinalizeConnection(p)

  # socket.curWindowPackets == acks means that this packet acked all remaining
  # packets including the sent FIN packets
  if (socket.finSent and socket.curWindowPackets == acks):
    debug "FIN acked, destroying socket"
    socket.finAcked = true
    # this part of the uTP spec is a bit under specified, i.e there is no
    # specification at all. The reference implementation moves socket to destroy
    # state in case that our FIN was acked and socket is considered closed for
    # reading and writing. But in theory, the remote could still write some data
    # on this socket (or even its own FIN).
    socket.destroy()

  # Update fast resend counter to avoid resending old packet twice
  if wrapCompareLess(socket.fastResendSeqNr, pkAckNr + 1):
    socket.fastResendSeqNr = pkAckNr + 1

  # The specifications indicate that ST_DATA packets are only to be send
  # when the socket is in connected state. It is unclear what to do when an
  # ST_FIN is received while not in connected state.
  # So the socket will drop any received ST_DATA or ST_FIN packet while not in
  # connected state.
  # Note: In the set-up where the connection initiator is not sending the
  # (first) data, it could be that ST_DATA arrives before an ST_STATE (SYN-ACK).
  # In this scenario, all ST_DATA gets dropped and the initiator will eventually
  # re-send the ST_SYN.
  # This check does need to happen before `ackPackets` as else the SYN packet
  # could get erased from the `outBuffer` already while the connection remains
  # in `SynSent` state as an ack from ST_DATA will not be accepted to set the
  # socket in `Connected` state.
  if (p.header.pType == ST_DATA or p.header.pType == ST_FIN) and
      socket.state != Connected:
    debug "Unexpected packet",
      socketState = socket.state,
      packetType = p.header.pType

    return

  socket.ackPackets(acks, timestampInfo.moment)

  # packets in front may have been acked by selective ack, decrease window until
  # we hit a packet that is still waiting to be acked.
  while (socket.curWindowPackets > 0 and
      socket.outBuffer.get(socket.seqNr - socket.curWindowPackets).isNone()):
    dec socket.curWindowPackets
    debug "Packet in front has been acked by selective ack. Decrease window",
      windowPackets = socket.curWindowPackets

  # fast timeout
  if socket.fastTimeout:
    let oldestOutstandingPktSeqNr = socket.seqNr - socket.curWindowPackets

    debug "Hit fast timeout re-send",
      curWindowPackets = socket.curWindowPackets,
      oldesPkSeqNr = oldestOutstandingPktSeqNr,
      fastResendSeqNr = socket.fastResendSeqNr


    if oldestOutstandingPktSeqNr != socket.fastResendSeqNr:
      # fastResendSeqNr does not point to oldest unacked packet, we probably
      # already resent the packet that timed-out. Leave on fast timeout mode.
      socket.fastTimeout = false
    else:
      let shouldReSendPacket = socket.outBuffer.exists(
        oldestOutstandingPktSeqNr, (p: OutgoingPacket) => p.transmissions > 0)
      if shouldReSendPacket:
        debug "Packet fast timeout resend",
          pkSeqNr = oldestOutstandingPktSeqNr

        inc socket.fastResendSeqNr

        # It is safe to call force resend as we already checked
        # `shouldReSendPacket` condition.
        socket.sendPacket(oldestOutstandingPktSeqNr)

  if (p.eack.isSome()):
    socket.selectiveAckPackets(pkAckNr, p.eack.unsafeGet(), timestampInfo.moment)

  if p.header.pType == ST_DATA or p.header.pType == ST_FIN:
    if (p.header.pType == ST_FIN and (not socket.gotFin)):
      debug "Received FIN packet",
        eofPktNr = pkSeqNr,
        curAckNr = socket.ackNr

      socket.gotFin = true
      socket.eofPktNr = pkSeqNr

    # we got in order packet
    if (pastExpected == 0 and (not socket.reachedFin)):
      debug "Received in order packet"
      let payloadLength = len(p.payload)
      if (payloadLength > 0 and (not socket.readShutdown)):
        # we need to sum both rcv buffer and reorder buffer
        let totalBufferSize =
          uint32(socket.offset) + socket.inBufferBytes + uint32(payloadLength)
        if (totalBufferSize > socket.socketConfig.optRcvBuffer):
          # even though packet is in order and passes all the checks, it would
          # overflow our receive buffer, it means that we are receiving data
          # faster than we are reading it. Do not ack this packet, and drop
          # received data.
          debug "Received packet would overflow receive buffer, dropping it",
            pkSeqNr = p.header.seqNr,
            bytesReceived = payloadLength,
            rcvbufferSize = socket.offset,
            reorderBufferSize = socket.inBufferBytes
          return

        debug "Received data packet",
          bytesReceived = payloadLength
        # we are getting in order data packet, we can flush data directly to the
        # incoming buffer.
        # await upload(addr socket.buffer, unsafeAddr p.payload[0], p.payload.len())
        moveMem(
          addr socket.rcvBuffer[socket.offset],
          unsafeAddr p.payload[0], payloadLength)
        socket.offset = socket.offset + payloadLength

      # Bytes have been passed to upper layer, we can increase number of last
      # acked packet
      inc socket.ackNr

      # check if the following packets are in re-order buffer
      debug "Looking for packets in re-order buffer",
        reorderCount = socket.reorderCount

      while true:
        # We are doing this in reorder loop, to handle the case when we already
        # received FIN but there were some gaps before eof.
        # we have reached remote eof and should not receive more packets from
        # remote.
        if ((not socket.reachedFin) and socket.gotFin and
            socket.eofPktNr == socket.ackNr):
          debug "Reached socket EOF"
          # In case of reaching eof, it is up to user of library what to do with
          # it. With the current implementation, the most appropriate way would
          # be to destroy it (as with our implementation we know that remote is
          # destroying its acked fin) as any other send will either generate
          # timeout, or socket will be forcefully closed by reset
          socket.reachedFin = true
          # this is not necessarily true, but as we have already reached eof we
          # can ignore following packets
          socket.reorderCount = 0

        if socket.reorderCount == 0:
          break

        let nextPacketNum = socket.ackNr + 1

        let maybePacket = socket.inBuffer.get(nextPacketNum)

        if maybePacket.isNone():
          break

        let packet = maybePacket.unsafeGet()
        let reorderPacketPayloadLength = len(packet.payload)

        if (reorderPacketPayloadLength > 0 and (not socket.readShutdown)):
          debug "Got packet from reorder buffer",
            packetBytes = len(packet.payload),
            packetSeqNr = packet.header.seqNr,
            packetAckNr = packet.header.ackNr,
            socketSeqNr = socket.seqNr,
            socketAckNr = socket.ackNr,
            rcvbufferSize = socket.offset,
            reorderBufferSize = socket.inBufferBytes

          # Rcv buffer and reorder buffer are sized such that it is always
          # possible to move data from reorder buffer to rcv buffer without
          # overflow.
          moveMem(
            addr socket.rcvBuffer[socket.offset],
            unsafeAddr packet.payload[0], reorderPacketPayloadLength)
          socket.offset = socket.offset + reorderPacketPayloadLength

        debug "Deleting packet",
          seqNr = nextPacketNum

        socket.inBuffer.delete(nextPacketNum)
        inc socket.ackNr
        dec socket.reorderCount
        socket.inBufferBytes =
          socket.inBufferBytes - uint32(reorderPacketPayloadLength)

      debug "Socket state after processing in order packet",
        socketKey = socket.socketKey,
        socketAckNr = socket.ackNr,
        reorderCount = socket.reorderCount,
        windowPackets = socket.curWindowPackets

      # TODO for now we just schedule concurrent task with ack sending. It may
      # need improvement, as with this approach there is no direct control over
      # how many concurrent tasks there are and how to cancel them when socket
      # is closed
      socket.sendAck()

    # we got packet out of order
    else:
      debug "Got out of order packet"

      if (socket.gotFin and pkSeqNr > socket.eofPktNr):
        debug "Got packet past eof",
          pkSeqNr = pkSeqNr,
          eofPktNr = socket.eofPktNr

        return

      # growing buffer before checking the packet is already there to avoid
      # looking at older packet due to indices wrap aroud
      socket.inBuffer.ensureSize(pkSeqNr + 1, pastExpected + 1)

      if (socket.inBuffer.get(pkSeqNr).isSome()):
        debug "Packet with seqNr already received",
          seqNr = pkSeqNr
      else:
        let
          payloadLength = uint32(len(p.payload))
          totalReorderSize = socket.inBufferBytes + payloadLength
          totalBufferSize =
            socket.inBufferBytes + uint32(socket.offset) + payloadLength
        if (totalReorderSize <= socket.socketConfig.maxSizeOfReorderBuffer and
            totalBufferSize <= socket.socketConfig.optRcvBuffer):

          debug "store packet in reorder buffer",
            packetBytes = payloadLength,
            packetSeqNr = p.header.seqNr,
            packetAckNr = p.header.ackNr,
            socketSeqNr = socket.seqNr,
            socketAckNr = socket.ackNr,
            rcvbufferSize = socket.offset,
            reorderBufferSize = socket.inBufferBytes

          socket.inBuffer.put(pkSeqNr, p)
          inc socket.reorderCount
          socket.inBufferBytes = socket.inBufferBytes + payloadLength
          debug "added out of order packet to reorder buffer",
            reorderCount = socket.reorderCount
          # we send ack packet, as we reorder count is > 0, so the eack bitmask
          # will be generated
          socket.sendAck()

proc processPacket*(socket: UtpSocket, p: Packet): Future[void] =
  socket.eventQueue.put(SocketEvent(kind: NewPacket, packet: p))

template shiftBuffer(t, c: untyped) =
  if (t).offset > c:
    if c > 0:
      moveMem(addr((t).rcvBuffer[0]), addr((t).rcvBuffer[(c)]), (t).offset - (c))
      (t).offset = (t).offset - (c)
  else:
    (t).offset = 0

proc onRead(socket: UtpSocket, readReq: var ReadReq): ReadResult =
  debug "Handling incoming read",
    rcvBufferSize = socket.offset,
    reorderBufferSize = socket.inBufferBytes,
    socketAtEOF = socket.atEof(),
    readTillEOF = readReq.bytesToRead == 0

  if readReq.reader.finished():
    return ReadCancelled

  if socket.atEof():
    # buffer is already empty and we reached remote fin, just finish read with
    # whatever was already read
    readReq.reader.complete(readReq.bytesAvailable)
    return SocketAlreadyFinished

  if readReq.bytesToRead == 0:
    # treat is as read till eof
    readReq.bytesAvailable.add(socket.rcvBuffer.toOpenArray(0, socket.offset - 1))
    socket.shiftBuffer(socket.offset)
    if (socket.atEof()):

      debug "Read finished",
        bytesRead = len(readReq.bytesAvailable),
        socketAtEof = socket.atEof()

      readReq.reader.complete(readReq.bytesAvailable)
      return ReadFinished
    else:
      debug "Read not finished",
        bytesRead = len(readReq.bytesAvailable),
        socketAtEof = socket.atEof()

      return ReadNotFinished
  else:
    let bytesAlreadyRead = len(readReq.bytesAvailable)
    let bytesLeftToRead = readReq.bytesToRead - bytesAlreadyRead
    let count = min(socket.offset, bytesLeftToRead)
    readReq.bytesAvailable.add(socket.rcvBuffer.toOpenArray(0, count - 1))
    socket.shiftBuffer(count)
    if (len(readReq.bytesAvailable) == readReq.bytesToRead):
      debug "Read finished",
        bytesRead = len(readReq.bytesAvailable),
        socketAtEof = socket.atEof()

      readReq.reader.complete(readReq.bytesAvailable)
      return ReadFinished
    else:
      debug "Read not finished",
        bytesRead = len(readReq.bytesAvailable),
        socketAtEof = socket.atEof()

      return ReadNotFinished

proc eventLoop(socket: UtpSocket) {.async.} =
  try:
    while true:
      let socketEvent = await socket.eventQueue.get()
      case socketEvent.kind
      of NewPacket:
        socket.processPacketInternal(socketEvent.packet)

        # we processed a packet and rcv buffer size is larger than 0,
        # check if we can finish some pending readers
        while socket.pendingReads.len() > 0:
          let readResult = socket.onRead(socket.pendingReads[0])
          case readResult
          of ReadFinished:
            discard socket.pendingReads.popFirst()
          of ReadNotFinished:
            # there was not enough bytes in buffer to finish this read request,
            # stop processing further reads
            break
          else:
            # read was cancelled or socket is already finished move on to next
            # read request
            discard socket.pendingReads.popFirst()

        # we processed packet, so there could more place in the send buffer
        while socket.pendingWrites.len() > 0:
          let pendingWrite = socket.pendingWrites.popFirst()
          case pendingWrite.kind
          of Close:
            socket.handleClose()
            # close should be last packet send
            break
          of Data:
            # check if writing was not cancelled in the mean time. This approach
            # can create partial writes as part of the data could be written with
            # with WriteReq
            if (not pendingWrite.writer.finished()):
              let bytesWritten = socket.handleDataWrite(pendingWrite.data)
              if (bytesWritten == len(pendingWrite.data)):
                # all bytes were written we can finish external future
                pendingWrite.writer.complete(
                  WriteResult.ok(bytesWritten)
                )
              else:
                let bytesLeft =
                  pendingWrite.data[bytesWritten..pendingWrite.data.high]
                # bytes partially written to buffer, schedule rest of data for
                # later
                socket.pendingWrites.addFirst(
                  WriteRequest(
                    kind: Data,
                    data: bytesLeft,
                    writer: pendingWrite.writer
                  )
                )
                # there is no more place in the buffer break from the loop
                break
      of CheckTimeouts:
        discard
      of CloseReq:
        if (socket.pendingWrites.len() > 0):
          # there are still some unfinished writes, waiting to be finished
          socket.pendingWrites.addLast(WriteRequest(kind: Close))
        else:
          socket.handleClose()
      of WriteReq:
        # check if the writer was not cancelled in mean time
        if (not socketEvent.writer.finished()):
          if (socket.pendingWrites.len() > 0):
            # there are still some unfinished writes, waiting to be finished
            # schedule this batch for later
            socket.pendingWrites.addLast(
              WriteRequest(
                kind: Data,
                data: socketEvent.data,
                writer: socketEvent.writer
              )
            )
          else:
            let bytesWritten = socket.handleDataWrite(socketEvent.data)
            if (bytesWritten == len(socketEvent.data)):
              # all bytes were written we can finish external future
              socketEvent.writer.complete(
                WriteResult.ok(bytesWritten)
              )
            else:
              let bytesLeft =
                socketEvent.data[bytesWritten..socketEvent.data.high]
              # bytes partially written to buffer, schedule rest of data for later
              socket.pendingWrites.addLast(
                WriteRequest(
                  kind: Data,
                  data: bytesLeft,
                  writer: socketEvent.writer
                )
              )
      of ReadReqType:
        # check if the writer was not cancelled in mean time
        if (not socketEvent.readReq.reader.finished()):
          if (socket.pendingReads.len() > 0):
            # there is already pending unfinished read request, schedule this
            # one for later
            socket.pendingReads.addLast(socketEvent.readReq)
          else:
            var readReq = socketEvent.readReq
            let readResult = socket.onRead(readReq)
            case readResult
            of ReadNotFinished:
              socket.pendingReads.addLast(readReq)
            else:
              # in any other case we do not need to do any thing
              discard
      socket.checkTimeouts()
  except CancelledError as exc:
    for w in socket.pendingWrites.items():
      if w.kind == Data and (not w.writer.finished()):
        let res = WriteResult.err(
          WriteError(kind: SocketNotWriteable, currentState: socket.state)
        )
        w.writer.complete(res)
    for r in socket.pendingReads.items():
      # complete every reader with already read bytes
      # TODO: it may be better to refine read API to return
      # Future[Result[seq[byte], E]] and return errors for not finished reads
      if (not r.reader.finished()):
        r.reader.complete(r.bytesAvailable)
    socket.pendingWrites.clear()
    socket.pendingReads.clear()
    # main eventLoop has been cancelled, try to cancel `checkTimeoutsLoop`
    socket.checkTimeoutsLoop.cancel()
    trace "main socket event loop cancelled"
    raise exc

proc startEventLoop(s: UtpSocket) =
  s.eventLoop = eventLoop(s)

proc atEof*(socket: UtpSocket): bool =
  # The socket is considered at eof when the remote side sent us a FIN packet
  # and all packets up to the FIN have been processed.
  socket.offset == 0 and socket.reachedFin

proc readingClosed(socket: UtpSocket): bool =
  socket.atEof() or socket.state == Destroy

proc close*(socket: UtpSocket) =
  ## Gracefully close the connection (send FIN) if the socket is in the
  ## connected state. Does not wait for the socket to close.
  if socket.state != Destroy:
    case socket.state
    of Connected:
      socket.readShutdown = true
      if (not socket.sendFinRequested):
        try:
          debug "Sending FIN", dst = socket.socketKey
          # With this approach, all pending writes will be executed before
          # sending the FIN packet.
          socket.eventQueue.putNoWait(SocketEvent(kind: CloseReq))
        except AsyncQueueFullError as e:
          # Should not happen as our write queue is unbounded.
          raiseAssert e.msg

        socket.sendFinRequested = true
    else:
      # When connection is not established, sending FIN makes no sense, just
      # destroy the socket.
      socket.destroy()

proc closeWait*(socket: UtpSocket) {.async.} =
  ## Gracefully close the connection (send FIN) if the socket is in the
  ## connected state and wait for the socket to be closed.
  ## Warning: if the FIN packet is lost, then the socket might get closed due to
  ## retransmission failures, which will take some time.
  ## The default is 4 retransmissions with doubling of rto between each
  ## retransmission.
  socket.close()
  await socket.closeEvent.wait()

proc write*(socket: UtpSocket, data: seq[byte]): Future[WriteResult] =
  debug "Write data", dst = socket.socketKey, length = len(data)

  let retFuture = newFuture[WriteResult]("UtpSocket.write")

  if (socket.state != Connected):
    let res = WriteResult.err(
      WriteError(kind: SocketNotWriteable, currentState: socket.state))
    retFuture.complete(res)
    return retFuture

  # fin should be last packet received by remote side, therefore trying to write
  # after sending fin is considered error
  if socket.sendFinRequested or socket.finSent:
    let res = WriteResult.err(WriteError(kind: FinSent))
    retFuture.complete(res)
    return retFuture

  var bytesWritten = 0

  if len(data) == 0:
    let res = WriteResult.ok(bytesWritten)
    retFuture.complete(res)
    return retFuture

  try:
    socket.eventQueue.putNoWait(SocketEvent(
      kind: WriteReq, data: data, writer: retFuture))
  except AsyncQueueFullError as e:
    # this should not happen as out write queue is unbounded
    raiseAssert e.msg

  return retFuture

proc read*(socket: UtpSocket, n: Natural): Future[seq[byte]] =
  ## Read all bytes from socket ``socket``.
  ##
  ## This procedure allocates buffer seq[byte] and return it as result.
  let fut = newFuture[seq[uint8]]()

  if socket.readingClosed():
    fut.complete(newSeq[uint8]())
    return fut

  try:
    socket.eventQueue.putNoWait(
      SocketEvent(
        kind:ReadReqType,
        readReq: ReadReq(
          bytesToRead: n,
          bytesAvailable: newSeq[uint8](),
          reader: fut))
    )
  except AsyncQueueFullError as e:
        # should not happen as our write queue is unbounded
        raiseAssert e.msg

  return fut

proc read*(socket: UtpSocket): Future[seq[byte]] =
  ## Read all bytes from socket ``socket``.
  ##
  ## This procedure allocates buffer seq[byte] and return it as result.
  let fut = newFuture[seq[uint8]]()

  if socket.readingClosed():
    fut.complete(newSeq[uint8]())
    return fut

  try:
    socket.eventQueue.putNoWait(
      SocketEvent(
        kind:ReadReqType,
        readReq: ReadReq(
          bytesToRead: 0,
          bytesAvailable: newSeq[uint8](),
          reader: fut))
    )
  except AsyncQueueFullError as e:
        # should not happen as our write queue is unbounded
        raiseAssert e.msg

  return fut

# Check how many packets are still in the out going buffer, usefully for tests
# or debugging.
proc numPacketsInOutGoingBuffer*(socket: UtpSocket): int =
  var num = 0
  for e in socket.outBuffer.items():
    if e.isSome():
      inc num
  num

# Check how many payload bytes are still in flight
proc numOfBytesInFlight*(socket: UtpSocket): uint32 = socket.currentWindow

# Check how many bytes are in incoming buffer
proc numOfBytesInIncomingBuffer*(socket: UtpSocket): uint32 =
  uint32(socket.offset)

# Check how many packets are still in the reorder buffer, useful for tests or
# debugging. It throws assertion error when number of elements in buffer do not
# equal kept counter.
proc numPacketsInReorderedBuffer*(socket: UtpSocket): int =
  var num = 0
  for e in socket.inBuffer.items():
    if e.isSome():
      inc num
  doAssert(num == int(socket.reorderCount))
  num

proc numOfEventsInEventQueue*(socket: UtpSocket): int = len(socket.eventQueue)

proc connectionId*[A](socket: UtpSocket[A]): uint16 =
  ## Connection id is the id which is used in first SYN packet which establishes
  ## the connection, so for `Outgoing` side it is actually its rcv_id, and for
  ## `Incoming` side it is its snd_id.
  case socket.direction
  of Incoming:
    socket.connectionIdSnd
  of Outgoing:
    socket.connectionIdRcv

# Check what is current available window size for this socket
proc currentMaxWindowSize*[A](socket: UtpSocket[A]): uint32 =
  socket.maxWindow

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
  initialAckNr: uint16,
  initialTimeout: Duration
): T =
  let currentTime = getMonoTimestamp().moment

  # Initial max window size. Reference implementation uses value which allows
  # one packet to be transferred.
  # We use a value two times higher as we do not yet have proper mtu estimation,
  # and our impl. should work over UDP and discovery v5 (where proper estimation
  # may be harder as packets already have discovery v5 envelope).
  let initMaxWindow = 2 * cfg.payloadSize
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
    outBufferBytes: 0,
    currentWindow: 0,
    # start with 1mb assumption, field will be updated with first received packet
    maxRemoteWindow: 1024 * 1024,
    maxWindow: initMaxWindow,
    inBuffer: GrowableCircularBuffer[Packet].init(),
    retransmitTimeout: initialTimeout,
    rtoTimeout: currentTime + initialTimeout,
    # Initial timeout values taken from reference implemntation
    rtt: milliseconds(0),
    rttVar: milliseconds(800),
    rto: milliseconds(3000),
    rcvBuffer: newSeq[uint8](int(cfg.optRcvBuffer)),
    pendingReads: initDeque[ReadReq](),
    closeEvent: newAsyncEvent(),
    closeCallbacks: newSeq[Future[void]](),
    pendingWrites: initDeque[WriteRequest](),
    eventQueue: newAsyncQueue[SocketEvent](),
    zeroWindowTimer: none[Moment](),
    socketKey: UtpSocketKey.init(to, rcvId),
    slowStart: true,
    fastTimeout: false,
    fastResendSeqNr: initialSeqNr,
    lastWindowDecay: currentTime - maxWindowDecay,
    slowStartThreshold: cfg.optSndBuffer,
    ourHistogram: DelayHistogram.init(currentTime),
    remoteHistogram: DelayHistogram.init(currentTime),
    driftCalculator: ClockDriftCalculator.init(currentTime),
    send: snd
  )

proc newOutgoingSocket*[A](
  to: A,
  snd: SendCallback[A],
  cfg: SocketConfig,
  rcvConnectionId: uint16,
  rng: var HmacDrbgContext
): UtpSocket[A] =
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
    # Initially ack nr is 0, as we do not know remote initial seqnr
    0,
    cfg.initialSynTimeout
  )

proc newIncomingSocket*[A](
  to: A,
  snd: SendCallback[A],
  cfg: SocketConfig,
  connectionId: uint16,
  ackNr: uint16,
  rng: var HmacDrbgContext
): UtpSocket[A] =
  let initialSeqNr = randUint16(rng)

  let (initialState, initialTimeout) =
    if (cfg.incomingSocketReceiveTimeout.isNone()):
      # it does not matter what timeout value we put here, as socket will be in
      # connected state without outgoing packets in buffer so any timeout hit
      # will just double rto without any penalties
      # although we cannot use 0, as then timeout will be constantly re-set to
      # 500ms and there will be a lot of not useful work done
      (Connected, defaultInitialSynTimeout)
    else:
      let timeout = cfg.incomingSocketReceiveTimeout.unsafeGet()
      (SynRecv, timeout)

  UtpSocket[A].new(
    to,
    snd,
    initialState,
    cfg,
    Incoming,
    connectionId + 1,
    connectionId,
    initialSeqNr,
    ackNr,
    initialTimeout
  )

proc getSocketConfig*(socket: UtpSocket): SocketConfig =
  socket.socketConfig

proc startIncomingSocket*(socket: UtpSocket) =
  # Make sure ack was flushed before moving forward
  socket.sendAck()
  socket.startEventLoop()
  socket.startTimeoutLoop()

proc startOutgoingSocket*(socket: UtpSocket): Future[void] =
  doAssert(socket.state == SynSent)
  let packet =
    synPacket(socket.seqNr, socket.connectionIdRcv, socket.getRcvWindowSize())
  debug "Sending SYN packet",
    seqNr = packet.header.seqNr,
    connectionId = packet.header.connectionId
  # set number of transmissions to 1 as syn packet will be send just after
  # initialization
  let outgoingPacket = OutgoingPacket.init(encodePacket(packet), 1, false, 0)
  socket.registerOutgoingPacket(outgoingPacket)
  socket.startEventLoop()
  socket.startTimeoutLoop()
  socket.sendData(outgoingPacket.packetBytes)
  return socket.connectionFuture
