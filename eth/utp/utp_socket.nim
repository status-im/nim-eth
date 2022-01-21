# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/sugar,
  chronos, chronicles, bearssl,
  stew/[results, bitops2],
  ./send_buffer_tracker,
  ./growable_buffer,
  ./packets,
  ./ledbat_congestion_control,
  ./delay_histogram,
  ./utp_utils,
  ./clock_drift_calculator

export
  chronicles

logScope:
  topics = "utp_socket"

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
  SendCallback*[A] = proc (to: A, data: seq[byte]): Future[void] {.gcsafe, raises: [Defect]}

  SocketConfig* = object
    # This is configurable (in contrast to reference impl), as with standard 2 syn resends
    # default timeout set to 3seconds and doubling of timeout with each re-send, it
    # means that initial connection would timeout after 21s, which seems rather long
    initialSynTimeout*: Duration

    # Number of resend re-tries of each data packet, before daclaring connection
    # failed
    dataResendsBeforeFailure*: uint16

    # Maximnal size of receive buffer in bytes
    optRcvBuffer*: uint32

    # Maximnal size of send buffer in bytes
    optSndBuffer*: uint32

    # If set to some(`Duration`), the incoming socket will be initialized in
    # `SynRecv` state and the remote peer will have `Duration` to transfer data
    # to move the socket in `Connected` state.
    # If set to none, the incoming socket will immediately be set to `Connected`
    # state and will be able to transfer data.
    incomingSocketReceiveTimeout*: Option[Duration]

    # Timeout after which the send window will be reset to its minimal value after it dropped
    # to zero. i.e when we received a packet from remote peer with `wndSize` set to 0.
    remoteWindowResetTimeout*: Duration

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

  UtpSocket*[A] = ref object
    remoteAddress*: A
    state: ConnectionState
    direction: ConnectionDirection
    socketConfig: SocketConfig

    # Connection id for packets we receive
    connectionIdRcv*: uint16
    # Connection id for packets we send
    connectionIdSnd*: uint16
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

    # Event which will complete whenever socket gets in destory state
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

    sendBufferTracker: SendBufferTracker

    writeQueue: AsyncQueue[WriteRequest]

    writeLoop: Future[void]

    zeroWindowTimer: Moment

    # last measured delay between current local timestamp, and remote sent
    # timestamp. In microseconds
    replayMicro: uint32

    # indicator if we're in slow-start (exponential growth) phase
    slowStart: bool

    #the slow-start threshold, in bytes
    slowStartTreshold: uint32

    # history of our delays
    ourHistogram: DelayHistogram

    # history of remote delays
    remoteHistogram: DelayHistogram

    # calculator of drifiting between local and remote clocks
    driftCalculator: ClockDriftCalculator

    # socket identifier
    socketKey*: UtpSocketKey[A]

    send: SendCallback[A]

  # User driven call back to be called whenever socket is permanently closed i.e
  # reaches destroy state
  SocketCloseCallback* = proc (): void {.gcsafe, raises: [Defect].}

  ConnectionError* = object of CatchableError

  OutgoingConnectionErrorType* = enum
    SocketAlreadyExists, ConnectionTimedOut, ErrorWhileSendingSyn

  OutgoingConnectionError* = object
    case kind*: OutgoingConnectionErrorType
    of ErrorWhileSendingSyn:
      error*: ref CatchableError
    of SocketAlreadyExists, ConnectionTimedOut:
      discard

  ConnectionResult*[A] = Result[UtpSocket[A], OutgoingConnectionError]

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
  # packet.
  defaultRcvRetransmitTimeout = milliseconds(10000)

  # Number of times each data packet will be resend before declaring connection
  # dead. 4 is taken from reference implementation
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

  # Timeout after which the send window will be reset to its minimal value after it dropped
  # to zero. i.e when we received a packet from remote peer with `wndSize` set to 0.
  defaultResetWindowTimeout = seconds(15)

  # If remote peer window drops to zero, then after some time we will reset it
  # to this value even if we do not receive any more messages from remote peers.
  # Reset period is configured in `SocketConfig`
  minimalRemoteWindow: uint32 = 1500

  # Initial max window size. Reference implementation uses value which enables one packet
  # to be transfered.
  # We use value two times higher as we do not yet have proper mtu estimation, and
  # our impl should work over udp and discovery v5 (where proper estmation may be harder
  # as packets already have discvoveryv5 envelope)
  startMaxWindow* = 2 * mtuSize

  reorderBufferMaxSize = 1024

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
  optSndBuffer: uint32 = defaultOptRcvBuffer
  ): T =
  SocketConfig(
    initialSynTimeout: initialSynTimeout,
    dataResendsBeforeFailure: dataResendsBeforeFailure,
    optRcvBuffer: optRcvBuffer,
    optSndBuffer: optSndBuffer,
    incomingSocketReceiveTimeout: incomingSocketReceiveTimeout,
    remoteWindowResetTimeout: remoteWindowResetTimeout
  )

proc getRcvWindowSize(socket: UtpSocket): uint32 =
  let currentDataSize = socket.buffer.dataLen()
  if currentDataSize > int(socket.socketConfig.optRcvBuffer):
    0'u32
  else:
    socket.socketConfig.optRcvBuffer - uint32(currentDataSize)

proc registerOutgoingPacket(socket: UtpSocket, oPacket: OutgoingPacket) =
  ## Adds packet to outgoing buffer and updates all related fields
  socket.outBuffer.ensureSize(socket.seqNr, socket.curWindowPackets)
  socket.outBuffer.put(socket.seqNr, oPacket)
  inc socket.seqNr
  inc socket.curWindowPackets

proc sendData(socket: UtpSocket, data: seq[byte]): Future[void] =
  let f = socket.send(socket.remoteAddress, data)
  f.callback = proc(data: pointer) {.gcsafe.} =
    if f.failed:
      warn "UTP send failed", msg = f.readError.msg
  return f

# Should be called before sending packet
proc setSend(s: UtpSocket, p: var OutgoingPacket): seq[byte] =
  let timestampInfo = getMonoTimestamp()

  inc p.transmissions
  p.needResend = false
  p.timeSent = timestampInfo.moment
  # all bytearrays in outgoing buffer should be properly encoded utp packets
  # so it is safe to directly modify fields
  modifyTimeStampAndAckNr(p.packetBytes, timestampInfo.timestamp, s.ackNr)

  return p.packetBytes

proc flushPackets(socket: UtpSocket) {.async.} =
  var i: uint16 = socket.seqNr - socket.curWindowPackets
  while i != socket.seqNr:
    # sending only packet which were not transmitted yet or need a resend
    let shouldSendPacket = socket.outBuffer.exists(i, (p: OutgoingPacket) => (p.transmissions == 0 or p.needResend == true))
    if (shouldSendPacket):
      if socket.sendBufferTracker.reserveNBytes(socket.outBuffer[i].payloadLength):
        debug "Resending packet during flush",
          pkSeqNr = i
        let toSend = socket.setSend(socket.outBuffer[i])
        await socket.sendData(toSend)
      else:
        debug "Should resend packet during flush but there is no place in send buffer",
          pkSeqNr = i
        # there is no place in send buffer, stop flushing
        return
    inc i

proc markAllPacketAsLost(s: UtpSocket) =
  var i = 0'u16
  while i < s.curWindowPackets:

    let packetSeqNr = s.seqNr - 1 - i
    if (s.outBuffer.exists(packetSeqNr, (p: OutgoingPacket) => p.transmissions > 0 and p.needResend == false)):
      debug "Marking packet as lost",
        pkSeqNr = packetSeqNr
      s.outBuffer[packetSeqNr].needResend = true
      let packetPayloadLength = s.outBuffer[packetSeqNr].payloadLength
      # lack of waiters notification in case of timeout effectivly means that
      # we do not allow any new bytes to enter snd buffer in case of new free space
      # due to timeout.
      s.sendBufferTracker.decreaseCurrentWindow(packetPayloadLength, notifyWaiters = false)

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

proc checkTimeouts(socket: UtpSocket) {.async.} =
  let currentTime = getMonoTimestamp().moment
  # flush all packets which needs to be re-send
  if socket.state != Destroy:
    await socket.flushPackets()

  if socket.isOpened():

    if (socket.sendBufferTracker.maxRemoteWindow == 0 and currentTime > socket.zeroWindowTimer):
      debug "Reset remote window to minimal value"
      socket.sendBufferTracker.updateMaxRemote(minimalRemoteWindow)

    if (currentTime > socket.rtoTimeout):
      debug "CheckTimeouts rto timeout",
        socketKey = socket.socketKey,
        state = socket.state,
        maxWindow = socket.sendBufferTracker.maxWindow,
        curWindowPackets = socket.curWindowPackets,
        curWindowBytes = socket.sendBufferTracker.currentWindow

      # TODO add handling of probe time outs. Reference implemenation has mechanism
      # of sending probes to determine mtu size. Probe timeouts do not count to standard
      # timeouts calculations

      # client initiated connections, but did not send following data packet in rto
      # time and our socket is configured to start in SynRecv state.
      if (socket.state == SynRecv):
        socket.destroy()
        return

      if socket.shouldDisconnectFromFailedRemote():
        debug "Remote host failed",
          state = socket.state,
          retransmitCount = socket.retransmitCount 

        if socket.state == SynSent and (not socket.connectionFuture.finished()):
          socket.connectionFuture.fail(newException(ConnectionError, "Connection to peer timed out"))

        socket.destroy()
        return

      let newTimeout = socket.retransmitTimeout * 2
      socket.retransmitTimeout = newTimeout
      socket.rtoTimeout = currentTime + newTimeout

      let currentPacketSize = uint32(socket.getPacketSize())

      if (socket.curWindowPackets == 0 and socket.sendBufferTracker.maxWindow > currentPacketSize):
        # there are no packets in flight even though there is place for more than whole packet
        # this means connection is just idling. Reset window by 1/3'rd but no more
        # than to fit at least one packet.
        let oldMaxWindow = socket.sendBufferTracker.maxWindow
        let newMaxWindow = max((oldMaxWindow * 2) div 3,  currentPacketSize)

        debug "Decaying max window due to socket idling",
          oldMaxWindow = oldMaxWindow,
          newMaxWindow = newMaxWindow
      
        socket.sendBufferTracker.updateMaxWindowSize(
          # maxRemote window does not change
          socket.sendBufferTracker.maxRemoteWindow,
          newMaxWindow
        )
      elif (socket.sendBufferTracker.maxWindow < currentPacketSize):
        # due to high delay window has shrunk below packet size
        # which means that we cannot send more data
        # reset it to fit at least one packet
        debug "Reseting window size do fit a least one packet",
          oldWindowSize = socket.sendBufferTracker.maxWindow,
          newWindowSize = currentPacketSize

        # delay was so high that window has shrunk below one packet. Reset window
        # to fit a least one packet and start with slow start
        socket.sendBufferTracker.updateMaxWindowSize(
          # maxRemote window does not change
          socket.sendBufferTracker.maxRemoteWindow,
          currentPacketSize
        )
        socket.slowStart = true

      # This will have much more sense when we will add handling of selective acks
      # as then every selecivly acked packet restes timeout timer and removes packet
      # from out buffer.
      markAllPacketAsLost(socket)

      # resend oldest packet if there are some packets in flight
      if (socket.curWindowPackets > 0):
        inc socket.retransmitCount
        let oldestPacketSeqNr = socket.seqNr - socket.curWindowPackets
        # TODO add handling of fast timeout

        doAssert(
          socket.outBuffer.get(oldestPacketSeqNr).isSome(),
          "oldest packet should always be available when there is data in flight"
        )

        let payloadLength = socket.outBuffer[oldestPacketSeqNr].payloadLength
        if (socket.sendBufferTracker.reserveNBytes(payloadLength)):
          debug "Resending oldest packet in outBuffer",
            seqNr = oldestPacketSeqNr,
            curWindowPackets = socket.curWindowPackets

          let dataToSend = socket.setSend(socket.outBuffer[oldestPacketSeqNr])
          await socket.sendData(dataToSend)
        else:
          # TODO Logs added here to check if we need to check for spcae in send buffer
          # reference impl does not do it.
          debug "Should resend oldest packet in outBuffer but there is no place for more bytes in send buffer",
            seqNr = oldestPacketSeqNr,
            curWindowPackets = socket.curWindowPackets


    # TODO add sending keep alives when necessary

proc checkTimeoutsLoop(s: UtpSocket) {.async.} =
  ## Loop that check timeouts in the socket.
  try:
    while true:
      await sleepAsync(checkTimeoutsLoopInterval)
      await s.checkTimeouts()
  except CancelledError:
    trace "checkTimeoutsLoop canceled"

proc startTimeoutLoop(s: UtpSocket) =
  s.checkTimeoutsLoop = checkTimeoutsLoop(s)

proc getPacketSize*(socket: UtpSocket): int =
  # TODO currently returning constant, ultimatly it should be bases on mtu estimates
  mtuSize

proc resetSendTimeout(socket: UtpSocket) =
  socket.retransmitTimeout = socket.rto
  socket.rtoTimeout = getMonoTimestamp().moment + socket.retransmitTimeout

proc handleDataWrite(socket: UtpSocket, data: seq[byte], writeFut: Future[WriteResult]): Future[void] {.async.} =
      if writeFut.finished():
        # write future was cancelled befere we got chance to process it, short circuit
        # processing and move to next loop iteration
        return

      let pSize = socket.getPacketSize()
      let endIndex = data.high()
      var i = 0
      var bytesWritten = 0
      let wndSize = socket.getRcvWindowSize()

      while i <= endIndex:
        let lastIndex = i + pSize - 1
        let lastOrEnd = min(lastIndex, endIndex)
        let dataSlice = data[i..lastOrEnd]
        let payloadLength =  uint32(len(dataSlice))
        try:
          await socket.sendBufferTracker.reserveNBytesWait(payloadLength)
          if socket.curWindowPackets == 0:
            socket.resetSendTimeout()

          let dataPacket =
            dataPacket(
              socket.seqNr,
              socket.connectionIdSnd,
              socket.ackNr,
              wndSize,
              dataSlice,
              socket.replayMicro
            )
          let outgoingPacket = OutgoingPacket.init(encodePacket(dataPacket), 1, false, payloadLength)
          socket.registerOutgoingPacket(outgoingPacket)
          await socket.sendData(outgoingPacket.packetBytes)
        except CancelledError as exc:
          # write loop has been cancelled in the middle of processing due to the
          # socket closing
          # this approach can create partial write in case destroyin socket in the
          # the middle of the write
          doAssert(socket.state == Destroy)
          if (not writeFut.finished()):
             let res = Result[int, WriteError].err(WriteError(kind: SocketNotWriteable, currentState: socket.state))
             writeFut.complete(res)
          # we need to re-raise exception so the outer loop will be properly cancelled too
          raise exc
        bytesWritten = bytesWritten + len(dataSlice)
        i = lastOrEnd + 1

      # Before completeing future with success (as all data was sent sucessfuly)
      # we need to check if user did not cancel write on his end
      if (not writeFut.finished()):
        writeFut.complete(Result[int, WriteError].ok(bytesWritten))

proc handleClose(socket: UtpSocket): Future[void] {.async.} =
  try:
    if socket.curWindowPackets == 0:
      socket.resetSendTimeout()

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
    socket.registerOutgoingPacket(OutgoingPacket.init(finEncoded, 1, true, 0))
    await socket.sendData(finEncoded)
    socket.finSent = true
  except CancelledError as exc:
    raise exc

proc writeLoop(socket: UtpSocket): Future[void] {.async.} =
  ## Loop that processes writes on socket
  try:
    while true:
      let req = await socket.writeQueue.get()
      case req.kind
      of Data:
        await socket.handleDataWrite(req.data, req.writer)
        info "Written data to remote",
          to = socket.socketKey,
          bytesWritten = len(req.data)
      of Close:
        await socket.handleClose()
        info "Sent FIN to remote",
          to = socket.socketKey

  except CancelledError:
    doAssert(socket.state == Destroy)
    for req in socket.writeQueue.items:
      if (req.kind == Data and not req.writer.finished()):
        let res = Result[int, WriteError].err(WriteError(kind: SocketNotWriteable, currentState: socket.state))
        req.writer.complete(res)
    socket.writeQueue.clear()
    trace "writeLoop canceled"

proc startWriteLoop(s: UtpSocket) =
  s.writeLoop = writeLoop(s)

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
    rtoTimeout: currentTime + initialTimeout,
    # Initial timeout values taken from reference implemntation
    rtt: milliseconds(0),
    rttVar: milliseconds(800),
    rto: milliseconds(3000),
    buffer: AsyncBuffer.init(int(cfg.optRcvBuffer)),
    closeEvent: newAsyncEvent(),
    closeCallbacks: newSeq[Future[void]](),
    # start with 1mb assumption, field will be updated with first received packet
    sendBufferTracker: SendBufferTracker.new(0, 1024 * 1024, cfg.optSndBuffer, startMaxWindow),
    # queue with infinite size
    writeQueue: newAsyncQueue[WriteRequest](),
    zeroWindowTimer: currentTime + cfg.remoteWindowResetTimeout,
    socketKey: UtpSocketKey.init(to, rcvId),
    slowStart: true,
    slowStartTreshold: cfg.optSndBuffer,
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
  rng: var BrHmacDrbgContext
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
    # Initialy ack nr is 0, as we do not know remote inital seqnr
    0,
    cfg.initialSynTimeout
  )

proc newIncomingSocket*[A](
  to: A,
  snd: SendCallback[A],
  cfg: SocketConfig,
  connectionId: uint16,
  ackNr: uint16,
  rng: var BrHmacDrbgContext
): UtpSocket[A] =
  let initialSeqNr = randUint16(rng)

  let (initialState, initialTimeout) =
    if (cfg.incomingSocketReceiveTimeout.isNone()):
      # it does not matter what timeout value we put here, as socket will be in
      # connected state without outgoing packets in buffer so any timeout hit will
      # just double rto without any penalties
      # although we cannont use 0, as then timeout will be constantly re-set to 500ms
      # and there will be a lot of not usefull work done
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

proc startOutgoingSocket*(socket: UtpSocket): Future[void] {.async.} =
  doAssert(socket.state == SynSent)
  let packet = synPacket(socket.seqNr, socket.connectionIdRcv, socket.getRcvWindowSize())
  debug "Sending SYN packet", 
    seqNr = packet.header.seqNr,
    connectionId = packet.header.connectionId
  # set number of transmissions to 1 as syn packet will be send just after
  # initiliazation
  let outgoingPacket = OutgoingPacket.init(encodePacket(packet), 1, false, 0)
  socket.registerOutgoingPacket(outgoingPacket)
  socket.startWriteLoop()
  socket.startTimeoutLoop()
  await socket.sendData(outgoingPacket.packetBytes)
  await socket.connectionFuture

proc isConnected*(socket: UtpSocket): bool =
  socket.state == Connected

proc isClosed*(socket: UtpSocket): bool =
  socket.state == Destroy and socket.closeEvent.isSet()

proc destroy*(s: UtpSocket) =
  info "Destroying socket",
    to = s.socketKey
  ## Moves socket to destroy state and clean all reasources.
  ## Remote is not notified in any way about socket end of life
  s.state = Destroy
  s.writeLoop.cancel()
  s.checkTimeoutsLoop.cancel()
  s.closeEvent.fire()

proc destroyWait*(s: UtpSocket) {.async.} =
  ## Moves socket to destroy state and clean all reasources and wait for all registered
  ## callback to fire
  ## Remote is not notified in any way about socket end of life
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
      pkNeedReesend = packet.needResend

    # from spec: The rtt and rtt_var is only updated for packets that were sent only once.
    # This avoids problems with figuring out which packet was acked, the first or the second one.
    # it is standard solution to retransmission ambiguity problem
    if packet.transmissions == 1:
      socket.updateTimeouts(packet.timeSent, currentTime)

    socket.retransmitTimeout = socket.rto
    socket.rtoTimeout = currentTime + socket.rto

    # if need_resend is set, this packet has already
    # been considered timed-out, and is not included in
    # the cur_window anymore
    if (not packet.needResend):
      socket.sendBufferTracker.decreaseCurrentWindow(packet.payloadLength, notifyWaiters = true)

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
    let result = socket.ackPacket(socket.seqNr - socket.curWindowPackets, currentTime)
    case result
    of PacketAcked:
      dec socket.curWindowPackets
    of PacketAlreadyAcked:
      dec socket.curWindowPackets
    of PacketNotSentYet:
      debug "Tried to ack packed which was not sent yet"
      break

    inc i

proc calculateAckedbytes(socket: UtpSocket, nrPacketsToAck: uint16, now: Moment): (uint32, Duration) =
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
proc calculateSelectiveAckBytes*(socket: UtpSocket,  receivedPackedAckNr: uint16, ext: SelectiveAckExtension): uint32 =
  # we add 2, as the first bit in the mask therefore represents ackNr + 2 becouse
  # ackNr + 1 (i.e next expected packet) is considered lost.
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

# ack packets (removes them from out going buffer) based on selective ack extension header
proc selectiveAckPackets(socket: UtpSocket,  receivedPackedAckNr: uint16, ext: SelectiveAckExtension, currentTime: Moment): void =
   # we add 2, as the first bit in the mask therefore represents ackNr + 2 becouse
  # ackNr + 1 (i.e next expected packet) is considered lost.
  let base = receivedPackedAckNr + 2

  if socket.curWindowPackets == 0:
    return

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
      discard socket.ackPacket(v, currentTime)

    dec bits

  # TODO Add handling of fast timeouts and duplicate acks counting

# Public mainly for test purposes
# generates bit mask which indicates which packets are already in socket
# reorder buffer
# from speck:
# The bitmask has reverse byte order. The first byte represents packets [ack_nr + 2, ack_nr + 2 + 7] in reverse order
# The least significant bit in the byte represents ack_nr + 2, the most significant bit in the byte represents ack_nr + 2 + 7
# The next byte in the mask represents [ack_nr + 2 + 8, ack_nr + 2 + 15] in reverse order, and so on
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

    ackPacket(
      socket.seqNr,
      socket.connectionIdSnd,
      socket.ackNr,
      socket.getRcvWindowSize(),
      socket.replayMicro,
      bitmask
    )

proc sendAck(socket: UtpSocket): Future[void] =
  ## Creates and sends ack, based on current socket state. Acks are different from
  ## other packets as we do not track them in outgoing buffet

  let ackPacket = socket.generateAckPacket()

  debug "Sending STATE packet",
    pkSeqNr = ackPacket.header.seqNr,
    pkAckNr = ackPacket.header.ackNr,
    gotEACK = ackPacket.eack.isSome()

  socket.sendData(encodePacket(ackPacket))

proc startIncomingSocket*(socket: UtpSocket) {.async.} =
  # Make sure ack was flushed before moving forward
  await socket.sendAck()
  socket.startWriteLoop()
  socket.startTimeoutLoop()

# TODO at socket level we should handle only FIN/DATA/ACK packets. Refactor to make
# it enforcable by type system
# TODO re-think synchronization of this procedure, as each await inside gives control
# to scheduler which means there could be potentialy several processPacket procs
# running
proc processPacket*(socket: UtpSocket, p: Packet) {.async.} =

  debug "Process packet",
    socketKey = socket.socketKey,
    socketAckNr = socket.ackNr,
    socketSeqNr = socket.seqNr,
    windowPackets = socket.curWindowPackets,
    packetType = p.header.pType,
    seqNr = p.header.seqNr,
    ackNr = p.header.ackNr,
    timestamp = p.header.timestamp,
    timestampDiff = p.header.timestampDiff

  let timestampInfo = getMonoTimestamp()

  if socket.isAckNrInvalid(p):
    debug "Received packet with invalid ack number",
      ackNr = p.header.ackNr,
      localSeqNr = socket.seqNr,
      lastUnacked = socket.seqNr - socket.curWindowPackets

    return

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

  debug "Packet state variables",
    pastExpected = pastExpected,
    acks = acks

  # If packet is totally of the mark short circout the processing
  if pastExpected >= reorderBufferMaxSize:

    # if `pastExpected` is really big number (for example: uint16.high) then most
    # probably we are receiving packet which we already received
    # example: we already received packet with `seqNr = 10` so our `socket.ackNr = 10`
    # if we receive this packet once again then `pastExpected = 10 - 10 - 1` which 
    # equals (due to wrapping) 65535
    # this means that remote most probably did not receive our ack, so we need to resend
    # it. We are doing it for last `reorderBufferMaxSize` packets
    let isPossibleDuplicatedOldPacket = pastExpected >= (int(uint16.high) + 1) - reorderBufferMaxSize

    if (isPossibleDuplicatedOldPacket and p.header.pType != ST_STATE):
      asyncSpawn socket.sendAck()

    debug "Got an invalid packet sequence number, too far off",
      pastExpected = pastExpected
    return

  var (ackedBytes, minRtt) = socket.calculateAckedbytes(acks, timestampInfo.moment)

  debug "Bytes acked by classic ack",
      bytesAcked = ackedBytes
  
  if (p.eack.isSome()):
    let selectiveAckedBytes = socket.calculateSelectiveAckBytes(pkAckNr, p.eack.unsafeGet())
    debug "Bytes acked by selective ack",
      bytesAcked = selectiveAckedBytes
    ackedBytes = ackedBytes + selectiveAckedBytes

  let sentTimeRemote = p.header.timestamp

  # we are using uint32 not a Duration, to wrap a round in case of
  # sentTimeRemote > receipTimestamp. This can happen as local and remote
  # clock can be not synchornized or even using different system clock.
  # i.e this number itself does not tell anything and is only used to feedback it
  # to remote peer with each sent packet
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
        socket.ourHistogram.shift(prevRemoteDelayBase - socket.remoteHistogram.delayBase)

  let actualDelay = p.header.timestampDiff

  if actualDelay != 0:
    socket.ourHistogram.addSample(actualDelay, timestampInfo.moment)
    socket.driftCalculator.addSample(actualDelay, timestampInfo.moment)

  # adjust base delay if delay estimates exceeds rtt
  if (socket.ourHistogram.getValue() > minRtt):
    let diff = uint32((socket.ourHistogram.getValue() - minRtt).microseconds())
    socket.ourHistogram.shift(diff)

  let (newMaxWindow, newSlowStartTreshold, newSlowStart) =
    applyCongestionControl(
      socket.sendBufferTracker.maxWindow,
      socket.slowStart,
      socket.slowStartTreshold,
      socket.socketConfig.optSndBuffer,
      uint32(socket.getPacketSize()),
      microseconds(actualDelay),
      ackedBytes,
      minRtt,
      socket.ourHistogram.getValue(),
      socket.driftCalculator.clockDrift
    )

  # update remote window size and max window
  socket.sendBufferTracker.updateMaxWindowSize(p.header.wndSize, newMaxWindow)
  socket.slowStart = newSlowStart
  socket.slowStartTreshold = newSlowStartTreshold

  debug "Applied ledbat congestion controller",
    maxWindow = newMaxWindow,
    remoteWindow = p.header.wndSize,
    slowStartTreshold = newSlowStartTreshold,
    slowstart = newSlowStart

  if (socket.sendBufferTracker.maxRemoteWindow == 0):
    # when zeroWindowTimer will be hit and maxRemoteWindow still will be equal to 0
    # then it will be reset to minimal value
    socket.zeroWindowTimer = timestampInfo.moment + socket.socketConfig.remoteWindowResetTimeout

    debug "Remote window size dropped to 0",
      currentTime = timestampInfo.moment,
      resetZeroWindowTime = socket.zeroWindowTimer

  # socket.curWindowPackets == acks means that this packet acked all remaining packets
  # including the sent fin packets
  if (socket.finSent and socket.curWindowPackets == acks):
    debug "FIN acked, destroying socket"
    socket.finAcked = true
    # this bit of utp spec is a bit under specified (i.e there is not specification at all)
    # reference implementation moves socket to destroy state in case that our fin was acked
    # and socket is considered closed for reading and writing.
    # but in theory remote could stil write some data on this socket (or even its own fin)
    socket.destroy()

  socket.ackPackets(acks, timestampInfo.moment)

  # packets in front may have been acked by selective ack, decrease window until we hit
  # a packet that is still waiting to be acked
  while (socket.curWindowPackets > 0 and socket.outBuffer.get(socket.seqNr - socket.curWindowPackets).isNone()):
    dec socket.curWindowPackets
    debug "Packet in front hase been acked by selective ack. Decrese window",
      windowPackets = socket.curWindowPackets

  if (p.eack.isSome()):
    socket.selectiveAckPackets(pkAckNr, p.eack.unsafeGet(), timestampInfo.moment)

  case p.header.pType
    of ST_DATA, ST_FIN:
      # To avoid amplification attacks, server socket is in SynRecv state until
      # it receices first data transfer
      # https://www.usenix.org/system/files/conference/woot15/woot15-paper-adamsky.pdf
      # Socket is in SynRecv state only when recv timeout is configured
      if (socket.state == SynRecv and p.header.pType == ST_DATA):
        socket.state = Connected

      if (p.header.pType == ST_FIN and (not socket.gotFin)):
        debug "Received FIN packet",
          eofPktNr = pkSeqNr,
          curAckNr = socket.ackNr

        socket.gotFin = true
        socket.eofPktNr = pkSeqNr

      # we got in order packet
      if (pastExpected == 0 and (not socket.reachedFin)):
        debug "Received in order packet"
        if (len(p.payload) > 0 and (not socket.readShutdown)):
          debug "Received data packet",
            bytesReceived = len(p.payload)
          # we are getting in order data packet, we can flush data directly to the incoming buffer
          await upload(addr socket.buffer, unsafeAddr p.payload[0], p.payload.len())
        # Bytes have been passed to upper layer, we can increase number of last
        # acked packet
        inc socket.ackNr

        # check if the following packets are in reorder buffer

        debug "Looking for packets in re-order buffer",
          reorderCount = socket.reorderCount

        while true:
          # We are doing this in reoreder loop, to handle the case when we already received
          # fin but there were some gaps before eof
          # we have reached remote eof, and should not receive more packets from remote
          if ((not socket.reachedFin) and socket.gotFin and socket.eofPktNr == socket.ackNr):
            debug "Reached socket EOF"
            # In case of reaching eof, it is up to user of library what to to with
            # it. With the current implementation, the most apropriate way would be to
            # destory it (as with our implementation we know that remote is destroying its acked fin)
            # as any other send will either generate timeout, or socket will be forcefully
            # closed by reset
            socket.reachedFin = true
            # this is not necessarily true, but as we have already reached eof we can
            # ignore following packets
            socket.reorderCount = 0

            # notify all readers we have reached eof
            socket.buffer.forget()

          if socket.reorderCount == 0:
            break

          let nextPacketNum = socket.ackNr + 1

          let maybePacket = socket.inBuffer.get(nextPacketNum)

          if maybePacket.isNone():
            break

          let packet = maybePacket.unsafeGet()

          if (len(packet.payload) > 0 and (not socket.readShutdown)):
            debug "Got packet from reorder buffer",
              packetBytes = len(packet.payload),
              packetSeqNr = packet.header.seqNr,
              packetAckNr = packet.header.ackNr,
              socketSeqNr = socket.seqNr,
              socekrAckNr = socket.ackNr

            await upload(addr socket.buffer, unsafeAddr packet.payload[0], packet.payload.len())

          socket.inBuffer.delete(nextPacketNum)

          inc socket.ackNr
          dec socket.reorderCount

        debug "Socket state after processing in order packet",
          socketKey = socket.socketKey,
          socketAckNr = socket.ackNr,
          reorderCount = socket.reorderCount,
          windowPackets = socket.curWindowPackets

        # TODO for now we just schedule concurrent task with ack sending. It may
        # need improvement, as with this approach there is no direct control over
        # how many concurrent tasks there are and how to cancel them when socket
        # is closed
        asyncSpawn socket.sendAck()

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
          socket.inBuffer.put(pkSeqNr, p)
          inc socket.reorderCount
          debug "added out of order packet to reorder buffer",
            reorderCount = socket.reorderCount
          # we send ack packet, as we reoreder count is > 0, so the eack bitmask will be 
          # generated
          asyncSpawn socket.sendAck()

    of ST_STATE:
      if (socket.state == SynSent and (not socket.connectionFuture.finished())):
        socket.state = Connected
        # TODO reference implementation sets ackNr (p.header.seqNr - 1), although
        # spec mention that it should be equal p.header.seqNr. For now follow the
        # reference impl to be compatible with it. Later investigate trin compatibility.
        socket.ackNr = p.header.seqNr - 1
        # In case of SynSent complate the future as last thing to make sure user of libray will
        # receive socket in correct state
        socket.connectionFuture.complete()

    of ST_RESET:
      debug "Received ST_RESET on known socket, ignoring"
    of ST_SYN:
      debug "Received ST_SYN on known socket, ignoring"

proc atEof*(socket: UtpSocket): bool =
  # socket is considered at eof when remote side sent us fin packet
  # and we have processed all packets up to fin
  socket.buffer.dataLen() == 0 and socket.reachedFin

proc readingClosed(socket: UtpSocket): bool =
  socket.atEof() or socket.state == Destroy

proc close*(socket: UtpSocket) =
  ## Gracefully closes conneciton (send FIN) if socket is in connected state
  ## does not wait for socket to close
  if socket.state != Destroy:
    case socket.state
    of Connected:
      socket.readShutdown = true
      if (not socket.sendFinRequested):
        try:
          info "Sending FIN",
            to = socket.socketKey
          # with this approach, all pending writes will be executed before sending fin packet
          # we could also and method which places close request as first one to process
          # but it would complicate the write loop
          socket.writeQueue.putNoWait(WriteRequest(kind: Close))
        except AsyncQueueFullError as e:
          # should not happen as our write queue is unbounded
          raiseAssert e.msg

        socket.sendFinRequested = true
    else:
      # In any other case like connection is not established so sending fin make
      # no sense, we can just out right close it
      socket.destroy()

proc closeWait*(socket: UtpSocket) {.async.} =
  ## Gracefully closes conneciton (send FIN) if socket is in connected state
  ## and waits for socket to be closed.
  ## Warning: if FIN packet for some reason will be lost, then socket will be closed
  ## due to retransmission failure which may take some time.
  ## default is 4 retransmissions with doubling of rto between each retranssmision
  socket.close()
  await socket.closeEvent.wait()

proc write*(socket: UtpSocket, data: seq[byte]): Future[WriteResult] =
  info "Write data",
    to = socket.socketKey,
    length = len(data)

  let retFuture = newFuture[WriteResult]("UtpSocket.write")

  if (socket.state != Connected):
    let res = Result[int, WriteError].err(WriteError(kind: SocketNotWriteable, currentState: socket.state))
    retFuture.complete(res)
    return retFuture

  # fin should be last packet received by remote side, therefore trying to write
  # after sending fin is considered error
  if socket.sendFinRequested or socket.finSent:
    let res = Result[int, WriteError].err(WriteError(kind: FinSent))
    retFuture.complete(res)
    return retFuture

  var bytesWritten = 0

  if len(data) == 0:
    let res = Result[int, WriteError].ok(bytesWritten)
    retFuture.complete(res)
    return retFuture

  try:
    socket.writeQueue.putNoWait(WriteRequest(kind: Data, data: data, writer: retFuture))
  except AsyncQueueFullError as e:
    # this should not happen as out write queue is unbounded
    raiseAssert e.msg

  return retFuture

template readLoop(body: untyped): untyped =
  while true:
    let (consumed, done) = body
    socket.buffer.shift(consumed)
    if done:
      break
    else:
      if not(socket.readingClosed()):
        await socket.buffer.wait()

proc read*(socket: UtpSocket, n: Natural): Future[seq[byte]] {.async.}=
  ## Read all bytes `n` bytes from socket ``socket``.
  ##
  ## This procedure allocates buffer seq[byte] and return it as result.
  var bytes = newSeq[byte]()

  if n == 0:
    return bytes

  readLoop():
    if socket.readingClosed():
      (0, true)
    else:
      let count = min(socket.buffer.dataLen(), n - len(bytes))
      bytes.add(socket.buffer.buffer.toOpenArray(0, count - 1))
      (count, len(bytes) == n)

  debug "Read data ",
    remote = socket.socketKey,
    length = n

  return bytes

proc read*(socket: UtpSocket): Future[seq[byte]] {.async.}=
  ## Read all bytes from socket ``socket``.
  ##
  ## This procedure allocates buffer seq[byte] and return it as result.
  var bytes = newSeq[byte]()

  readLoop():
    if socket.readingClosed():
      (0, true)
    else:
      let count = socket.buffer.dataLen()
      bytes.add(socket.buffer.buffer.toOpenArray(0, count - 1))
      (count, false)

  debug "Read data ",
    remote = socket.socketKey,
    length = len(bytes)

  return bytes

# Check how many packets are still in the out going buffer, usefull for tests or
# debugging.
proc numPacketsInOutGoingBuffer*(socket: UtpSocket): int =
  var num = 0
  for e in socket.outBuffer.items():
    if e.isSome():
      inc num
  num

# Check how many payload bytes are still in flight
proc numOfBytesInFlight*(socket: UtpSocket): uint32 = socket.sendBufferTracker.currentBytesInFlight()

# Check how many bytes are in incoming buffer
proc numOfBytesInIncomingBuffer*(socket: UtpSocket): uint32 = uint32(socket.buffer.dataLen())

# Check how many packets are still in the reorder buffer, usefull for tests or
# debugging.
# It throws assertion error when number of elements in buffer do not equal kept counter
proc numPacketsInReordedBuffer*(socket: UtpSocket): int =
  var num = 0
  for e in socket.inBuffer.items():
    if e.isSome():
      inc num
  doAssert(num == int(socket.reorderCount))
  num

proc connectionId*[A](socket: UtpSocket[A]): uint16 =
  ## Connection id is id which is used in first SYN packet which establishes the connection
  ## so for Outgoing side it is actually its rcv_id, and for Incoming side it is
  ## its snd_id
  case socket.direction
  of Incoming:
    socket.connectionIdSnd
  of Outgoing:
    socket.connectionIdRcv

# Check what is current available window size for this socket
proc currentMaxWindowSize*[A](socket: UtpSocket[A]): uint32 =
  socket.sendBufferTracker.maxWindow
