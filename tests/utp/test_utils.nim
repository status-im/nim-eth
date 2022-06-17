import
  chronos,
  ../../eth/utp/utp_socket,
  ../../eth/utp/packets,
  ../../eth/keys

type AssertionCallback = proc(): bool {.gcsafe, raises: [Defect].}

let testBufferSize = 1024'u32
let defaultRcvOutgoingId = 314'u16

proc waitUntil*(f: AssertionCallback): Future[void] {.async.} =
  while true:
    let res = f()
    if res:
      break
    else:
      await sleepAsync(milliseconds(50))

template connectOutGoingSocket*(
  initialRemoteSeq: uint16,
  q: AsyncQueue[Packet],
  remoteReceiveBuffer: uint32 = testBufferSize,
  cfg: SocketConfig = SocketConfig.init()): (UtpSocket[TransportAddress], Packet) =
  let sock1 = newOutgoingSocket[TransportAddress](testAddress, initTestSnd(q), cfg, defaultRcvOutgoingId, rng[])
  asyncSpawn sock1.startOutgoingSocket()
  let initialPacket = await q.get()

  check:
    initialPacket.header.pType == ST_SYN

  let responseAck =
    ackPacket(
      initialRemoteSeq,
      initialPacket.header.connectionId,
      initialPacket.header.seqNr,
      remoteReceiveBuffer,
      0
    )

  await sock1.processPacket(responseAck)
  await waitUntil(proc (): bool = sock1.isConnected())
  check:
    sock1.isConnected()

  (sock1, initialPacket)

template connectOutGoingSocketWithIncoming*(
  initialRemoteSeq: uint16,
  outgoingQueue: AsyncQueue[Packet],
  incomingQueue: AsyncQueue[Packet],
  remoteReceiveBuffer: uint32 = testBufferSize,
  cfg: SocketConfig = SocketConfig.init()): (UtpSocket[TransportAddress], UtpSocket[TransportAddress]) =
  let outgoingSocket = newOutgoingSocket[TransportAddress](testAddress, initTestSnd(outgoingQueue), cfg, defaultRcvOutgoingId, rng[])
  asyncSpawn outgoingSocket.startOutgoingSocket()
  let initialPacket = await outgoingQueue.get()

  check:
    initialPacket.header.pType == ST_SYN

  let incomingSocket = newIncomingSocket[TransportAddress](
    testAddress,
    initTestSnd(incomingQueue),
    cfg,
    initialPacket.header.connectionId,
    initialPacket.header.seqNr,
    rng[]
  )

  incomingSocket.startIncomingSocket()

  let responseAck = await incomingQueue.get()

  await outgoingSocket.processPacket(responseAck)

  await waitUntil(proc (): bool = outgoingSocket.isConnected())

  check:
    outgoingSocket.isConnected()

  (outgoingSocket, incomingSocket)


proc generateDataPackets*(
  numberOfPackets: uint16,
  initialSeqNr: uint16,
  connectionId: uint16,
  ackNr: uint16,
  rng: var HmacDrbgContext): seq[Packet] =
  let packetSize = 100
  var packets = newSeq[Packet]()
  var i = 0'u16
  while i < numberOfPackets:
    let packet = dataPacket(
      initialSeqNr + i,
      connectionId,
      ackNr,
      testBufferSize,
      rng.generateBytes(packetSize),
      0
    )
    packets.add(packet)

    inc i

  packets

proc initTestSnd*(q: AsyncQueue[Packet]): SendCallback[TransportAddress]=
  return  (
    proc (to: TransportAddress, bytes: seq[byte]): Future[void] =
      let p = decodePacket(bytes).get()
      q.addLast(p)
  )
