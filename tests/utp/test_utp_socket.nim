# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[algorithm, random, sequtils],
  chronos, bearssl, chronicles,
  testutils/unittests,
  ./test_utils,
  ../../eth/utp/utp_router,
  ../../eth/utp/utp_socket,
  ../../eth/utp/packets,
  ../../eth/keys

procSuite "Utp socket unit test":
  let rng = newRng()
  let testAddress = initTAddress("127.0.0.1", 9079)
  let testBufferSize = 1024'u32

  proc initTestSnd(q: AsyncQueue[Packet]): SendCallback[TransportAddress]=
    return  (
      proc (to: TransportAddress, bytes: seq[byte]): Future[void] =
        let p = decodePacket(bytes).get()
        q.addLast(p)
    )

  proc generateDataPackets(
    numberOfPackets: uint16,
    initialSeqNr: uint16,
    connectionId: uint16,
    ackNr: uint16,
    rng: var BrHmacDrbgContext): seq[Packet] =
    let packetSize = 100
    var packets = newSeq[Packet]()
    var i = 0'u16
    while i < numberOfPackets:
      let packet = dataPacket(
        initialSeqNr + i,
        connectionId,
        ackNr,
        testBufferSize,
        generateByteArray(rng, packetSize)
      )
      packets.add(packet)

      inc i

    packets

  proc packetsToBytes(packets: seq[Packet]): seq[byte] =
    var resultBytes = newSeq[byte]()
    for p in packets:
      resultBytes.add(p.payload)
    return resultBytes

  template connectOutGoingSocket(
    initialRemoteSeq: uint16,
    q: AsyncQueue[Packet],
    cfg: SocketConfig = SocketConfig.init()): (UtpSocket[TransportAddress], Packet) =
    let sock1 = initOutgoingSocket[TransportAddress](testAddress, initTestSnd(q), cfg, rng[])
    await sock1.startOutgoingSocket()
    let initialPacket = await q.get()

    check:
      initialPacket.header.pType == ST_SYN

    let responseAck = ackPacket(initialRemoteSeq, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize)

    await sock1.processPacket(responseAck)

    check:
      sock1.isConnected()

    (sock1, initialPacket)

  asyncTest "Starting outgoing socket should send Syn packet":
    let q = newAsyncQueue[Packet]()
    let defaultConfig = SocketConfig.init()
    let sock1 = initOutgoingSocket[TransportAddress](testAddress, initTestSnd(q), defaultConfig, rng[])
    await sock1.startOutgoingSocket()
    let initialPacket = await q.get()

    check:
      initialPacket.header.pType == ST_SYN
      initialPacket.header.wndSize == defaultConfig.optRcvBuffer

  asyncTest "Outgoing socket should re-send syn packet 2 times before declaring failure":
    let q = newAsyncQueue[Packet]()
    let sock1 = initOutgoingSocket[TransportAddress](testAddress, initTestSnd(q), SocketConfig.init(milliseconds(100)), rng[])
    await sock1.startOutgoingSocket()
    let initialPacket = await q.get()

    check:
      initialPacket.header.pType == ST_SYN

    let resentSynPacket = await q.get()

    check:
      resentSynPacket.header.pType == ST_SYN

    let resentSynPacket1 = await q.get()

    check:
      resentSynPacket1.header.pType == ST_SYN

    # next timeout will should disconnect socket
    await waitUntil(proc (): bool = sock1.isConnected() == false)

    check:
      not sock1.isConnected()

  asyncTest "Processing in order ack should make socket connected":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    discard connectOutGoingSocket(initialRemoteSeq, q)

  asyncTest "Processing in order data packet should upload it to buffer and ack packet":
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16
    let data = @[1'u8, 2'u8, 3'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    let dataP1 = dataPacket(initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize, data)
    
    await outgoingSocket.processPacket(dataP1)
    let ack1 = await q.get()

    check:
      ack1.header.pType == ST_STATE
      ack1.header.ackNr == initalRemoteSeqNr

    let receivedBytes = await outgoingSocket.read(len(data))

    check:
      receivedBytes == data

  asyncTest "Processing out of order data packet should buffer it until receiving in order one":
    # TODO test is valid until implementing selective acks
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    var packets = generateDataPackets(10, initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, rng[])

    let data = packetsToBytes(packets)

    # start feeding packets from the last one
    packets.reverse()

    for p in packets:
      await outgoingSocket.processPacket(p)

    let ack2 = await q.get()

    check:
      ack2.header.pType == ST_STATE
      # we are acking in one shot whole 10 packets
      ack2.header.ackNr == initalRemoteSeqNr + uint16(len(packets) - 1) 

    let receivedData = await outgoingSocket.read(len(data))

    check:
      receivedData == data
    
  asyncTest "Processing out of order data packet should ignore duplicated not ordered packets":
    # TODO test is valid until implementing selective acks
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    var packets = generateDataPackets(3, initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, rng[])

    let data = packetsToBytes(packets)

    # start feeding packets from the last one
    packets.reverse()

    # Process last packet additional two times, it should be ignored by processing logic
    await outgoingSocket.processPacket(packets[0])
    await outgoingSocket.processPacket(packets[0])

    for p in packets:
      await outgoingSocket.processPacket(p)

    let ack2 = await q.get()

    check:
      ack2.header.pType == ST_STATE
      # we are acking in one shot whole 10 packets
      ack2.header.ackNr == initalRemoteSeqNr + uint16(len(packets) - 1) 

    let receivedData = await outgoingSocket.read(len(data))

    check:
      receivedData == data
  
  asyncTest "Processing packets in random order":
    # TODO test is valid until implementing selective acks
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    var packets = generateDataPackets(30, initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, rng[])

    let data = packetsToBytes(packets)

    # start feeding packets from the last one
    randomize()
    packets.shuffle()

    for p in packets:
      await outgoingSocket.processPacket(p)

    let receivedData = await outgoingSocket.read(len(data))

    check:
      # with packets totally out of order we cannont assert on acks
      # as they can be fired at any point. What matters is that data is passed
      # in same order as received.
      receivedData == data

  asyncTest "Ignoring totally out of order packet":
    # TODO test is valid until implementing selective acks
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    var packets = generateDataPackets(1025, initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, rng[])

    await outgoingSocket.processPacket(packets[1024])

    check:
      outgoingSocket.numPacketsInReordedBuffer() == 0

    await outgoingSocket.processPacket(packets[1023])

    check:
      outgoingSocket.numPacketsInReordedBuffer() == 1

  asyncTest "Writing small enough data should produce 1 data packet":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite = @[1'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let bytesWritten = await outgoingSocket.write(dataToWrite)

    check:
      bytesWritten.get() == len(dataToWrite)

    let sentPacket = await q.get()

    check:
      outgoingSocket.numPacketsInOutGoingBuffer() == 1
      sentPacket.header.pType == ST_DATA
      sentPacket.header.seqNr == initialPacket.header.seqNr + 1
      sentPacket.payload == dataToWrite

    # ackNr in state packet, is set to sentPacket.header.seqNr which means remote
    # side processed out packet
    let responseAck = ackPacket(initialRemoteSeq, initialPacket.header.connectionId, sentPacket.header.seqNr, testBufferSize)

    await outgoingSocket.processPacket(responseAck)

    check: 
      outgoingSocket.numPacketsInOutGoingBuffer() == 0

  asyncTest "Socket should re-send data packet configurable number of times before declaring failure":
    let q = newAsyncQueue[Packet]()   
    let initalRemoteSeqNr = 10'u16

    let outgoingSocket = initOutgoingSocket[TransportAddress](testAddress, initTestSnd(q), SocketConfig.init(milliseconds(50), 2), rng[])
    await outgoingSocket.startOutgoingSocket()
    let initialPacket = await q.get()

    check:
      initialPacket.header.pType == ST_SYN

    let responseAck = ackPacket(initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize)

    await outgoingSocket.processPacket(responseAck)

    check:
      outgoingSocket.isConnected()

    let dataToWrite = @[1'u8]

    let bytesWritten = await outgoingSocket.write(dataToWrite)

    check:
      bytesWritten.get() == len(dataToWrite)

    let sentPacket = await q.get()

    check:
      outgoingSocket.numPacketsInOutGoingBuffer() == 1
      sentPacket.header.pType == ST_DATA
      sentPacket.header.seqNr == initialPacket.header.seqNr + 1
      sentPacket.payload == dataToWrite

    let reSend1 = await q.get()

    check:
      outgoingSocket.numPacketsInOutGoingBuffer() == 1
      reSend1.header.pType == ST_DATA
      reSend1.header.seqNr == initialPacket.header.seqNr + 1
      reSend1.payload == dataToWrite

    let reSend2 = await q.get()

    check:
      outgoingSocket.numPacketsInOutGoingBuffer() == 1
      reSend2.header.pType == ST_DATA
      reSend2.header.seqNr == initialPacket.header.seqNr + 1
      reSend2.payload == dataToWrite

    # next timeout will should disconnect socket
    await waitUntil(proc (): bool = outgoingSocket.isConnected() == false)

    check:
      not outgoingSocket.isConnected()
      len(q) == 0

  asyncTest "Processing in order fin should make socket reach eof and ack this packet":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let finP = finPacket(initialRemoteSeq, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize)
    
    await outgoingSocket.processPacket(finP)
    let ack1 = await q.get()

    check:
      ack1.header.pType == ST_STATE
      outgoingSocket.atEof()

  asyncTest "Processing out of order fin should buffer it until receiving all remaining packets":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16
    let data = @[1'u8, 2'u8, 3'u8]
    let data1 = @[4'u8, 5'u8, 6'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let readF = outgoingSocket.read()

    let dataP = dataPacket(initialRemoteSeq, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize, data)
    let dataP1 = dataPacket(initialRemoteSeq + 1, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize, data1)

    let finP = finPacket(initialRemoteSeq + 2, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize)
    
    await outgoingSocket.processPacket(finP)

    check:
      not readF.finished()
      not outgoingSocket.atEof()

    await outgoingSocket.processPacket(dataP1)

    check:
      not readF.finished()
      not outgoingSocket.atEof()
   
    await outgoingSocket.processPacket(dataP)

    let bytes = await readF

    check:
      readF.finished()
      outgoingSocket.atEof()
      bytes == concat(data, data1)

  asyncTest "Socket should ignore data past eof packet":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16
    let data = @[1'u8, 2'u8, 3'u8]
    let data1 = @[4'u8, 5'u8, 6'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let readF = outgoingSocket.read()

    let dataP = dataPacket(initialRemoteSeq, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize, data)

    let finP = finPacket(initialRemoteSeq + 1, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize)

    # dataP1 has seqNr larger than fin, there fore it should be considered past eof and never passed
    # to user of library
    let dataP1 = dataPacket(initialRemoteSeq + 2, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize, data1)

    await outgoingSocket.processPacket(finP)

    check:
      not readF.finished()
      not outgoingSocket.atEof()

    # it is out of order dataP1 (as we still not processed dataP packet)
    await outgoingSocket.processPacket(dataP1)

    check:
      not readF.finished()
      not outgoingSocket.atEof()
   
    await outgoingSocket.processPacket(dataP)

    # it is in order dataP1, as we have now processed dataP + fin which came before
    # but it is past eof so it should be ignored
    await outgoingSocket.processPacket(dataP1)

    let bytes = await readF

    check:
      readF.finished()
      outgoingSocket.atEof()
      bytes == concat(data)

  asyncTest "Calling close should send fin packet":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    await outgoingSocket.close()

    let sendFin = await q.get()

    check:
      sendFin.header.pType == ST_FIN

  asyncTest "Receiving ack for fin packet should destroy socket":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let closeF = outgoingSocket.close()

    let sendFin = await q.get()

    check:
      sendFin.header.pType == ST_FIN

    let responseAck = ackPacket(initialRemoteSeq, initialPacket.header.connectionId, sendFin.header.seqNr, testBufferSize)

    await outgoingSocket.processPacket(responseAck)
    
    await closeF

    check:
      not outgoingSocket.isConnected()

  asyncTest "Trying to write data onto closed socket should return error":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    await outgoingSocket.destroyWait()

    let writeResult = await outgoingSocket.write(@[1'u8])

    check:
      writeResult.isErr()

    let error = writeResult.error()

    check:
      error.kind == SocketNotWriteable
      error.currentState == Destroy

  asyncTest "Trying to write data onto closed socket which sent fin":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    await outgoingSocket.close()

    let writeResult = await outgoingSocket.write(@[1'u8])

    check:
      writeResult.isErr()

    let error = writeResult.error()

    check:
      error.kind == FinSent

  asyncTest "Processing data packet should update window size accordingly and use it in all send packets":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeqNr = 10'u16
    let initialRcvBufferSize = 10'u32
    let data = @[1'u8, 2'u8, 3'u8]
    let sCfg = SocketConfig.init(optRcvBuffer = initialRcvBufferSize)
    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeqNr, q, sCfg)

    let dataP1 = dataPacket(initialRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize, data)
    
    await outgoingSocket.processPacket(dataP1)

    let ack1 = await q.get()

    check:
      ack1.header.pType == ST_STATE
      ack1.header.ackNr == initialRemoteSeqNr
      ack1.header.wndSize == initialRcvBufferSize - uint32(len(data))

    let written = await outgoingSocket.write(data)

    let sentData = await q.get()

    check:
      sentData.header.pType == ST_DATA
      sentData.header.wndSize == initialRcvBufferSize - uint32(len(data))

    await outgoingSocket.close()

    let sentFin = await q.get()

    check:
      sentFin.header.pType == ST_FIN
      sentFin.header.wndSize == initialRcvBufferSize - uint32(len(data))

  asyncTest "Reading data from the buffer shoud increase receive window":
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16
    let initialRcvBufferSize = 10'u32
    let data = @[1'u8, 2'u8, 3'u8]
    let sCfg = SocketConfig.init(optRcvBuffer = initialRcvBufferSize)
    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q, sCfg)

    let dataP1 = dataPacket(initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize, data)
    
    await outgoingSocket.processPacket(dataP1)

    let ack1 = await q.get()

    check:
      ack1.header.pType == ST_STATE
      ack1.header.ackNr == initalRemoteSeqNr
      ack1.header.wndSize == initialRcvBufferSize - uint32(len(data))

    let readData = await outgoingSocket.read(data.len())

    check:
      readData == data

    discard await outgoingSocket.write(data)

    let sentData = await q.get()

    check:
      sentData.header.pType == ST_DATA
      # we have read all data from rcv buffer, advertised window should go back to
      # initial size
      sentData.header.wndSize == initialRcvBufferSize
