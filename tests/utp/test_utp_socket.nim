# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[algorithm, random, sequtils, options],
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
  let defaultRcvOutgoingId = 314'u16

  proc packetsToBytes(packets: seq[Packet]): seq[byte] =
    var resultBytes = newSeq[byte]()
    for p in packets:
      resultBytes.add(p.payload)
    return resultBytes

  asyncTest "Starting outgoing socket should send Syn packet":
    let q = newAsyncQueue[Packet]()
    let defaultConfig = SocketConfig.init()
    let sock1 = newOutgoingSocket[TransportAddress](
      testAddress,
      initTestSnd(q),
      defaultConfig,
      defaultRcvOutgoingId,
      rng[]
    )
    let fut1 = sock1.startOutgoingSocket()
    let initialPacket = await q.get()

    check:
      initialPacket.header.pType == ST_SYN
      initialPacket.header.wndSize == defaultConfig.optRcvBuffer

    await sock1.destroyWait()
    fut1.cancel()

  asyncTest "Outgoing socket should re-send syn packet 2 times before declaring failure":
    let q = newAsyncQueue[Packet]()
    let sock1 = newOutgoingSocket[TransportAddress](
      testAddress,
      initTestSnd(q),
      SocketConfig.init(milliseconds(100)),
      defaultRcvOutgoingId,
      rng[]
    )
    let fut1 =  sock1.startOutgoingSocket()
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

    await sock1.destroyWait()
    fut1.cancel()

  asyncTest "Processing in order ack should make socket connected":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (sock1, packet) = connectOutGoingSocket(initialRemoteSeq, q)

    check:
      sock1.isConnected()

    await sock1.destroyWait()

  asyncTest "Processing in order data packet should upload it to buffer and ack packet":
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16
    let data = @[1'u8, 2'u8, 3'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    let dataP1 =
      dataPacket(
        initalRemoteSeqNr,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data,
        0
      )

    await outgoingSocket.processPacket(dataP1)
    let ack1 = await q.get()

    check:
      ack1.header.pType == ST_STATE
      ack1.header.ackNr == initalRemoteSeqNr

    let receivedBytes = await outgoingSocket.read(len(data))

    check:
      receivedBytes == data

    await outgoingSocket.destroyWait()

  asyncTest "Processing duplicated fresh data packet should ack it and stop processing":
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16
    let data = @[1'u8, 2'u8, 3'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    let dataP1 =
      dataPacket(
        initalRemoteSeqNr,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data,
        0
      )

    await outgoingSocket.processPacket(dataP1)

    let ack1 = await q.get()

    check:
      ack1.header.pType == ST_STATE
      ack1.header.ackNr == initalRemoteSeqNr

    let receivedBytes = await outgoingSocket.read(len(data))

    check:
      receivedBytes == data

    # remote re-send data packet, most probably due to lost ack
    await outgoingSocket.processPacket(dataP1)

    let ack2 = await q.get()

    check:
      ack2.header.pType == ST_STATE
      ack2.header.ackNr == initalRemoteSeqNr
      # we do not upload data one more time
      outgoingSocket.numOfBytesInIncomingBuffer() == 0'u32

    await outgoingSocket.destroyWait()

  asyncTest "Processing out of order data packet should buffer it until receiving in order one":
    # TODO test is valid until implementing selective acks
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16
    let numOfPackets = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    var packets = generateDataPackets(numOfPackets, initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, rng[])

    let data = packetsToBytes(packets)

    # start feeding packets from the last one
    packets.reverse()

    for p in packets:
      await outgoingSocket.processPacket(p)

    var sentAcks: seq[Packet] = @[]
    
    for i in 0'u16..<numOfPackets:
      let ack = await q.get()
      sentAcks.add(ack)

    # all packets except last one should be selective acks, without bumped ackNr
    for i in 0'u16..<numOfPackets - 1:
      check:
        sentAcks[i].header.ackNr == initalRemoteSeqNr - 1
        sentAcks[i].eack.isSome()

    # last ack should be normal ack packet (not selective one), and it should ack
    # all remaining packets
    let lastAck = sentAcks[numOfPackets - 1]

    check:
      lastAck.header.pType == ST_STATE
      # we are acking in one shot whole 10 packets
      lastAck.header.ackNr == initalRemoteSeqNr + uint16(len(packets) - 1)

      lastAck.eack.isNone()

    let receivedData = await outgoingSocket.read(len(data))

    check:
      receivedData == data

    await outgoingSocket.destroyWait()

  asyncTest "Processing out of order data packet should ignore duplicated not ordered packets":
    # TODO test is valid until implementing selective acks
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16
    let numOfPackets = 3'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    var packets = generateDataPackets(numOfPackets, initalRemoteSeqNr, initialPacket.header.connectionId, initialPacket.header.seqNr, rng[])

    let data = packetsToBytes(packets)

    # start feeding packets from the last one
    packets.reverse()

    # Process last packet additional two times, it should be ignored by processing logic
    await outgoingSocket.processPacket(packets[0])
    await outgoingSocket.processPacket(packets[0])

    for p in packets:
      await outgoingSocket.processPacket(p)

    var sentAcks: seq[Packet] = @[]
    
    for i in 0'u16..<numOfPackets:
      let ack = await q.get()
      sentAcks.add(ack)

    # all packets except last one should be selective acks, without bumped ackNr
    for i in 0'u16..<numOfPackets - 1:
      check:
        sentAcks[i].header.ackNr == initalRemoteSeqNr - 1
        sentAcks[i].eack.isSome()

    # last ack should be normal ack packet (not selective one), and it should ack
    # all remaining packets
    let lastAck = sentAcks[numOfPackets - 1]

    check:
      lastAck.header.pType == ST_STATE
      # we are acking in one shot whole 10 packets
      lastAck.header.ackNr == initalRemoteSeqNr + uint16(len(packets) - 1)

      lastAck.eack.isNone()

    let receivedData = await outgoingSocket.read(len(data))

    check:
      receivedData == data

    await outgoingSocket.destroyWait()

  asyncTest "Processing packets in random order":
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

    await outgoingSocket.destroyWait()

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

    await outgoingSocket.destroyWait()

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
    let responseAck =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        sentPacket.header.seqNr,
        testBufferSize,
        0
      )

    await outgoingSocket.processPacket(responseAck)

    check:
      outgoingSocket.numPacketsInOutGoingBuffer() == 0

    await outgoingSocket.destroyWait()

  proc ackAllPacket(
    socket: UtpSocket[TransportAddress],
    queue: AsyncQueue[Packet],
    initialRemoteSeq: uint16): Future[void] {.async.} =
    try:
      while true:
        let sentPacket = await queue.get()
        let ack = ackPacket(
          initialRemoteSeq,
          sentPacket.header.connectionId,
          sentPacket.header.seqNr,
          1024 * 1024,
          1000'u32
        )
        await socket.processPacket(ack)
    except CancelledError:
      echo "foo"

  asyncTest "Hitting RTO timeout with packets in flight should not decay window":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    # lot of data which will generate at least 5 packets
    let bigDataTowWrite = generateByteArray(rng[], 10000)
    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let acker = outgoingSocket.ackAllPacket(q, initialRemoteSeq)
    let bytesWritten = await outgoingSocket.write(bigDataTowWrite)

    check:
      bytesWritten.get() == len(bigDataTowWrite)

    await waitUntil(proc (): bool = outgoingSocket.numPacketsInOutGoingBuffer() == 0)

    let maxWindowAfterSuccesfulSends = outgoingSocket.currentMaxWindowSize() 

    check:
      # after processing a lot of data, our window size should be a lot bigger than our packet size
      maxWindowAfterSuccesfulSends > uint32(outgoingSocket.getPacketSize())

    # cancel acking process, next writes will for sure timeout
    await acker.cancelAndWait()
    
    # data which fits one packet and will timeout
    let smallerData = generateByteArray(rng[], 100)

    let bytesWritten1 = await outgoingSocket.write(smallerData)

    # ignore standard sent packet
    discard await q.get()

    check:
      bytesWritten1.get() == len(smallerData)

    # ignore also first re-send
    discard await q.get()
    
    let maxWindowAfterTimeout = outgoingSocket.currentMaxWindowSize()

    check:
      # After standard timeout window should not decay and must be bigger than packet size
      maxWindowAfterTimeout > uint32(outgoingSocket.getPacketSize())
      maxWindowAfterTimeout == maxWindowAfterSuccesfulSends

    await outgoingSocket.destroyWait()

  asyncTest "Blocked writing futures should be properly finished when socket is closed":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite1 = @[0'u8]
    let dataToWrite2 = @[1'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q, 0)

    let writeFut1 = outgoingSocket.write(dataToWrite1)
    let writeFut2 = outgoingSocket.write(dataToWrite2)

    # wait a little to show that futures are not progressing
    await sleepAsync(seconds(1))

    check:
      not writeFut1.finished()
      not writeFut2.finished()

    outgoingSocket.destroy()

    yield writeFut1
    yield writeFut2

    check:
      writeFut1.completed()
      writeFut2.completed()
      writeFut1.read().isErr()
      writeFut2.read().isErr()

    await outgoingSocket.destroyWait()

  asyncTest "Cancelled write futures should not be processed if cancelled before processing":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite1 = @[0'u8]
    let dataToWrite2 = @[1'u8]
    let dataToWrite3 = @[2'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q, 0)

    # only writeFut1 will progress as to processing stage, writeFut2 and writeFut3
    # will be blocked in queue
    let writeFut1 = outgoingSocket.write(dataToWrite1)
    let writeFut2 = outgoingSocket.write(dataToWrite2)
    let writeFut3 = outgoingSocket.write(dataToWrite3)

    # user decided to cancel second write
    await writeFut2.cancelAndWait()
    # remote increased wnd size enough for all writes
    let someAckFromRemote =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        10,
        0
      )

    await outgoingSocket.processPacket(someAckFromRemote)

    yield writeFut1
    yield writeFut2
    yield writeFut3

    check:
      writeFut1.completed()
      writeFut2.cancelled()
      writeFut3.completed()

    let p1 = await q.get()
    let p2 = await q.get

    check:
      # we produce only two data packets as write with dataToWrite2 was cancelled
      p1.payload == dataToWrite1
      p2.payload == dataToWrite3

    await outgoingSocket.destroyWait()

  asyncTest "Socket should re-send data packet configurable number of times before declaring failure":
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16

    let outgoingSocket = newOutgoingSocket[TransportAddress](
      testAddress,
      initTestSnd(q),
      SocketConfig.init(milliseconds(3000), 2),
      defaultRcvOutgoingId,
      rng[]
    )

    let fut1 = outgoingSocket.startOutgoingSocket()

    let initialPacket = await q.get()

    check:
      initialPacket.header.pType == ST_SYN

    let responseAck =
      ackPacket(
        initalRemoteSeqNr,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        0
      )

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

    await outgoingSocket.destroyWait()

  asyncTest "Processing in order fin should make socket reach eof and ack this packet":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let finP =
      finPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        0
      )

    await outgoingSocket.processPacket(finP)
    let ack1 = await q.get()

    check:
      ack1.header.pType == ST_STATE
      outgoingSocket.atEof()

    await outgoingSocket.destroyWait()

  asyncTest "Processing out of order fin should buffer it until receiving all remaining packets":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16
    let data = @[1'u8, 2'u8, 3'u8]
    let data1 = @[4'u8, 5'u8, 6'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let readF = outgoingSocket.read()

    let dataP =
      dataPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data,
        0
      )

    let dataP1 =
      dataPacket(
        initialRemoteSeq + 1,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data1,
        0
      )

    let finP =
      finPacket(
        initialRemoteSeq + 2,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        0
      )

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

    await outgoingSocket.destroyWait()

  asyncTest "Socket should ignore data past eof packet":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16
    let data = @[1'u8, 2'u8, 3'u8]
    let data1 = @[4'u8, 5'u8, 6'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let readF = outgoingSocket.read()

    let dataP =
      dataPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data,
        0
      )

    let finP =
      finPacket(
        initialRemoteSeq + 1,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        0
      )

    # dataP1 has seqNr larger than fin, there fore it should be considered past eof and never passed
    # to user of library
    let dataP1 =
      dataPacket(
        initialRemoteSeq + 2,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data1,
        0
      )

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

    await outgoingSocket.destroyWait()

  asyncTest "Calling close should send fin packet":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    outgoingSocket.close()

    let sendFin = await q.get()

    check:
      sendFin.header.pType == ST_FIN

    await outgoingSocket.destroyWait()

  asyncTest "Receiving ack for fin packet should destroy socket":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    outgoingSocket.close()

    let sendFin = await q.get()

    check:
      sendFin.header.pType == ST_FIN

    let responseAck =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        sendFin.header.seqNr,
        testBufferSize,
        0
      )

    await outgoingSocket.processPacket(responseAck)

    check:
      not outgoingSocket.isConnected()

    await outgoingSocket.destroyWait()

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

    outgoingSocket.close()

    let writeResult = await outgoingSocket.write(@[1'u8])

    check:
      writeResult.isErr()

    let error = writeResult.error()

    check:
      error.kind == FinSent

    await outgoingSocket.destroyWait()

  asyncTest "Processing data packet should update window size accordingly and use it in all send packets":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeqNr = 10'u16
    let initialRcvBufferSize = 10'u32
    let data = @[1'u8, 2'u8, 3'u8]
    let sCfg = SocketConfig.init(optRcvBuffer = initialRcvBufferSize)
    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeqNr, q, testBufferSize, sCfg)

    let dataP1 =
      dataPacket(
        initialRemoteSeqNr,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data,
        0
      )

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

    outgoingSocket.close()

    let sentFin = await q.get()

    check:
      sentFin.header.pType == ST_FIN
      sentFin.header.wndSize == initialRcvBufferSize - uint32(len(data))

    await outgoingSocket.destroyWait()

  asyncTest "Reading data from the buffer shoud increase receive window":
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16
    let initialRcvBufferSize = 10'u32
    let data = @[1'u8, 2'u8, 3'u8]
    let sCfg = SocketConfig.init(optRcvBuffer = initialRcvBufferSize)
    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q, testBufferSize, sCfg)

    let dataP1 =
      dataPacket(
        initalRemoteSeqNr,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data,
        0
      )

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

    await outgoingSocket.destroyWait()

  asyncTest "Socket should ignore packets with bad ack number":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16
    let data1 = @[1'u8, 2'u8, 3'u8]
    let data2 = @[4'u8, 5'u8, 6'u8]
    let data3 = @[7'u8, 7'u8, 9'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    # data packet with ack nr set above our seq nr i.e  packet from the future
    let dataFuture =
      dataPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr + 1,
        testBufferSize,
        data1,
        0
      )
    # data packet wth ack number set below out ack window i.e packet too old
    let dataTooOld =
      dataPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr - allowedAckWindow - 1,
        testBufferSize,
        data2,
        0
      )

    let dataOk =
      dataPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        data3,
        0
      )

    await outgoingSocket.processPacket(dataFuture)
    await outgoingSocket.processPacket(dataTooOld)
    await outgoingSocket.processPacket(dataOk)

    let receivedBytes = await outgoingSocket.read(data3.len)

    check:
      # data1 and data2 were sent in bad packets we should only receive data3
      receivedBytes == data3

    await outgoingSocket.destroyWait()

  asyncTest "Writing data should increase current bytes window":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite = @[1'u8, 2, 3, 4, 5]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    discard await outgoingSocket.write(dataToWrite)

    check:
      int(outgoingSocket.numOfBytesInFlight) == len(dataToWrite)

    discard await outgoingSocket.write(dataToWrite)

    check:
      int(outgoingSocket.numOfBytesInFlight) == len(dataToWrite) + len(dataToWrite)

    await outgoingSocket.destroyWait()

  asyncTest "Acking data packet should decrease current bytes window":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite = @[1'u8, 2, 3, 4, 5]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    discard await outgoingSocket.write(dataToWrite)

    let sentPacket = await q.get()

    check:
      int(outgoingSocket.numOfBytesInFlight) == len(dataToWrite)


    discard await outgoingSocket.write(dataToWrite)

    check:
      int(outgoingSocket.numOfBytesInFlight) == len(dataToWrite) + len(dataToWrite)

    let responseAck =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        sentPacket.header.seqNr,
        testBufferSize,
        0
      )

    await outgoingSocket.processPacket(responseAck)

    check:
      # only first packet has been acked so there should still by 5 bytes left
      int(outgoingSocket.numOfBytesInFlight) == len(dataToWrite)

    await outgoingSocket.destroyWait()

  asyncTest "Timeout packets should decrease bytes window":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite = @[1'u8, 2, 3]
    let dataToWrite1 = @[6'u8, 7, 8, 9, 10]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    discard await outgoingSocket.write(dataToWrite)

    let sentPacket = await q.get()

    check:
      int(outgoingSocket.numOfBytesInFlight) == len(dataToWrite)


    discard await outgoingSocket.write(dataToWrite1)

    let sentPacket1 = await q.get()

    check:
      int(outgoingSocket.numOfBytesInFlight) == len(dataToWrite) + len(dataToWrite1)

    # after timeout oldest packet will be immediatly re-sent
    let reSentFirstPacket = await q.get()

    check:
      reSentFirstPacket.payload == sentPacket.payload

      # first packet has been re-sent so its payload still counts to bytes in flight
      # second packet has been marked as missing, therefore its bytes are not counting
      # to bytes in flight
      int(outgoingSocket.numOfBytesInFlight) == len(dataToWrite)

    await outgoingSocket.destroyWait()

  asyncTest "Writing data should asynchronously block until there is enough space in snd buffer":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite = @[1'u8, 2, 3, 4, 5]

    # remote is initialized with buffer to small to handle whole payload
    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q, uint32(len(dataToWrite) - 1))

    let writeFut = outgoingSocket.write(dataToWrite)

    # wait some time to check future is not finished
    await sleepAsync(seconds(2))

    # write is not finished as future is blocked from progressing due to to small
    # send window
    check:
      not writeFut.finished()

    let someAckFromRemote =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        uint32(len(dataToWrite)),
        0
      )

    await outgoingSocket.processPacket(someAckFromRemote)

    # after processing packet with increased buffer size write should complete and
    # packet should be sent
    let sentPacket = await q.get()

    check:
      sentPacket.payload == dataToWrite
      writeFut.finished()

    await outgoingSocket.destroyWait()

  asyncTest "Writing data should not progress in case of timeouting packets and small snd window":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite = @[1'u8, 2, 3, 4, 5]

    # remote is initialized with buffer to small to handle whole payload
    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)
    let remoteRcvWindowSize = uint32(outgoingSocket.getPacketSize())
    let someAckFromRemote =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        remoteRcvWindowSize,
        0
      )

    # we are using ack from remote to setup our snd window size to one packet size on one packet
    await outgoingSocket.processPacket(someAckFromRemote)

    let twoPacketData = generateByteArray(rng[], int(2 * remoteRcvWindowSize))

    let writeFut = outgoingSocket.write(twoPacketData)

    # after this time first packet will be send and will timeout, but the write should not
    # finish, as timeouting packets do not notify writing about new space in snd
    # buffer
    await sleepAsync(seconds(2))

    check:
      not writeFut.finished()

    await outgoingSocket.destroyWait()

  asyncTest "Writing data should respect remote rcv window size":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let dataToWrite = @[1'u8, 2, 3, 4, 5]

    # remote is initialized with buffer to small to handle whole payload
    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)
    let remoteRcvWindowSize = uint32(outgoingSocket.getPacketSize())
    let someAckFromRemote =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        remoteRcvWindowSize,
        0
      )

    # we are using ack from remote to setup our snd window size to one packet size on one packet
    await outgoingSocket.processPacket(someAckFromRemote)

    let twoPacketData = generateByteArray(rng[], int(2 * remoteRcvWindowSize))

    let writeFut = outgoingSocket.write(twoPacketData)

    let firstAckFromRemote =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr + 1,
        remoteRcvWindowSize,
        0
      )

    let packet = await q.get()

    check:
      packet.header.pType == ST_DATA
      uint32(len(packet.payload)) == remoteRcvWindowSize
      not writeFut.finished

    await outgoingSocket.processPacket(firstAckFromRemote)

    let packet1 = await q.get()
    let writeResult = await writeFut

    check:
      packet1.header.pType == ST_DATA
      writeFut.finished

    await outgoingSocket.destroyWait()

  asyncTest "Remote window should be reseted to minimal value after configured amount of time":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16
    let someData = @[1'u8]
    let (outgoingSocket, packet) =
      connectOutGoingSocket(
        initialRemoteSeq,
        q,
        remoteReceiveBuffer = 0,
        cfg = SocketConfig.init(
          remoteWindowResetTimeout = seconds(3)
        )
      )

    check:
      outgoingSocket.isConnected()

    let writeFut = outgoingSocket.write(someData)

    await sleepAsync(seconds(1))

    check:
      # Even after 1 second write is not finished as we did not receive any message
      # so remote rcv window is still zero
      not writeFut.finished()

    # Ultimately, after 3 second remote rcv window will be reseted to minimal value
    # and write will be able to progress
    let writeResult = await writeFut

    let p = await q.get()

    check:
      writeResult.isOk()
      p.payload == someData

    await outgoingSocket.destroyWait()

  asyncTest "Writing data should respect max snd buffer option":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16
    let someData1 = @[1'u8]
    let someData2 = @[2'u8]
    let (outgoingSocket, initialPacket) =
      connectOutGoingSocket(
        initialRemoteSeq,
        q,
        cfg = SocketConfig.init(
          optSndBuffer = 1
        )
      )

    check:
      outgoingSocket.isConnected()

    # snd buffer got 1 byte of space so this future shold finish
    let write1 = await outgoingSocket.write(someData1)

    let writeFut2 = outgoingSocket.write(someData2)

    # wait until 2 re-sends to check we do not accidently free buffer during re-sends
    discard await q.get()
    discard await q.get()
    let firstPacket = await q.get()

    check:
      # this write still cannot progress as 1st write is not acked
      not writeFut2.finished()

    let someAckFromRemote =
      ackPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr + 1,
        10,
        0
      )

    # acks first write, so there is space in buffer for new data and second
    # write should progress
    await outgoingSocket.processPacket(someAckFromRemote)

    yield writeFut2

    let secondPacket =  await q.get()

    check:
      writeFut2.finished()
      firstPacket.payload == someData1
      secondPacket.payload == someData2

    await outgoingSocket.destroyWait()

  asyncTest "Socket should inform remote about its delay":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    let dataP1 =
      dataPacket(
        initialRemoteSeq,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        @[1'u8],
        0
      )

    check:
      outgoingSocket.isConnected()

    # necessary to avoid timestampDiff near 0 and flaky tests
    await sleepAsync(milliseconds(50))
    await outgoingSocket.processPacket(dataP1)

    let socketAck = await q.get()

    check:
      socketAck.header.timestampDiff > 0

    await outgoingSocket.destroyWait()

  asyncTest "Re-sent packet should have updated timestamps and ack numbers":
    let q = newAsyncQueue[Packet]()
    let initalRemoteSeqNr = 10'u16

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initalRemoteSeqNr, q)

    let writeResult = await outgoingSocket.write(@[1'u8])

    check:
      writeResult.isOk()

    let firstSend = await q.get()

    let secondSend = await q.get()

    check:
      # there was sometime between resend but no packet from remote
      # so timestamp should be updated but not ackNr
      secondSend.header.timestamp > firstSend.header.timestamp
      firstSend.header.ackNr == secondSend.header.ackNr

    let dataP1 =
      dataPacket(
        initalRemoteSeqNr,
        initialPacket.header.connectionId,
        initialPacket.header.seqNr,
        testBufferSize,
        @[1'u8],
        0
      )

    await outgoingSocket.processPacket(dataP1)

    let ack = await q.get()

    check:
      ack.header.pType == ST_STATE

    let thirdSend = await q.get()

    check:
      # as there was some incoming data between resend, both timestamp and ackNr
      # should be updated
      thirdSend.header.timestamp > secondSend.header.timestamp
      thirdSend.header.ackNr > secondSend.header.ackNr

    await outgoingSocket.destroyWait()
