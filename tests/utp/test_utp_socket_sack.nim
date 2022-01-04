# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[options, sequtils],
  chronos, bearssl, chronicles,
  stew/bitops2,
  testutils/unittests,
  ./test_utils,
  ../../eth/utp/utp_router,
  ../../eth/utp/utp_socket,
  ../../eth/utp/packets,
  ../../eth/keys

procSuite "Utp socket selective acks unit test":
  let rng = newRng()
  let testAddress = initTAddress("127.0.0.1", 9079)
  let defaultBufferSize = 1024'u32

  proc connectAndProcessMissingPacketWithIndexes(idxs: seq[int]): Future[array[4, uint8]] {.async.} =
    let initialRemoteSeq = 1'u16
    let q = newAsyncQueue[Packet]()
    let data = @[0'u8]

    let (outgoingSocket, initialPacket) = connectOutGoingSocket(initialRemoteSeq, q)

    var dataPackets: seq[Packet] = @[]

    for i in idxs:
      let dataP =
        dataPacket(
          # initialRemoteSeq is next expected packet, so n represent how far from the
          # future is this packet
          initialRemoteSeq + uint16(i),
          initialPacket.header.connectionId,
          initialPacket.header.seqNr,
          defaultBufferSize,
          data,
          0
        )
      dataPackets.add(dataP)

    for p in dataPackets:
      await outgoingSocket.processPacket(p)

    let extArray = outgoingSocket.generateSelectiveAckBitMask()

    await outgoingSocket.destroyWait()

    return extArray

  proc numOfSetBits(arr: openArray[byte]): int =
    var numOfSetBits = 0
    for b in arr:
      numOfSetBits = numOfSetBits + countOnes(b)
    return numOfSetBits

  proc hasOnlyOneBitSet(arr: openArray[byte]): bool = 
    return numOfSetBits(arr) == 1

  asyncTest "Socket with empty buffer should generate array with only zeros":
    let q = newAsyncQueue[Packet]()
    let initialRemoteSeq = 10'u16

    let (outgoingSocket, packet) = connectOutGoingSocket(initialRemoteSeq, q)

    let extArray = outgoingSocket.generateSelectiveAckBitMask()

    check:
      extArray == [0'u8, 0, 0, 0]
  
  asyncTest "Socket should generate correct bit mask for each missing packet":
    # 1 means that received packet is packet just after expected packet i.e
    # packet.seqNr - receivingSocket.ackNr = 2
    # 32 means that received packet is 32 packets after expected one i.e
    # packet.seqNr - receivingSocket.ackNr = 32
    # First byte represents packets [ack_nr + 2, ack_nr + 9] in reverse order
    # Second byte represents packets [ack_nr + 10, ack_nr + 17] in reverse order
    # Third byte represents packets [ack_nr + 18, ack_nr + 25] in reverse order
    # Fourth byte represents packets [ack_nr + 26, ack_nr + 33] in reverse order
    let afterExpected = 1..32

    for i in afterExpected:
      # bit mask should have max 4 bytes
      let bitMask = await connectAndProcessMissingPacketWithIndexes(@[i])

      check:
        # only one bit should have been set as only one packet has been processed
        # out of order
        hasOnlyOneBitSet(bitMask)
        getBit(bitMask, i - 1)

  asyncTest "Socket should generate correct bit mask if there is more than one missing packet":
    # Each testcase defines which out of order packets should be processed i.e
    # @[1] - packet just after expected will be processed
    # @[3, 5] - packet three packets after will be processed and then packet 5 packets
    # after expected will be processed
    let testCases = @[
      @[1],
      @[1, 2],
      @[1, 9, 11, 18],
      @[1, 3, 8, 15, 18, 22, 27, 32]
    ]

    for missingIndexes in testCases:
      let bitMask = await connectAndProcessMissingPacketWithIndexes(missingIndexes)
      check:
        numOfSetBits(bitMask) == len(missingIndexes)
      
      for idx in missingIndexes:
        check:
          getBit(bitMask, idx - 1)

  asyncTest "Socket should generate max 4 bytes bit mask even if there is more missing packets":
    let testCases = @[
      toSeq(1..40)
    ]

    for missingIndexes in testCases:
      let bitMask = await connectAndProcessMissingPacketWithIndexes(missingIndexes)
      check:
        numOfSetBits(bitMask) == 32
        len(bitMask) == 4
      
  type TestCase = object
    # number of packet to generate by writitng side
    numOfPackets: int
    # indexes of packets which should be delivered to remote
    packetsDelivered: seq[int]

  let selectiveAckTestCases = @[
      TestCase(numOfPackets: 2, packetsDelivered: @[1]),
      TestCase(numOfPackets: 10, packetsDelivered: @[1, 3, 5, 7, 9]),
      TestCase(numOfPackets: 10, packetsDelivered: @[1, 2, 3, 4, 5, 6, 7, 8, 9]),
      TestCase(numOfPackets: 15, packetsDelivered: @[1, 3, 5, 7, 9, 10, 11, 12, 14]),
      TestCase(numOfPackets: 20, packetsDelivered: @[1, 3, 5, 7, 9, 11, 13, 15, 17, 19]),
      TestCase(numOfPackets: 33, packetsDelivered: @[32]),
      TestCase(numOfPackets: 33, packetsDelivered: @[25, 26, 27, 28, 29, 30, 31, 32]),
      TestCase(numOfPackets: 33, packetsDelivered: toSeq(1..32))
    ]

  asyncTest "Socket should calculate number of bytes acked by selective acks":
    let dataSize = 10
    let initialRemoteSeq = 10'u16
    let smallData = generateByteArray(rng[], 10)

    for testCase in selectiveAckTestCases:
      let outgoingQueue = newAsyncQueue[Packet]()
      let incomingQueue = newAsyncQueue[Packet]()
    
      let (outgoingSocket, incomingSocket) = 
        connectOutGoingSocketWithIncoming(
          initialRemoteSeq,
          outgoingQueue,
          incomingQueue
        )

      var packets: seq[Packet] = @[]

      for _ in 0..<testCase.numOfPackets:
        discard await outgoingSocket.write(smallData)
        let packet = await outgoingQueue.get()
        packets.add(packet)
      
      for toDeliver in testCase.packetsDelivered:
        await incomingSocket.processPacket(packets[toDeliver])

      let finalAck = incomingSocket.generateAckPacket()

      check:
        finalAck.eack.isSome()

      let mask = finalAck.eack.unsafeGet().acks

      check:
        numOfSetBits(mask) == len(testCase.packetsDelivered)

      for idx in testCase.packetsDelivered:
        check:
          getBit(mask, idx - 1)

      let ackedBytes = outgoingSocket.calculateSelectiveAckBytes(finalAck.header.ackNr, finalAck.eack.unsafeGet())

      check: 
        int(ackedBytes) == len(testCase.packetsDelivered) * dataSize

      await outgoingSocket.destroyWait()
      await incomingSocket.destroyWait()

  asyncTest "Socket should ack packets based on selective ack packet":
    let dataSize = 10
    let initialRemoteSeq = 10'u16
    let smallData = generateByteArray(rng[], 10)

    for testCase in selectiveAckTestCases:
      let outgoingQueue = newAsyncQueue[Packet]()
      let incomingQueue = newAsyncQueue[Packet]()
    
      let (outgoingSocket, incomingSocket) = 
        connectOutGoingSocketWithIncoming(
          initialRemoteSeq,
          outgoingQueue,
          incomingQueue
        )

      var packets: seq[Packet] = @[]

      for _ in 0..<testCase.numOfPackets:
        discard await outgoingSocket.write(smallData)
        let packet = await outgoingQueue.get()
        packets.add(packet)
      
      for toDeliver in testCase.packetsDelivered:
        await incomingSocket.processPacket(packets[toDeliver])

      let finalAck = incomingSocket.generateAckPacket()

      check:
        finalAck.eack.isSome()

      let mask = finalAck.eack.unsafeGet().acks

      check:
        numOfSetBits(mask) == len(testCase.packetsDelivered)

      for idx in testCase.packetsDelivered:
        check:
          getBit(mask, idx - 1)

      check:
        outgoingSocket.numPacketsInOutGoingBuffer() == testCase.numOfPackets

      await outgoingSocket.processPacket(finalAck)

      check:
        outgoingSocket.numPacketsInOutGoingBuffer() == testCase.numOfPackets - len(testCase.packetsDelivered)

      await outgoingSocket.destroyWait()
      await incomingSocket.destroyWait()
