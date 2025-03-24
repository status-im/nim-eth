# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# uTP packet format as specified in:
# https://www.bittorrent.org/beps/bep_0029.html

{.push raises: [].}

import
  faststreams,
  chronos,
  stew/[endians2, objects],
  results,
  ../p2p/discoveryv5/random2

export results, random2

const
  minimalHeaderSize = 20
  minimalHeaderSizeWithSelectiveAck = 26
  protocolVersion = 1
  zeroMoment = Moment.init(0, Nanosecond)
  acksArrayLength: uint8 = 4

type
  PacketType* = enum
    ST_DATA = 0,
    ST_FIN = 1,
    ST_STATE = 2,
    ST_RESET = 3,
    ST_SYN = 4

  MicroSeconds = uint32

  PacketHeaderV1* = object
    pType*: PacketType
    version*: uint8
    extension*: uint8
    connectionId*: uint16
    timestamp*: MicroSeconds
    timestampDiff*: MicroSeconds
    wndSize*: uint32
    seqNr*: uint16
    ackNr*: uint16

  SelectiveAckExtension* = object
    acks*: array[4, byte]

  Packet* = object
    header*: PacketHeaderV1
    eack*: Opt[SelectiveAckExtension]
    payload*: seq[uint8]

  TimeStampInfo* = object
    moment*: Moment
    timestamp*: uint32

# Important timing assumptions for uTP protocol here:
# 1. Microsecond precisions
# 2. Monotonicity
# Reference lib has a lot of checks to assume that this is monotonic on
# every system, and warnings when monotonic clock is not available.
proc getMonoTimestamp*(): TimeStampInfo =
  let currentMoment = Moment.now()

  # Casting this value from int64 to uint32, may lead to some sudden spikes in
  # timestamp numeric values, i.e it is possible that the timestamp will
  # suddenly change from 4294967296 to for example 10. This may lead to sudden
  # spikes in calculated delays.
  # The uTP implementation is resistant to those spikes are as it keeps a
  # history of several last delays and uses the smallest one for calculating
  # the ledbat window, thus any outlier value will be ignored.
  let timestamp = uint32((currentMoment - zeroMoment).microseconds())
  TimeStampInfo(moment: currentMoment, timestamp: timestamp)

# Simple generator, not useful for cryptography
proc randUint16*(rng: var HmacDrbgContext): uint16 =
  uint16(rand(rng, int(high(uint16))))

# Simple generator, not useful for cryptography
proc randUint32*(rng: var HmacDrbgContext): uint32 =
  uint32(rand(rng, int(high(uint32))))

func encodeTypeVer(h: PacketHeaderV1): uint8 =
  var typeVer = 0'u8
  let typeOrd = uint8(ord(h.pType))
  typeVer = (typeVer and 0xf0) or (h.version and 0xf)
  typeVer = (typeVer and 0xf) or (typeOrd shl 4)
  typeVer

proc encodeHeaderStream(s: var OutputStream, h: PacketHeaderV1) =
  try:
    s.write(encodeTypeVer(h))
    s.write(h.extension)
    s.write(h.connectionId.toBytesBE())
    s.write(h.timestamp.toBytesBE())
    s.write(h.timestampDiff.toBytesBE())
    s.write(h.wndSize.toBytesBE())
    s.write(h.seqNr.toBytesBE())
    s.write(h.ackNr.toBytesBE())
  except IOError as e:
    # This should not happen in case of in-memory streams
    raiseAssert e.msg

proc encodeExtensionStream(s: var OutputStream, e: SelectiveAckExtension) =
  try:
    # writing always 0 as there are no other extensions (only selective ack)
    s.write(0'u8)
    s.write(acksArrayLength)
    s.write(e.acks)
  except IOError as e:
    # This should not happen in case of in-memory streams
    raiseAssert e.msg

proc encodePacket*(p: Packet): seq[byte] =
  var s = memoryOutput().s
  try:
    encodeHeaderStream(s, p.header)
    if (p.eack.isSome()):
      encodeExtensionStream(s, p.eack.unsafeGet())
    if (len(p.payload) > 0):
      s.write(p.payload)
    s.getOutput()
  except IOError as e:
    # This should not happen in case of in-memory streams
    raiseAssert e.msg

func decodePacket*(bytes: openArray[byte]): Result[Packet, string] =
    let receivedBytesLength = len(bytes)
    if receivedBytesLength < minimalHeaderSize:
      return err("Invalid header size")

    let version = bytes[0] and 0xf
    if version != protocolVersion:
      return err("Invalid packet version: " & $version)

    var kind: PacketType
    if not checkedEnumAssign(kind, (bytes[0] shr 4)):
      return err("Invalid message type")

    let extensionByte = bytes[1]

    if (not (extensionByte == 0 or extensionByte == 1)):
       return err("Invalid extension type")

    let header =
      PacketHeaderV1(
        pType: kind,
        version: version,
        extension: extensionByte,
        connection_id: fromBytesBE(uint16, bytes.toOpenArray(2, 3)),
        timestamp: fromBytesBE(uint32, bytes.toOpenArray(4, 7)),
        timestamp_diff: fromBytesBE(uint32, bytes.toOpenArray(8, 11)),
        wnd_size: fromBytesBE(uint32, bytes.toOpenArray(12, 15)),
        seq_nr: fromBytesBE(uint16, bytes.toOpenArray(16, 17)),
        ack_nr: fromBytesBE(uint16, bytes.toOpenArray(18, 19)),
      )

    if extensionByte == 0:
      # packet without extensions
      let payload =
        if (receivedBytesLength == minimalHeaderSize):
          @[]
        else:
          bytes[minimalHeaderSize..^1]

      return ok(Packet(
        header: header,
        eack: Opt.none(SelectiveAckExtension),
        payload: payload))
    else:
      # packet with the selective ack extension
      if (receivedBytesLength < minimalHeaderSizeWithSelectiveAck):
        return err("Packet too short for selective ack extension: " &
          "len = " & $receivedBytesLength)

      let nextExtension = bytes[20]
      let extLength = bytes[21]

      # The byte for nextExtension must be 0 as selective ack is currently the
      # only supported extension.
      # For extLength, the specification states that it must be at least 4, and
      # in multiples of 4. However, the reference implementation always uses a 4
      # bytes bit mask, which makes sense as a 4 byte bit mask is able to ack
      # 32 packets in the future, which is sounds more than enough.
      if (nextExtension != 0 or extLength != 4):
        return err("Bad format of selective ack extension: " &
          "extension = " & $nextExtension & " len = " & $extLength)

      let extension = SelectiveAckExtension(
        acks: toArray(4, bytes.toOpenArray(22, 25))
      )

      let payload =
        if (receivedBytesLength == minimalHeaderSizeWithSelectiveAck):
          @[]
        else:
          bytes[minimalHeaderSizeWithSelectiveAck..^1]

      return ok(Packet(header: header, eack: Opt.some(extension), payload: payload))

proc modifyTimeStampAndAckNr*(
    packetBytes: var seq[byte], newTimestamp: uint32, newAckNr: uint16) =
  ## Modifies timestamp and ack nr of already encoded packets. These fields
  ## must be filled right before sending, so when re-sending the packet they
  ## can be updated without decoding and re-encoding the packet.
  doAssert(len(packetBytes) >= minimalHeaderSize)
  packetBytes[4..7] = toBytesBE(newTimestamp)
  packetBytes[18..19] = toBytesBE(newAckNr)

proc synPacket*(
    seqNr: uint16, rcvConnectionId: uint16, bufferSize: uint32): Packet =
  # rcvConnectionId - should be a random, not already used, number
  # bufferSize - should be a pre-configured initial buffer size for the socket
  # SYN packets are special and have the conn_id_recv in the conn_id field,
  # instead of conn_id_send.
  let h = PacketHeaderV1(
    pType: ST_SYN,
    version: protocolVersion,
    extension: 0'u8,
    connectionId: rcvConnectionId,
    timestamp: getMonoTimestamp().timestamp,
    timestampDiff: 0'u32,
    wndSize: bufferSize,
    seqNr: seqNr,
    ackNr: 0'u16 # At start, no acks have been received
  )

  Packet(header: h, eack: Opt.none(SelectiveAckExtension), payload: @[])

proc ackPacket*(
    seqNr: uint16,
    sndConnectionId: uint16,
    ackNr: uint16,
    bufferSize: uint32,
    timestampDiff: uint32,
    acksBitmask: Opt[array[4, byte]] = Opt.none(array[4, byte])
  ): Packet =

  let (extensionByte, extensionData) =
    if acksBitmask.isSome():
      (1'u8, Opt.some(SelectiveAckExtension(acks: acksBitmask.unsafeGet())))
    else:
      (0'u8, Opt.none(SelectiveAckExtension))

  let h = PacketHeaderV1(
    pType: ST_STATE,
    version: protocolVersion,
    extension: extensionByte,
    connectionId: sndConnectionId,
    timestamp: getMonoTimestamp().timestamp,
    timestampDiff: timestampDiff,
    wndSize: bufferSize,
    seqNr: seqNr,
    ackNr: ackNr
  )

  Packet(header: h, eack: extensionData, payload: @[])

proc dataPacket*(
  seqNr: uint16,
  sndConnectionId: uint16,
  ackNr: uint16,
  bufferSize: uint32,
  payload: seq[byte],
  timestampDiff: uint32
): Packet =
  let h = PacketHeaderV1(
    pType: ST_DATA,
    version: protocolVersion,
    extension: 0'u8, # data packets always have extension field set to 0
    connectionId: sndConnectionId,
    timestamp: getMonoTimestamp().timestamp,
    timestampDiff: timestampDiff,
    wndSize: bufferSize,
    seqNr: seqNr,
    ackNr: ackNr
  )

  Packet(header: h, eack: Opt.none(SelectiveAckExtension), payload: payload)

proc resetPacket*(
    seqNr: uint16, sndConnectionId: uint16, ackNr: uint16): Packet =
  let h = PacketHeaderV1(
    pType: ST_RESET,
    version: protocolVersion,
    extension: 0'u8, # reset packets always have extension field set to 0
    connectionId: sndConnectionId,
    timestamp: getMonoTimestamp().timestamp,
    # reset packet informs remote about lack of state for given connection,
    # therefore the remote is not informed about its delay.
    timestampDiff: 0,
    wndSize: 0,
    seqNr: seqNr,
    ackNr: ackNr
  )

  Packet(header: h, eack: Opt.none(SelectiveAckExtension), payload: @[])

proc finPacket*(
  seqNr: uint16,
  sndConnectionId: uint16,
  ackNr: uint16,
  bufferSize: uint32,
  timestampDiff: uint32
): Packet =
  let h = PacketHeaderV1(
    pType: ST_FIN,
    version: protocolVersion,
    extension: 0'u8, # fin packets always have extension field set to 0
    connectionId: sndConnectionId,
    timestamp: getMonoTimestamp().timestamp,
    timestampDiff: timestampDiff,
    wndSize: bufferSize,
    seqNr: seqNr,
    ackNr: ackNr
  )

  Packet(header: h, eack: Opt.none(SelectiveAckExtension), payload: @[])
