# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[monotimes],
  faststreams,
  stew/[endians2, results, objects], bearssl,
  ../p2p/discoveryv5/random2

export results

const minimalHeaderSize = 20
const protocolVersion = 1

type 
  PacketType* = enum
    ST_DATA = 0,
    ST_FIN = 1,
    ST_STATE = 2,
    ST_RESET = 3,
    ST_SYN = 4

  MicroSeconds = uint32

  PacketHeaderV1 = object
    pType*: PacketType
    version*: uint8
    extension*: uint8
    connectionId*: uint16
    timestamp*: MicroSeconds
    timestampDiff*: MicroSeconds
    wndSize*: uint32
    seqNr*: uint16
    ackNr*: uint16

  Packet* = object
    header*: PacketHeaderV1
    payload*: seq[uint8]

# Important timing assumptions for utp protocol here:
# 1. Microsecond precisions
# 2. Monotonicity
# Reference lib have a lot of checks to assume that this is monotonic on
# every system, and warnings when monotonic clock is not avaialable.
# For now we can use basic monotime, later it would be good to analyze:
# https://github.com/bittorrent/libutp/blob/master/utp_utils.cpp, to check all the
# timing assumptions on different platforms
proc getMonoTimeTimeStamp(): uint32 = 
  let time = getMonoTime()
  cast[uint32](time.ticks() div 1000)

# Simple generator, not useful for cryptography
proc randUint16*(rng: var BrHmacDrbgContext): uint16 =
  uint16(rand(rng, int(high(uint16))))

# Simple generator, not useful for cryptography
proc randUint32*(rng: var BrHmacDrbgContext): uint32 =
  uint32(rand(rng, int(high(uint32))))

proc encodeTypeVer(h: PacketHeaderV1): uint8 =
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

proc encodePacket*(p: Packet): seq[byte] =
  var s = memoryOutput().s
  try:
    encodeHeaderStream(s, p.header)
    if (len(p.payload) > 0):
      s.write(p.payload)
    s.getOutput()
  except IOError as e:
    # This should not happen in case of in-memory streams
    raiseAssert e.msg
  
# TODO for now we do not handle extensions
proc decodePacket*(bytes: openArray[byte]): Result[Packet, string] =
    if len(bytes) < minimalHeaderSize:
      return err("invalid header size")

    let version = bytes[0] and 0xf
    if version != protocolVersion:
      return err("invalid packet version")
  
    var kind: PacketType
    if not checkedEnumAssign(kind, (bytes[0] shr 4)):
      return err("Invalid message type")
      
    let header =
      PacketHeaderV1(
        pType: kind,
        version: version,
        extension: bytes[1],
        connection_id: fromBytesBE(uint16, bytes.toOpenArray(2, 3)),
        timestamp: fromBytesBE(uint32, bytes.toOpenArray(4, 7)),
        timestamp_diff: fromBytesBE(uint32, bytes.toOpenArray(8, 11)),
        wnd_size: fromBytesBE(uint32, bytes.toOpenArray(12, 15)),
        seq_nr: fromBytesBE(uint16, bytes.toOpenArray(16, 17)),
        ack_nr: fromBytesBE(uint16, bytes.toOpenArray(18, 19)),
      )
    
    let payload =
      if (len(bytes) == 20):
        @[]
      else:
        bytes[20..^1]

    ok(Packet(header: header, payload: payload))

# connectionId - should be random not already used number
# bufferSize - should be pre configured initial buffer size for socket
proc synPacket*(rng: var BrHmacDrbgContext, connectionId: uint16, bufferSize: uint32): Packet =
  let h = PacketHeaderV1(
    pType: ST_SYN,
    version: protocolVersion,
    # TODO for we do not handle extensions
    extension: 0'u8,
    # TODO should be random not used number
    connectionId: connectionId,

    timestamp: getMonoTimeTimeStamp(),

    timestampDiff: 0'u32,
    # TODO shouldbe current available buffer size
    wndSize: bufferSize,
    seqNr: randUint16(rng),
    # Initialy we did not receive any acks
    ackNr: 0'u16
  )

  Packet(header: h, payload: @[])
