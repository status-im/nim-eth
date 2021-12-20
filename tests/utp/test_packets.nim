# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/options,
  unittest2,
  ../../eth/utp/packets,
  ../../eth/keys

suite "Utp packets encoding/decoding":

  let rng = newRng()

  test "Encode/decode syn packet":
    let synPacket = synPacket(5, 10, 20)
    let encoded = encodePacket(synPacket)
    let decoded = decodePacket(encoded)

    check:
      len(encoded) == 20
      decoded.isOk()

    let synPacketDec = decoded.get()

    check:
      synPacketDec == synPacket

  test "Encode/decode fin packet":
    let finPacket = finPacket(5, 10, 20, 30, 40)
    let encoded = encodePacket(finPacket)
    let decoded = decodePacket(encoded)

    check:
      len(encoded) == 20
      decoded.isOk()

    let finPacketDec = decoded.get()

    check:
      finPacketDec == finPacket

  test "Encode/decode reset packet":
    let resetPacket = resetPacket(5, 10, 20)
    let encoded = encodePacket(resetPacket)
    let decoded = decodePacket(encoded)

    check:
      len(encoded) == 20
      decoded.isOk()

    let resetPacketDec = decoded.get()

    check:
      resetPacketDec == resetPacket

  test "Encode/decode ack packet without extensions":
    let ackPacket = ackPacket(5, 10, 20, 30, 40)
    let encoded = encodePacket(ackPacket)
    let decoded = decodePacket(encoded)

    check:
      len(encoded) == 20
      decoded.isOk()

    let ackPacketDec = decoded.get()

    check:
      ackPacketDec == ackPacket

  test "Encode/decode ack packet with extensions":
    let bitMask: array[4, byte] = [1'u8, 2, 3, 4]
    let ackPacket = ackPacket(5, 10, 20, 30, 40, some(bitMask))
    let encoded = encodePacket(ackPacket)
    let decoded = decodePacket(encoded)

    check:
      len(encoded) == 26
      decoded.isOk()

    let ackPacketDec = decoded.get()

    check:
      ackPacketDec == ackPacket
      ackPacketDec.eack.isSome()

  test "Fail to decode packet with malformed extensions":
    let bitMask: array[4, byte] = [1'u8, 2, 3, 4]
    let ackPacket = ackPacket(5, 10, 20, 30, 40, some(bitMask))

    var encoded1 = encodePacket(ackPacket)
    # change nextExtension to non zero
    encoded1[20] = 1
    let err1 = decodePacket(encoded1)
    check:
      err1.isErr()
      err1.error() == "Bad format of selective ack extension"

    var encoded2 = encodePacket(ackPacket)
    # change len of extension to value different than 4
    encoded2[21] = 7
    let err2 = decodePacket(encoded2)
    check:
      err2.isErr()
      err2.error() == "Bad format of selective ack extension"

    var encoded3 = encodePacket(ackPacket)
    # delete last byte, now packet is to short
    encoded3.del(encoded3.high)
    let err3 = decodePacket(encoded3)

    check:
      err3.isErr()
      err3.error() == "Packet too short for selective ack extension"


    var encoded4 = encodePacket(ackPacket)
    # change change extension field to something other than 0 or 1
    encoded4[1] = 2
    let err4 = decodePacket(encoded4)
    check:
      err4.isErr()
      err4.error() == "Invalid extension type"

  test "Decode state packet":
    # Packet obtained by interaction with c reference implementation
    let pack: array[20, uint8] = [
            0x21'u8, 0x0, 0x15, 0x72, 0x00, 0xBA, 0x4D, 0x71, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0,
            0x0, 0x41, 0xA7, 0x00, 0x01]
    let decoded = decodePacket(pack)

    check:
      decoded.isOk()

    let packet = decoded.get()

    check:
      packet.header.pType == ST_STATE
      packet.header.version == 1
      packet.header.extension == 0
      packet.header.connectionId == 5490
      packet.header.timestamp == 12209521
      packet.header.timestampDiff == 0
      packet.header.wndSize == 1048576
      packet.header.seqNr == 16807
      packet.header.ackNr == 1

  test "Modify timestamp of encoded packet":
    let synPacket = synPacket(5, 10, 20)
    let initialTimestamp = synPacket.header.timestamp
    let initialAckNr = synPacket.header.ackNr
    let modifiedTimeStamp = initialTimestamp + 120324
    let modifiedAckNr = initialAckNr + 20
    var encoded = encodePacket(synPacket)
    modifyTimeStampAndAckNr(encoded, modifiedTimeStamp, modifiedAckNr)

    let decoded = decodePacket(encoded)

    check:
      decoded.isOk()
      decoded.get().header.timestamp == modifiedTimeStamp
      decoded.get().header.ackNr == modifiedAckNr
