# Copyright (c) 2020-2023 Status Research & Development GmbH
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

suite "uTP Packet Encoding":
  test "Encode/decode SYN packet":
    let
      synPacket = synPacket(5, 10, 20)
      encoded = encodePacket(synPacket)
      decoded = decodePacket(encoded)

    check:
      len(encoded) == 20
      decoded.isOk()

    let synPacketDec = decoded.get()

    check synPacketDec == synPacket

  test "Encode/decode FIN packet":
    let
      finPacket = finPacket(5, 10, 20, 30, 40)
      encoded = encodePacket(finPacket)
      decoded = decodePacket(encoded)

    check:
      len(encoded) == 20
      decoded.isOk()

    let finPacketDec = decoded.get()

    check finPacketDec == finPacket

  test "Encode/decode RESET packet":
    let
      resetPacket = resetPacket(5, 10, 20)
      encoded = encodePacket(resetPacket)
      decoded = decodePacket(encoded)

    check:
      len(encoded) == 20
      decoded.isOk()

    let resetPacketDec = decoded.get()

    check resetPacketDec == resetPacket

  test "Encode/decode ACK packet: without extensions":
    let
      ackPacket = ackPacket(5, 10, 20, 30, 40)
      encoded = encodePacket(ackPacket)
      decoded = decodePacket(encoded)

    check:
      len(encoded) == 20
      decoded.isOk()

    let ackPacketDec = decoded.get()

    check ackPacketDec == ackPacket

  test "Encode/decode ACK packet: with extensions":
    let
      bitMask: array[4, byte] = [1'u8, 2, 3, 4]
      ackPacket = ackPacket(5, 10, 20, 30, 40, some(bitMask))
      encoded = encodePacket(ackPacket)
      decoded = decodePacket(encoded)

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

    block: # nextExtension to non zero
      var encoded = encodePacket(ackPacket)
      encoded[20] = 1
      let err = decodePacket(encoded)
      check err.isErr()

    block: # len of extension to value different than 4
      var encoded = encodePacket(ackPacket)
      encoded[21] = 7
      let err = decodePacket(encoded)
      check err.isErr()

    block: # delete last byte, now packet is too short
      var encoded = encodePacket(ackPacket)
      encoded.del(encoded.high)
      let err = decodePacket(encoded)
      check err.isErr()

    block: # change extension field to something other than 0 or 1
      var encoded = encodePacket(ackPacket)
      encoded[1] = 2
      let err = decodePacket(encoded)
      check: err.isErr()

  test "Decode STATE packet":
    # Packet obtained by interaction with c reference implementation
    let pack: array[20, uint8] = [
            0x21'u8, 0x0, 0x15, 0x72, 0x00, 0xBA, 0x4D, 0x71, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x41, 0xA7, 0x00, 0x01]
    let decoded = decodePacket(pack)

    check decoded.isOk()

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
    let
      synPacket = synPacket(5, 10, 20)
      initialTimestamp = synPacket.header.timestamp
      initialAckNr = synPacket.header.ackNr
      modifiedTimeStamp = initialTimestamp + 120324
      modifiedAckNr = initialAckNr + 20
    var encoded = encodePacket(synPacket)
    modifyTimeStampAndAckNr(encoded, modifiedTimeStamp, modifiedAckNr)

    let decoded = decodePacket(encoded)

    check:
      decoded.isOk()
      decoded.get().header.timestamp == modifiedTimeStamp
      decoded.get().header.ackNr == modifiedAckNr
