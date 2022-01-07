# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/options,
  stew/[byteutils, bitops2],
  unittest2,
  ../../eth/utp/packets,
  ../../eth/keys

suite "Utp packets test vectors":
  test "SYN packet":
    let synPacket = Packet(
      header: PacketHeaderV1(
        pType: ST_SYN,
        version: 1,
        extension: 0,
        connectionId: 10049,
        timestamp: 3384187322'u32,
        timestampDiff: 0,
        wndSize: 1048576,
        seqNr: 11884,
        ackNr: 0
      ),
      eack: none[SelectiveAckExtension](),
      payload: @[]
    )

    let encodedSyn = encodePacket(synPacket)
    
    let synBytes = hexToSeqByte("0x41002741c9b699ba00000000001000002e6c0000")

    check:
      encodedSyn == synBytes

  test "ACK packet (No selective acks)":
    let ackPacket = Packet(
      header: PacketHeaderV1(
        pType: ST_STATE,
        version: 1,
        extension: 0,
        connectionId: 10049,
        timestamp: 6195294,
        timestampDiff: 916973699,
        wndSize: 1048576,
        seqNr: 16807,
        ackNr: 11885
      ),
      eack: none[SelectiveAckExtension](),
      payload: @[]
    )

    let encodedAck = encodePacket(ackPacket)

    let ackBytes = hexToSeqByte("0x21002741005e885e36a7e8830010000041a72e6d")

    check:
      encodedAck == ackBytes

  test "ACK packet (with selective acks)":
    # bit mask with the first and last bit set
    var bitMask = [1'u8, 0, 0, 128]

    let ackPacket = Packet(
      header: PacketHeaderV1(
        pType: ST_STATE,
        version: 1,
        extension: 1,
        connectionId: 10049,
        timestamp: 6195294,
        timestampDiff: 916973699,
        wndSize: 1048576,
        seqNr: 16807,
        ackNr: 11885
      ),
      eack: some(SelectiveAckExtension(
        acks: bitMask
      )),
      payload: @[]
    )

    let encodedAck = encodePacket(ackPacket)

    let ackBytes = hexToSeqByte("0x21012741005e885e36a7e8830010000041a72e6d000401000080")

    check:
      encodedAck == ackBytes

  test "DATA packet":
    let dataPacket = Packet(
      header: PacketHeaderV1(
        pType: ST_DATA,
        version: 1,
        extension: 0,
        connectionId: 26237,
        timestamp: 252492495'u32,
        timestampDiff: 242289855,
        wndSize: 1048576,
        seqNr: 8334,
        ackNr: 16806
      ),
      eack: none[SelectiveAckExtension](),
      payload: @[0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    )

    let encodedData = encodePacket(dataPacket)
    
    let dataBytes = hexToSeqByte("0x0100667d0f0cbacf0e710cbf00100000208e41a600010203040506070809")

    check:
      encodedData == dataBytes

  test "FIN packet":
    let finPacket = Packet(
      header: PacketHeaderV1(
        pType: ST_FIN,
        version: 1,
        extension: 0,
        connectionId: 19003,
        timestamp: 515227279,
        timestampDiff: 511481041,
        wndSize: 1048576,
        seqNr: 41050,
        ackNr: 16806
      ),
      eack: none[SelectiveAckExtension](),
      payload: @[]
    )

    let encodedFIn = encodePacket(finPacket)

    let finBytes = hexToSeqByte("0x11004a3b1eb5be8f1e7c94d100100000a05a41a6")

    check:
      encodedFIn == finBytes

  test "RESET packet":
    let resetPacket = Packet(
      header: PacketHeaderV1(
        pType: ST_RESET,
        version: 1,
        extension: 0,
        connectionId: 62285,
        timestamp: 751226811,
        timestampDiff: 0,
        wndSize: 0,
        seqNr: 55413,
        ackNr: 16807
      ),
      eack: none[SelectiveAckExtension](),
      payload: @[]
    )

    let encodedReset = encodePacket(resetPacket)

    let resetBytes = hexToSeqByte("0x3100f34d2cc6cfbb0000000000000000d87541a7")

    check:
      encodedReset == resetBytes
