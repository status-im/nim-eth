# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest,
  ../eth/utp/packets,
   ../../eth/keys

suite "Utp packets encoding/decoding":

  let rng = newRng()
  
  test "Encode/decode syn packet":
    let synPacket = synPacket(rng[], 10, 20)
    let encoded = encodePacket(synPacket)
    let decoded = decodePacket(encoded)

    check:
      decoded.isOk()
      synPacket == decoded.get()

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
