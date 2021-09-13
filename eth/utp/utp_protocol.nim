# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos, chronicles, bearssl,
  ./packets,
  ../keys

logScope:
  topics = "utp"

type
  # For now utp protocol is tied to udp transport, but ultimatly we would like to
  # abstract underlying transport to be able to run utp over udp, discoveryv5 or
  # maybe some test transport
  UtpProtocol* = ref object
    transport: DatagramTransport
    rng*: ref BrHmacDrbgContext

  UtpSocket* = ref object

# TODO not implemented
# for now just log incoming packets
proc processPacket(p: Packet) =
  notice "Received packet ", packet = p

# Connect to provided address
# Reference implementation: https://github.com/bittorrent/libutp/blob/master/utp_internal.cpp#L2732
# TODO not implemented
proc connectTo*(p: UtpProtocol, address: TransportAddress): Future[UtpSocket] {.async.} =
  let packet = synPacket(p.rng[], randUint16(p.rng[]), 1048576)
  notice "Sending packet", packet = packet
  let packetEncoded = encodePacket(packet)
  await p.transport.sendTo(address, packetEncoded)
  return UtpSocket()

proc processDatagram(transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async.} =
  # TODO: should we use `peekMessage()` to avoid allocation?
  let buf = try: transp.getMessage()
            except TransportOsError as e:
              # This is likely to be local network connection issues.
              return

  let dec = decodePacket(buf)
  if (dec.isOk()):
    processPacket(dec.get())
  else:
    warn "failed to decode packet from address", address = raddr

proc new*(T: type UtpProtocol, address: TransportAddress, rng = newRng()): UtpProtocol {.raises: [Defect, CatchableError].} =
  let ta = newDatagramTransport(processDatagram, local = address)
  UtpProtocol(transport: ta, rng: rng)

proc closeWait*(p: UtpProtocol): Future[void] =
  p.transport.closeWait()
