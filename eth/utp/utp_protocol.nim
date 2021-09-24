# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[random],
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
  
  ConnectionState* = enum
    uninitialized, 
    synSent,
    synRecv,
    connected,
    disconnected
  
  ConnectionKey* = ref object
    nodeId*: uint16
    connectionIdRecv*: uint16

  UtpSocket* = ref object
    state*: ConnectionState
    seqNr*: uint16
    ackNr*: uint16
    connectionIdRecv*: uint16
    connectionIdSend*: uint16
    maxWindow*: uint32
    curWindow*: uint32
    lastAck*: uint16
    duplicateAcks*: uint8
  
  
proc createSocket*(): UtpSocket =
  let s = UtpSocket(
    state: uninitialized,
    seqNr: 0,
    ackNr: 0,
    connectionIdRecv: 0,
    connectionIdSend: 0,
    maxWindow: 0,
    curWindow: 0,
  )

  return s

# TODO not implemented
# for now just log incoming packets
# Process an incoming packet

proc sendPacket(uTP: UtpProtocol, address: TransportAddress, conn: UtpSocket, p: Packet) {.async.} =
  #if conn.cur_window + sizeof(p) <= min(int(conn.max_window), int(p.wndSize)):
    #send the packet
  #elif conn.maxWindow < sizeof(p) and conn.curWindow <= conn.maxWindow:
    #we can also send the packet
  let packetEncoded = encodePacket(p)
  await uTP.transport.sendTo(address, packetEncoded)

  #need to pass utp to every function
      
#[proc handleSynPacket(uTP: UtpProtocol, address: TransportAddress, conn: UtpSocket, p: Packet) {.async.} =
  conn.connectionIdRecv = p.header.connectionId + 1
  conn.connectionIdSend = p.header.connectionId
  #conn.seqNr = randUint16()
  conn.ackNr = p.header.seqNr
  conn.state = synRecv

  let response = Packet.new()
  response.header.pType = ST_STATE
  response.header.connectionId = conn.connectionIdRecv
  let currentTime = getMonoTimeTimeStamp()
  response.header.timestamp = currentTime
  let timestampDiff = int(p.header.timestamp) - int(currentTime)
  #Not sure if this is the most efficient way of getting the diff
  response.header.timestampDiff = uint32(abs(timestampDiff)) #Get time diff vs timestamp
  response.header.seqNr = conn.seqNr + 1
  response.header.ackNr = conn.ackNr

  await sendPacket(uTP, address, conn, response)]#

# Should creating the packet be done the way above or below?

proc handleSynPacket(uTP: UtpProtocol, address: TransportAddress, conn: UtpSocket, p: Packet) {.async.} =
  conn.connectionIdRecv = p.header.connectionId + 1
  conn.connectionIdSend = p.header.connectionId
  #conn.seqNr = randUint16()
  conn.ackNr = p.header.seqNr
  conn.state = synRecv


  let currentTime = getMonoTimeTimeStamp()
  let timestampDiff = int(p.header.timestamp) - int(currentTime)
  let response = PacketHeaderV1(
    pType: ST_STATE,
    connectionId: conn.connectionIdRecv,
    timestamp: currentTime,
    timestampDiff: uint32(abs(timestampDiff)),
    seqNr: conn.seqNr + 1,
    ackNr: conn.ackNr
  )
  await sendPacket(uTP, address, conn, Packet(header: response, payload: @[]))



proc handleStatePacket(uTP: UtpProtocol, address: TransportAddress, conn: UtpSocket, p: Packet) {.async.} =
  if conn.state == synSent:
    conn.state = connected
    conn.ackNr = p.header.seqNr 
  else:
    if conn.lastAck == p.header.ackNr:
      conn.duplicateAcks += 1;
    else:
      conn.lastAck = p.header.ackNr
      conn.duplicateAcks = 1
  


proc handleDataPacket(uTP: UtpProtocol, address: TransportAddress, conn: UtpSocket, p: Packet) {.async.} =
  if conn.state == synRecv:
    conn.state = connected

  let currentTime = getMonoTimeTimeStamp()
  let timestampDiff = int(p.header.timestamp) - int(currentTime)
  let response = PacketHeaderV1(
    pType: ST_STATE,
    connectionId: conn.connectionIdSend,
    timestamp: currentTime,
    timestampDiff: uint32(abs(timestampDiff)),
    seqNr: conn.seqNr,
    ackNr: conn.ackNr
  )
  await sendPacket(uTP, address, conn, Packet(header: response, payload: @[]))


proc handleFinalizePacket(uTP: UtpProtocol, address: TransportAddress, conn: UtpSocket, p: Packet) {.async.}=
  
  if conn.state == connected:

    conn.state = disconnected

    let currentTime = getMonoTimeTimeStamp()
    let timestampDiff = int(p.header.timestamp) - int(currentTime)
    let response = PacketHeaderV1(
      pType: ST_STATE,
      connectionId: conn.connectionIdSend,
      timestamp: currentTime,
      timestampDiff: uint32(abs(timestampDiff)),
      seqNr: conn.seqNr,
      ackNr: conn.ackNr
    )
    await sendPacket(uTP, address, conn, Packet(header: response, payload: @[]))  


proc handlePacket*(uTP: UtpProtocol, address: TransportAddress, conn: UtpSocket, p: Packet) {.async.} =
    let packetType = p.header.pType
    case packetType:
      of ST_SYN:
        await handleSynPacket(uTP, address, conn, p)
      of ST_STATE:
        await handleStatePacket(uTP, address, conn, p)
      of ST_DATA:
        await handleDataPacket(uTP, address, conn, p)
      of ST_FIN:
        await handleFinalizePacket(uTP, address, conn, p)
      of ST_RESET:
        warn "Should not end up here"

proc processPacket(uTP: UtpProtocol, address: TransportAddress, conn: UtpSocket, p: Packet) {.async.} =
  notice "Received packet ", packet = p
  let connection_id = p.header.connectionId
  let packetType = p.header.pType

  await handlePacket(uTP, address, conn, p)

  # if packetType == ST_RESET:
  #   echo "Reset"
  #   #conn.connectionIdSend == connection_id
  # elif packetType == ST_SYN:
  #   let seqNr = p.header.seqNr
  #   let connSeqNr = conn.seqNr
  # else:

  #   if packetType != ST_SYN or conn.state != synRecv: #and if ack_nr is invalid
  #     return 0 
  #handlePacket(conn, p)



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
  let protocol = createSocket()
  let dec = decodePacket(buf)
  if (dec.isOk()):
    let uTP = UtpProtocol.new()
    await processPacket(uTP, raddr, protocol, dec.get())
  else:
    warn "failed to decode packet from address", address = raddr

proc new*(T: type UtpProtocol, address: TransportAddress, rng = newRng()): UtpProtocol {.raises: [Defect, CatchableError].} =
  let ta = newDatagramTransport(processDatagram, local = address)
  UtpProtocol(transport: ta, rng: rng)


proc closeWait*(p: UtpProtocol): Future[void] =
  p.transport.closeWait()
