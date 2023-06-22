# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[tables, options, hashes, math],
  chronos, chronicles,
  ./utp_router,
  ../keys

logScope:
  topics = "eth utp"

type
  # For now utp protocol is tied to udp transport, but ultimately we would like to
  # abstract underlying transport to be able to run utp over udp, discoveryv5 or
  # maybe some test transport
  UtpProtocol* = ref object
    transport: DatagramTransport
    utpRouter: UtpRouter[TransportAddress]

  SendCallbackBuilder* =
    proc (d: DatagramTransport):
      SendCallback[TransportAddress] {.gcsafe, raises: [].}

chronicles.formatIt(TransportAddress): $it

# This should probably be defined in TransportAddress module, as hash function should
# be consistent with equality function
# in nim zero arrays always have hash equal to 0, irrespectively of array size, to
# avoid clashes between different types of addresses, each type have mixed different
# magic number
proc hash(x: TransportAddress): Hash =
  var h: Hash = 0
  case x.family
  of AddressFamily.None:
    h = h !& 31
    !$h
  of AddressFamily.IPv4:
    h = h !& x.address_v4.hash
    h = h !& x.port.hash
    h = h !& 37
    !$h
  of AddressFamily.IPv6:
    h = h !& x.address_v6.hash
    h = h !& x.port.hash
    h = h !& 41
    !$h
  of AddressFamily.Unix:
    h = h !& x.address_un.hash
    h = h !& 43
    !$h

# Required to use socketKey as key in hashtable
proc hash(x: UtpSocketKey[TransportAddress]): Hash =
  var h = 0
  h = h !& x.remoteAddress.hash
  h = h !& x.rcvId.hash
  !$h

proc processDatagram(transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async.} =
  let router = getUserData[UtpRouter[TransportAddress]](transp)
  # TODO: should we use `peekMessage()` to avoid allocation?
  let buf = try: transp.getMessage()
            except TransportOsError as e:
              # This is likely to be local network connection issues.
              return
  await processIncomingBytes[TransportAddress](router, buf, raddr)

proc initSendCallback(t: DatagramTransport): SendCallback[TransportAddress] =
  return (
    proc (to: TransportAddress, data: seq[byte]): Future[void] =
      t.sendTo(to, data)
  )

proc new*(
    T: type UtpProtocol,
    acceptConnectionCb: AcceptConnectionCallback[TransportAddress],
    address: TransportAddress,
    udata: pointer = nil,
    socketConfig: SocketConfig = SocketConfig.init(),
    allowConnectionCb: AllowConnectionCallback[TransportAddress] = nil,
    sendCallbackBuilder: SendCallbackBuilder = nil,
    rng = newRng()): UtpProtocol {.raises: [CatchableError].} =

  doAssert(not(isNil(acceptConnectionCb)))

  let router = UtpRouter[TransportAddress].new(
    acceptConnectionCb,
    allowConnectionCb,
    udata,
    socketConfig,
    rng
  )

  let ta = newDatagramTransport(processDatagram, udata = router, local = address)

  if (sendCallbackBuilder == nil):
    router.sendCb = initSendCallback(ta)
  else:
    router.sendCb = sendCallbackBuilder(ta)

  UtpProtocol(transport: ta, utpRouter: router)

proc new*(
    T: type UtpProtocol,
    acceptConnectionCb: AcceptConnectionCallback[TransportAddress],
    address: TransportAddress,
    udata: ref,
    socketConfig: SocketConfig = SocketConfig.init(),
    allowConnectionCb: AllowConnectionCallback[TransportAddress] = nil,
    sendCallbackBuilder: SendCallbackBuilder = nil,
    rng = newRng()): UtpProtocol {.raises: [CatchableError].} =
  GC_ref(udata)
  UtpProtocol.new(
    acceptConnectionCb,
    address,
    cast[pointer](udata),
    socketConfig,
    allowConnectionCb,
    sendCallbackBuilder,
    rng
  )

proc shutdownWait*(p: UtpProtocol): Future[void] {.async.} =
  ## closes all managed utp sockets and then underlying transport
  await p.utpRouter.shutdownWait()
  await p.transport.closeWait()

proc connectTo*(r: UtpProtocol, address: TransportAddress): Future[ConnectionResult[TransportAddress]] =
  return r.utpRouter.connectTo(address)

proc connectTo*(r: UtpProtocol, address: TransportAddress, connectionId: uint16): Future[ConnectionResult[TransportAddress]] =
  return r.utpRouter.connectTo(address, connectionId)

proc openSockets*(r: UtpProtocol): int =
  len(r.utpRouter)
