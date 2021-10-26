# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, options, hashes, sugar, math],
  chronos, chronicles, bearssl,
  ./utp_router,
  ../keys

logScope:
  topics = "utp"

type
  # For now utp protocol is tied to udp transport, but ultimatly we would like to
  # abstract underlying transport to be able to run utp over udp, discoveryv5 or
  # maybe some test transport
  UtpProtocol* = ref object
    transport: DatagramTransport
    utpRouter: UtpRouter

proc processDatagram(transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async.} =
  let router = getUserData[UtpRouter](transp)
  # TODO: should we use `peekMessage()` to avoid allocation?
  let buf = try: transp.getMessage()
            except TransportOsError as e:
              # This is likely to be local network connection issues.
              return
  await router.processIncomingBytes(buf, raddr)

proc initSendCallback(t: DatagramTransport): SendCallback =
  return (
    proc (to: TransportAddress, data: seq[byte]): Future[void] = 
      t.sendTo(to, data)
  )

proc new*(
  T: type UtpProtocol, 
  acceptConnectionCb: AcceptConnectionCallback, 
  address: TransportAddress,
  socketConfig: SocketConfig = SocketConfig.init(),
  rng = newRng()): UtpProtocol {.raises: [Defect, CatchableError].} =
  doAssert(not(isNil(acceptConnectionCb)))

  let router = UtpRouter.new(
    acceptConnectionCb,
    socketConfig,
    rng
  )

  let ta = newDatagramTransport(processDatagram, udata = router, local = address)
  router.sendCb = initSendCallback(ta)
  UtpProtocol(transport: ta, utpRouter: router)

proc closeWait*(p: UtpProtocol): Future[void] {.async.} =
  # TODO Rething all this when working on FIN and RESET packets and proper handling
  # of resources
  await p.transport.closeWait()
  p.utpRouter.close()

proc connectTo*(r: UtpProtocol, address: TransportAddress): Future[UtpSocket] {.async.} =
  return await r.utpRouter.connectTo(address)

proc openSockets*(r: UtpProtocol): int =
  len(r.utpRouter)
