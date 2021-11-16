# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/hashes,
  chronos, bearssl, chronicles,
  testutils/unittests,
  ./test_utils,
  ../../eth/utp/utp_router,
  ../../eth/utp/packets,
  ../../eth/keys

proc hash*(x: UtpSocketKey[int]): Hash =
  var h = 0
  h = h !& x.remoteAddress.hash
  h = h !& x.rcvId.hash
  !$h

type
  TestError* = object of CatchableError

procSuite "Utp router unit tests":
  let rng = newRng()
  let testSender = 1
  let testSender2 = 2
  let testBufferSize = 1024'u32

  proc registerIncomingSocketCallback(serverSockets: AsyncQueue): AcceptConnectionCallback[int] =
    return (
      proc(server: UtpRouter[int], client: UtpSocket[int]): Future[void] =
        serverSockets.addLast(client)
    )

  proc testSend(to: int, bytes: seq[byte]): Future[void] =
    let f = newFuture[void]()
    f.complete()
    f

  proc initTestSnd(q: AsyncQueue[(Packet, int)]): SendCallback[int]=
    return  (
      proc (to: int, bytes: seq[byte]): Future[void] =
        let p = decodePacket(bytes).get()
        q.addLast((p, to))
    )

  template connectOutgoing(
    r: UtpRouter[int],
    remote: int,
    pq: AsyncQueue[(Packet, int)],
    initialRemoteSeq: uint16): (UtpSocket[int], Packet)= 
    let connectFuture = router.connectTo(remote)
    
    let (initialPacket, sender) = await pq.get()

    check:
      initialPacket.header.pType == ST_SYN

    let responseAck = ackPacket(initialRemoteSeq, initialPacket.header.connectionId, initialPacket.header.seqNr, testBufferSize)

    await router.processIncomingBytes(encodePacket(responseAck), remote)

    let outgoingSocket = await connectFuture
    (outgoingSocket.get(), initialPacket)

  asyncTest "Router should ingnore non utp packets":
    let q = newAsyncQueue[UtpSocket[int]]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = testSend

    await router.processIncomingBytes(@[1'u8, 2, 3], testSender)

    check:
      router.len() == 0
      q.len() == 0

  asyncTest "Router should create new incoming socket when receiving not known syn packet":
    let q = newAsyncQueue[UtpSocket[int]]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = testSend
    let encodedSyn = encodePacket(synPacket(10, 10, 10))

    await router.processIncomingBytes(encodedSyn, testSender)

    check:
      router.len() == 1

  asyncTest "Router should create new incoming socket when receiving same syn packet from diffrent sender":
    let q = newAsyncQueue[UtpSocket[int]]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = testSend
    let encodedSyn = encodePacket(synPacket(10, 10, 10))

    await router.processIncomingBytes(encodedSyn, testSender)

    check:
      router.len() == 1

    await router.processIncomingBytes(encodedSyn, testSender2)

    check:
      router.len() == 2

  asyncTest "Router should ignore duplicated syn packet":
    let q = newAsyncQueue[UtpSocket[int]]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = testSend
    let encodedSyn = encodePacket(synPacket(10, 10, 10))

    await router.processIncomingBytes(encodedSyn, testSender)

    check:
      router.len() == 1

    await router.processIncomingBytes(encodedSyn, testSender)

    check:
      router.len() == 1

  asyncTest "Router should clear closed incoming sockets":
    let q = newAsyncQueue[UtpSocket[int]]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = testSend
    let encodedSyn = encodePacket(synPacket(10, 10, 10))

    await router.processIncomingBytes(encodedSyn, testSender)

    let socket = await q.get()

    check:
      router.len() == 1

    await socket.destroyWait()

    check:
      not socket.isConnected()
      router.len() == 0

  asyncTest "Router should connect to out going peer":
    let q = newAsyncQueue[UtpSocket[int]]()
    let pq = newAsyncQueue[(Packet, int)]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = initTestSnd(pq)

    let (outgoingSocket, initialSyn) = router.connectOutgoing(testSender2, pq, 30'u16)

    check:
      outgoingSocket.isConnected()
      router.len() == 1

  asyncTest "Router should fail connect when socket syn will not be acked":
    let q = newAsyncQueue[UtpSocket[int]]()
    let pq = newAsyncQueue[(Packet, int)]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(milliseconds(500)), rng)
    router.sendCb = initTestSnd(pq)

    let connectFuture = router.connectTo(testSender2)
    
    let (initialPacket, sender) = await pq.get()

    check:
      initialPacket.header.pType == ST_SYN

    let connectResult = await connectFuture

    check:
      connectResult.isErr()
      connectResult.error().kind == ConnectionTimedOut
      router.len() == 0

  asyncTest "Router should clear all resources when connection future is cancelled":
    let q = newAsyncQueue[UtpSocket[int]]()
    let pq = newAsyncQueue[(Packet, int)]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(milliseconds(500)), rng)
    router.sendCb = initTestSnd(pq)

    let connectFuture = router.connectTo(testSender2)
    
    let (initialPacket, sender) = await pq.get()

    check:
      initialPacket.header.pType == ST_SYN
      router.len() == 1

    await connectFuture.cancelAndWait() 

    check:
      router.len() == 0

  asyncTest "Router should clear all resources and handle error while sending syn packet":
    let q = newAsyncQueue[UtpSocket[int]]()
    let pq = newAsyncQueue[(Packet, int)]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(milliseconds(500)), rng)
    router.sendCb =
      proc (to: int, data: seq[byte]): Future[void] =
        let f = newFuture[void]()
        f.fail(newException(TestError, "faile"))
        return f

    let connectResult = await router.connectTo(testSender2)

    await waitUntil(proc (): bool = router.len() == 0)

    check:
      connectResult.isErr()
      connectResult.error().kind == ErrorWhileSendingSyn
      cast[TestError](connectResult.error().error) is TestError
      router.len() == 0
  
  asyncTest "Router should clear closed outgoing connections":
    let q = newAsyncQueue[UtpSocket[int]]()
    let pq = newAsyncQueue[(Packet, int)]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = initTestSnd(pq)

    let (outgoingSocket, initialSyn) = router.connectOutgoing(testSender2, pq, 30'u16)

    check:
      outgoingSocket.isConnected()
      router.len() == 1

    await outgoingSocket.destroyWait()

    check:
      not outgoingSocket.isConnected()
      router.len() == 0

  asyncTest "Router should respond with Reset when receiving packet for not known connection":
    let q = newAsyncQueue[UtpSocket[int]]()
    let pq = newAsyncQueue[(Packet, int)]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = initTestSnd(pq)

    let sndId = 10'u16
    let dp = dataPacket(10'u16, sndId, 10'u16, 10'u32, @[1'u8])

    await router.processIncomingBytes(encodePacket(dp), testSender2)

    let (packet, sender) = await pq.get()
    check:
      packet.header.pType == ST_RESET
      packet.header.connectionId == sndId
      sender == testSender2

  asyncTest "Router close incoming connection which receives reset":
    let q = newAsyncQueue[UtpSocket[int]]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = testSend
    let recvId = 10'u16
    let encodedSyn = encodePacket(synPacket(10, recvId, 10))

    await router.processIncomingBytes(encodedSyn, testSender)

    check:
      router.len() == 1

    let rstPacket = resetPacket(10, recvId, 10)

    await router.processIncomingBytes(encodePacket(rstPacket), testSender)

    await waitUntil(proc (): bool = router.len() == 0)

    check:
      router.len() == 0
  
  asyncTest "Router close outgoing connection which receives reset":
    let q = newAsyncQueue[UtpSocket[int]]()
    let pq = newAsyncQueue[(Packet, int)]()
    let router = UtpRouter[int].new(registerIncomingSocketCallback(q), SocketConfig.init(), rng)
    router.sendCb = initTestSnd(pq)

    let (outgoingSocket, initialSyn) = router.connectOutgoing(testSender2, pq, 30'u16)

    check:
      router.len() == 1

    # remote side sendId is syn.header.connectionId + 1
    let rstPacket = resetPacket(10, initialSyn.header.connectionId + 1, 10)

    await router.processIncomingBytes(encodePacket(rstPacket), testSender2)

    await waitUntil(proc (): bool = router.len() == 0)

    check:
      router.len() == 0

