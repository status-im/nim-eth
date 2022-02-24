# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[sequtils, tables, options, sugar],
  chronos, bearssl,
  testutils/unittests,
  ./test_utils,
  ../../eth/utp/utp_router,
  ../../eth/utp/utp_protocol,
  ../../eth/keys,
  ../../eth/p2p/discoveryv5/random2


proc connectTillSuccess(p: UtpProtocol, to: TransportAddress, maxTries: int = 20): Future[UtpSocket[TransportAddress]] {.async.} = 
  var i = 0
  while true:
    let res = await p.connectTo(to)

    if res.isOk():
      return res.unsafeGet()
    else:
      inc i
      if i >= maxTries:
        raise newException(CatchableError, "Connection failed")

proc buildAcceptConnection(
    t: ref Table[UtpSocketKey[TransportAddress], UtpSocket[TransportAddress]]
  ): AcceptConnectionCallback[TransportAddress] = 
  return (
    proc (server: UtpRouter[TransportAddress], client: UtpSocket[TransportAddress]): Future[void] =
      let fut = newFuture[void]()
      let key = client.socketKey
      t[key] = client
      fut.complete()
      return fut
  )

proc getServerSocket(
  t: ref Table[UtpSocketKey[TransportAddress], UtpSocket[TransportAddress]], 
  clientAddress: TransportAddress,
  clientConnectionId: uint16): Option[UtpSocket[TransportAddress]] =
  let serverSocketKey = UtpSocketKey[TransportAddress](remoteAddress: clientAddress, rcvId: clientConnectionId + 1)
  let srvSocket = t.getOrDefault(serverSocketKey)
  if srvSocket == nil:
    return none[UtpSocket[TransportAddress]]()
  else:
    return some(srvSocket)

procSuite "Utp protocol over udp tests with loss and delays":
  let rng = newRng()

  proc sendBuilder(maxDelay: int, packetDropRate: int): SendCallbackBuilder =
    return (
      proc (d: DatagramTransport): SendCallback[TransportAddress] =
        return (
          proc (to: TransportAddress, data: seq[byte]): Future[void] {.async.} =
            let i = rand(rng[], 99)
            if i >= packetDropRate:
              let delay = milliseconds(rand(rng[], maxDelay))
              await sleepAsync(delay)
              await d.sendTo(to, data)
        )
    )

  proc testScenario(maxDelay: int, dropRate: int, cfg: SocketConfig = SocketConfig.init()): 
    Future[(
      UtpProtocol, 
      UtpSocket[TransportAddress], 
      UtpProtocol, 
      UtpSocket[TransportAddress])
    ] {.async.} =

    var connections1 = newTable[UtpSocketKey[TransportAddress], UtpSocket[TransportAddress]]()
    let address1 = initTAddress("127.0.0.1", 9080)
    let utpProt1 = 
      UtpProtocol.new(
        buildAcceptConnection(connections1), 
        address1,
        socketConfig = cfg,
        sendCallbackBuilder = sendBuilder(maxDelay, dropRate), 
        rng = rng)

    var connections2 = newTable[UtpSocketKey[TransportAddress], UtpSocket[TransportAddress]]()
    let address2 = initTAddress("127.0.0.1", 9081)
    let utpProt2 = 
      UtpProtocol.new(
        buildAcceptConnection(connections2),
        address2,
        socketConfig = cfg,
        sendCallbackBuilder = sendBuilder(maxDelay, dropRate),
        rng = rng)

    let clientSocket = await utpProt1.connectTillSuccess(address2)
    let maybeServerSocket = connections2.getServerSocket(address1, clientSocket.socketKey.rcvId)

    let serverSocket = maybeServerSocket.unsafeGet()

    return (utpProt1, clientSocket, utpProt2, serverSocket)

  type TestCase = object
    # in miliseconds
    maxDelay: int
    dropRate: int
    bytesToTransfer: int
    bytesPerRead: int
    cfg: SocketConfig

  proc init(
    T: type TestCase, 
    maxDelay: int, 
    dropRate: int, 
    bytesToTransfer: int,
    cfg: SocketConfig = SocketConfig.init(),
    bytesPerRead: int = 0): TestCase =
    TestCase(maxDelay: maxDelay, dropRate: dropRate, bytesToTransfer: bytesToTransfer, cfg: cfg, bytesPerRead: bytesPerRead)


  let testCases = @[
    TestCase.init(45, 10, 40000),
    TestCase.init(25, 15, 40000),
    # super small recv buffer which will be constantly on the brink of being full
    TestCase.init(15, 5, 40000, SocketConfig.init(optRcvBuffer = uint32(6000), remoteWindowResetTimeout = seconds(5))),
    TestCase.init(15, 10, 40000, SocketConfig.init(optRcvBuffer = uint32(6000), remoteWindowResetTimeout = seconds(5)))
  ]

  asyncTest "Write and Read large data in different network conditions":
    for testCase in testCases:

      let (
        clientProtocol,
        clientSocket,
        serverProtocol,
        serverSocket) = await testScenario(testCase.maxDelay, testCase.dropRate, testcase.cfg)

      let smallBytes = 10
      let smallBytesToTransfer = generateByteArray(rng[], smallBytes)
      # first transfer and read to make server socket connecteced
      let write1 = await clientSocket.write(smallBytesToTransfer)
      let read1 = await serverSocket.read(smallBytes)

      check:
        write1.isOk()
        read1 == smallBytesToTransfer

      let numBytes = testCase.bytesToTransfer
      let bytesToTransfer = generateByteArray(rng[], numBytes)

      discard clientSocket.write(bytesToTransfer)
      discard serverSocket.write(bytesToTransfer)
      
      let serverReadFut = serverSocket.read(numBytes)
      let clientReadFut = clientSocket.read(numBytes)

      yield serverReadFut
      yield clientReadFut

      let clientRead = clientReadFut.read()
      let serverRead = serverReadFut.read()

      check:
        clientRead == bytesToTransfer
        serverRead == bytesToTransfer
      
      await clientProtocol.shutdownWait()
      await serverProtocol.shutdownWait()

  let testCases1 = @[
    # small buffers so it will fill up between reads
    TestCase.init(15, 5, 40000, SocketConfig.init(optRcvBuffer = uint32(6000), remoteWindowResetTimeout = seconds(5)), 10000),
    TestCase.init(15, 10, 40000, SocketConfig.init(optRcvBuffer = uint32(6000), remoteWindowResetTimeout = seconds(5)), 10000),
    TestCase.init(15, 15, 40000, SocketConfig.init(optRcvBuffer = uint32(6000), remoteWindowResetTimeout = seconds(5)), 10000)
  ]

  proc readWithMultipleReads(s: UtpSocket[TransportAddress], numOfReads: int, bytesPerRead: int): Future[seq[byte]] {.async.}=
    var i = 0
    var res: seq[byte] = @[]
    while i < numOfReads:
      let bytes = await s.read(bytesPerRead)
      res.add(bytes)
      inc i
    return res
    
  asyncTest "Write and Read large data in different network conditions split over several reads":
    for testCase in testCases1:

      let (
        clientProtocol,
        clientSocket,
        serverProtocol,
        serverSocket) = await testScenario(testCase.maxDelay, testCase.dropRate, testcase.cfg)

      let smallBytes = 10
      let smallBytesToTransfer = generateByteArray(rng[], smallBytes)
      # first transfer and read to make server socket connecteced
      let write1 = await clientSocket.write(smallBytesToTransfer)
      let read1 = await serverSocket.read(smallBytes)

      check:
        read1 == smallBytesToTransfer

      let numBytes = testCase.bytesToTransfer
      let bytesToTransfer = generateByteArray(rng[], numBytes)

      discard clientSocket.write(bytesToTransfer)
      discard serverSocket.write(bytesToTransfer)
      
      let numOfReads = int(testCase.bytesToTransfer / testCase.bytesPerRead)
      let serverReadFut = serverSocket.readWithMultipleReads(numOfReads, testCase.bytesPerRead)
      let clientReadFut = clientSocket.readWithMultipleReads(numOfReads, testCase.bytesPerRead)

      yield serverReadFut

      yield clientReadFut

      let clientRead = clientReadFut.read()
      let serverRead = serverReadFut.read()

      check:
        clientRead == bytesToTransfer
        serverRead == bytesToTransfer

      await clientProtocol.shutdownWait()
      await serverProtocol.shutdownWait()

