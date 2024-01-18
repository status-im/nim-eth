# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  sequtils,
  chronos,
  testutils/unittests,
  ./test_utils,
  ../../eth/keys,
  ../../eth/utp/[utp_router, utp_protocol],
  ../stubloglevel

proc setAcceptedCallback(
    event: AsyncEvent
  ): AcceptConnectionCallback[TransportAddress] =
  return (
    proc(server: UtpRouter[TransportAddress], client: UtpSocket[TransportAddress]): Future[void] =
      let fut = newFuture[void]()
      event.fire()
      fut.complete()
      fut
  )

proc registerIncomingSocketCallback(
    serverSockets: AsyncQueue
  ): AcceptConnectionCallback[TransportAddress] =
  return (
    proc(server: UtpRouter[TransportAddress], client: UtpSocket[TransportAddress]): Future[void] =
      serverSockets.addLast(client)
  )

proc allowOneIdCallback(
    allowedId: uint16
  ): AllowConnectionCallback[TransportAddress] =
  return (
     proc(r: UtpRouter[TransportAddress], remoteAddress: TransportAddress, connectionId: uint16): bool =
       connectionId == allowedId
  )

proc transferData(
    sender: UtpSocket[TransportAddress],
    receiver: UtpSocket[TransportAddress],
    data: seq[byte]
  ): Future[seq[byte]] {.async.} =
  let bytesWritten = await sender.write(data)
  check:
    bytesWritten.isOk()
    bytesWritten.value() == len(data)
  let received = await receiver.read(len(data))
  return received

type
  ClientServerScenario = object
    utp1: UtpProtocol
    utp2: UtpProtocol
    clientSocket: UtpSocket[TransportAddress]
    serverSocket: UtpSocket[TransportAddress]

  TwoClientsServerScenario = object
    utp1: UtpProtocol
    utp2: UtpProtocol
    utp3: UtpProtocol
    client1Socket: UtpSocket[TransportAddress]
    client2Socket: UtpSocket[TransportAddress]
    serverSocket1: UtpSocket[TransportAddress]
    serverSocket2: UtpSocket[TransportAddress]

proc initClientServerScenario(): Future[ClientServerScenario] {.async.} =
  let
    server1Incoming = newAsyncEvent() # Not used
    address1 = initTAddress("127.0.0.1", 9079)
    utpProto1 = UtpProtocol.new(setAcceptedCallback(server1Incoming), address1)

    utpProto2Sockets = newAsyncQueue[UtpSocket[TransportAddress]]()
    address2 = initTAddress("127.0.0.1", 9080)
    utpProto2 = UtpProtocol.new(registerIncomingSocketCallback(utpProto2Sockets), address2)

    clientSocket = await utpProto1.connectTo(address2)
    serverSocket = await utpProto2Sockets.popFirst()

  return ClientServerScenario(
    utp1: utpProto1,
    utp2: utpProto2,
    clientSocket: clientSocket.get(),
    serverSocket: serverSocket
  )

proc close(s: ClientServerScenario) {.async.} =
  await s.clientSocket.destroyWait()
  await s.serverSocket.destroyWait()
  await s.utp1.shutdownWait()
  await s.utp2.shutdownWait()

proc initTwoClientsOneServerScenario(): Future[TwoClientsServerScenario] {.async.} =
  let
    server1Incoming = newAsyncEvent() # not used
    address1 = initTAddress("127.0.0.1", 9079)
    utpProto1 = UtpProtocol.new(setAcceptedCallback(server1Incoming), address1)

    server2Incoming = newAsyncEvent() # not used
    address2 = initTAddress("127.0.0.1", 9080)
    utpProto2 = UtpProtocol.new(setAcceptedCallback(server2Incoming), address2)

    server3Sockets = newAsyncQueue[UtpSocket[TransportAddress]]()
    address3 = initTAddress("127.0.0.1", 9081)
    utpProto3 = UtpProtocol.new(registerIncomingSocketCallback(server3Sockets), address3)

    client1Socket = await utpProto1.connectTo(address3)
    client2Socket = await utpProto2.connectTo(address3)

  await waitUntil(proc (): bool = len(server3Sockets) == 2)

  return TwoClientsServerScenario(
    utp1: utpProto1,
    utp2: utpProto2,
    utp3: utpProto3,
    client1Socket: client1Socket.get(),
    client2Socket: client2Socket.get(),
    serverSocket1: server3Sockets[0],
    serverSocket2: server3Sockets[1]
  )

proc close(s: TwoClientsServerScenario) {.async.} =
  await s.utp1.shutdownWait()
  await s.utp2.shutdownWait()
  await s.utp3.shutdownWait()

procSuite "uTP over UDP protocol":
  let rng = newRng()

  asyncTest "Connect to remote host: test connection callback":
    let
      server1Incoming = newAsyncEvent()
      address1 = initTAddress("127.0.0.1", 9079)
      utpProto1 = UtpProtocol.new(setAcceptedCallback(server1Incoming), address1)

      server2Incoming = newAsyncEvent()
      address2 = initTAddress("127.0.0.1", 9080)
      utpProto2 = UtpProtocol.new(setAcceptedCallback(server2Incoming), address2)

      socketResult = await utpProto1.connectTo(address2)

    check socketResult.isOk()
    let socket = socketResult.value()

    # This future will complete when the accepted connection callback is called
    await server2Incoming.wait()

    check:
      socket.isConnected()
      # after a successful connection the outgoing buffer should be empty as
      # the SYN packet should have been acked
      socket.numPacketsInOutGoingBuffer() == 0

      server2Incoming.isSet()

    await utpProto1.shutdownWait()
    await utpProto2.shutdownWait()

  asyncTest "Connect to remote host: test udata pointer and use it in callback":
    proc cbUserData(
        server: UtpRouter[TransportAddress],
        client: UtpSocket[TransportAddress]): Future[void] =
      let q = getUserData[TransportAddress, AsyncQueue[UtpSocket[TransportAddress]]](server)
      q.addLast(client)

    let
      incomingConnections1 = newAsyncQueue[UtpSocket[TransportAddress]]()
      address1 = initTAddress("127.0.0.1", 9079)
      utpProto1 = UtpProtocol.new(cbUserData, address1, incomingConnections1)

      incomingConnections2 = newAsyncQueue[UtpSocket[TransportAddress]]()
      address2 = initTAddress("127.0.0.1", 9080)
      utpProto2 = UtpProtocol.new(cbUserData, address2, incomingConnections2)

      socketResult = await utpProto1.connectTo(address2)

    check socketResult.isOk()

    let clientSocket = socketResult.get()
    # This future will complete when the accepted connection callback is called
    let serverSocket = await incomingConnections2.get()

    check:
      clientSocket.isConnected()
      # after a successful connection the outgoing buffer should be empty as
      # the SYN packet should have been acked
      clientSocket.numPacketsInOutGoingBuffer() == 0

      # Server socket is not in connected state until first data transfer
      not serverSocket.isConnected()

    await utpProto1.shutdownWait()
    await utpProto2.shutdownWait()

  asyncTest "Connect to offline remote server host":
    let
      server1Incoming = newAsyncEvent()
      address1 = initTAddress("127.0.0.1", 9079)
      utpProto1 = UtpProtocol.new(
        setAcceptedCallback(server1Incoming), address1 , nil,
        SocketConfig.init(milliseconds(200)))

      address2 = initTAddress("127.0.0.1", 9080)

      socketResult = await utpProto1.connectTo(address2)

    check socketResult.isErr()
    let connectionError = socketResult.error()
    check connectionError.kind == ConnectionTimedOut

    await waitUntil(proc (): bool = utpProto1.openSockets() == 0)

    check utpProto1.openSockets() == 0

    await utpProto1.shutdownWait()

  asyncTest "Connect to remote host which was initially offline":
    let
      server1Incoming = newAsyncEvent()
      address1 = initTAddress("127.0.0.1", 9079)
      utpProto1 = UtpProtocol.new(
        setAcceptedCallback(server1Incoming), address1, nil,
        # Sets initial SYN timeout to 500ms
        SocketConfig.init(milliseconds(500)))

      address2 = initTAddress("127.0.0.1", 9080)

      futSock = utpProto1.connectTo(address2)

    # waiting 400 millisecond will trigger at least one re-send
    await sleepAsync(milliseconds(400))

    var server2Incoming = newAsyncEvent()
    let utpProto2 = UtpProtocol.new(setAcceptedCallback(server2Incoming), address2)

    # This future will complete when the accepted connection callback is called
    await server2Incoming.wait()

    discard (await futSock)

    check:
      futSock.finished() and (not futSock.failed()) and (not futSock.cancelled())
      server2Incoming.isSet()

    await utpProto1.shutdownWait()
    await utpProto2.shutdownWait()

  asyncTest "Data transfer where data fits into one packet":
    let s = await initClientServerScenario()

    check:
      s.clientSocket.isConnected()
      # after a successful connection the outgoing buffer should be empty as
      # the SYN packet should have been acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      # Server socket is not in connected state until first data transfer
      (not s.serverSocket.isConnected())

    let bytesToTransfer = rng[].generateBytes(100)

    let bytesReceivedFromClient = await transferData(
      s.clientSocket, s.serverSocket, bytesToTransfer)

    check:
      bytesToTransfer == bytesReceivedFromClient
      s.serverSocket.isConnected()

    let bytesReceivedFromServer = await transferData(
      s.serverSocket, s.clientSocket, bytesToTransfer)

    check:
      bytesToTransfer == bytesReceivedFromServer

    await s.close()

  asyncTest "Data transfer where data need to be sliced into multiple packets":
    let s = await initClientServerScenario()

    check:
      s.clientSocket.isConnected()
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      (not s.serverSocket.isConnected())

    # 20_000 bytes is way over maximal packet size
    let bytesToTransfer = rng[].generateBytes(20_000)

    let bytesReceivedFromClient = await transferData(
      s.clientSocket, s.serverSocket, bytesToTransfer)
    let bytesReceivedFromServer = await transferData(
      s.serverSocket, s.clientSocket, bytesToTransfer)

    # ultimately all send packets will acked, and outgoing buffer will be empty
    await waitUntil(proc (): bool = s.clientSocket.numPacketsInOutGoingBuffer() == 0)
    await waitUntil(proc (): bool = s.serverSocket.numPacketsInOutGoingBuffer() == 0)

    check:
      s.serverSocket.isConnected()
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      s.serverSocket.numPacketsInOutGoingBuffer() == 0
      bytesReceivedFromClient == bytesToTransfer
      bytesReceivedFromServer == bytesToTransfer

    await s.close()

  asyncTest "Multiple data transfers where data need to be sliced into multiple packets":
    let s = await initClientServerScenario()

    check:
      s.clientSocket.isConnected()
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

    const
      amountOfTransfers = 3
      amountOfBytes = 5000

    var totalBytesToTransfer: seq[byte]
    for i in 0..<amountOfTransfers:
      let bytesToTransfer = rng[].generateBytes(amountOfBytes)
      let written = await s.clientSocket.write(bytesToTransfer)

      check:
        written.isOk()
        written.value() == amountOfBytes

      totalBytesToTransfer.add(bytesToTransfer)

    let bytesReceived = await s.serverSocket.read(amountOfBytes * amountOfTransfers)
    await waitUntil(proc (): bool = s.clientSocket.numPacketsInOutGoingBuffer() == 0)

    check:
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      totalBytesToTransfer == bytesReceived

    await s.close()

  asyncTest "Data transfers from multiple clients to one server":
    let s = await initTwoClientsOneServerScenario()

    check:
      s.client1Socket.isConnected()
      s.client2Socket.isConnected()
      s.client1Socket.numPacketsInOutGoingBuffer() == 0
      s.client2Socket.numPacketsInOutGoingBuffer() == 0

    let
      numBytesToTransfer = 5000
      client1Data = rng[].generateBytes(numBytesToTransfer)
      client2Data = rng[].generateBytes(numBytesToTransfer)

    discard s.client1Socket.write(client1Data)
    discard s.client2Socket.write(client2Data)

    let serverReadBytes1 = await s.serverSocket1.read(numBytesToTransfer)
    let serverReadBytes2 = await s.serverSocket2.read(numBytesToTransfer)

    check:
      client1Data == serverReadBytes1
      client2Data == serverReadBytes2

    await s.close()

  asyncTest "Graceful stop of the socket":
    let s = await initClientServerScenario()
    check:
      s.clientSocket.isConnected()
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      (not s.serverSocket.isConnected())

    let bytesToTransfer = rng[].generateBytes(100)

    let bytesReceivedFromClient = await transferData(
      s.clientSocket, s.serverSocket, bytesToTransfer)

    check:
      bytesToTransfer == bytesReceivedFromClient
      s.serverSocket.isConnected()

    await s.clientSocket.closeWait()

    check:
      not s.clientSocket.isConnected()
      s.serverSocket.atEof()
      s.utp1.openSockets() == 0
      s.utp2.openSockets() == 1

    await s.serverSocket.destroyWait()

    check:
      not s.serverSocket.isConnected()
      s.utp2.openSockets() == 0

    await s.close()

  asyncTest "Read data until eof":
    let s = await initClientServerScenario()
    check:
      s.clientSocket.isConnected()
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      (not s.serverSocket.isConnected())

    let
      bytesToTransfer1 = rng[].generateBytes(1000)
      bytesToTransfer2 = rng[].generateBytes(1000)
      bytesToTransfer3 = rng[].generateBytes(1000)

    discard await s.clientSocket.write(bytesToTransfer1)
    discard await s.clientSocket.write(bytesToTransfer2)
    discard await s.clientSocket.write(bytesToTransfer3)
    await s.clientSocket.closeWait()

    let readData = await s.serverSocket.read()

    check:
      readData == concat(bytesToTransfer1, bytesToTransfer2, bytesToTransfer3)
      s.serverSocket.atEof()
      s.utp1.openSockets() == 0

    await s.close()

  asyncTest "Accept connection only from allowed peers":
    const
      allowedId: uint16 = 10
      lowSynTimeout = milliseconds(500)

    let
      server1Incoming = newAsyncEvent() # not used
      address1 = initTAddress("127.0.0.1", 9079)
      utpProto1 =
        UtpProtocol.new(
          setAcceptedCallback(server1Incoming), address1, nil,
          SocketConfig.init(lowSynTimeout)
        )

      server2Incoming = newAsyncEvent() # not used
      address2 = initTAddress("127.0.0.1", 9080)
      utpProto2 =
        UtpProtocol.new(
          setAcceptedCallback(server2Incoming), address2, nil,
          SocketConfig.init(lowSynTimeout)
        )

      server3Sockets = newAsyncQueue[UtpSocket[TransportAddress]]()
      address3 = initTAddress("127.0.0.1", 9081)
      utpProto3 =
        UtpProtocol.new(
          registerIncomingSocketCallback(server3Sockets),
          address3,
          nil,
          SocketConfig.init(),
          allowOneIdCallback(allowedId)
        )

    let allowedSocketRes = await utpProto1.connectTo(address3, allowedId)
    let notAllowedSocketRes = await utpProto2.connectTo(address3, allowedId + 1)

    check:
      allowedSocketRes.isOk()
      notAllowedSocketRes.isErr()
      # remote did not allow this connection and it timed out
      notAllowedSocketRes.error().kind == ConnectionTimedOut

    let clientSocket = allowedSocketRes.get()
    let serverSocket = await server3Sockets.get()

    check:
      clientSocket.connectionId() == allowedId
      serverSocket.connectionId() == allowedId

    await utpProto1.shutdownWait()
    await utpProto2.shutdownWait()
    await utpProto3.shutdownWait()

  asyncTest "Data transfer of a lot of data should increase window on sender side":
    let s = await initClientServerScenario()
    let startMaxWindow = 2 * s.clientSocket.getSocketConfig().payloadSize

    check:
      s.clientSocket.isConnected()
      # initially the window has value equal to a pre-configured constant
      s.clientSocket.currentMaxWindowSize == startMaxWindow
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      (not s.serverSocket.isConnected())

    # big transfer of 50kb
    let bytesToTransfer = rng[].generateBytes(50000)

    let bytesReceivedFromClient = await transferData(
      s.clientSocket, s.serverSocket, bytesToTransfer)

    # ultimately all send packets will be acked and the outgoing buffer will be empty
    await waitUntil(proc (): bool = s.clientSocket.numPacketsInOutGoingBuffer() == 0)

    check:
      # we can only assess that the window has grown, because the specific value
      # depends on particular timings
      s.clientSocket.currentMaxWindowSize > startMaxWindow
      s.serverSocket.isConnected()
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      bytesReceivedFromClient == bytesToTransfer

    await s.close()

  asyncTest "Unused socket should decay its max send window":
    let s = await initClientServerScenario()
    let startMaxWindow = 2 * s.clientSocket.getSocketConfig().payloadSize

    check:
      s.clientSocket.isConnected()
      # initially the window has value equal to a pre-configured constant
      s.clientSocket.currentMaxWindowSize == startMaxWindow
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      (not s.serverSocket.isConnected())

    # big transfer of 50kb
    let bytesToTransfer = rng[].generateBytes(50000)

    let bytesReceivedFromClient = await transferData(
      s.clientSocket, s.serverSocket, bytesToTransfer)

    # ultimately all send packets will be acked and the outgoing buffer will be empty
    await waitUntil(proc (): bool = s.clientSocket.numPacketsInOutGoingBuffer() == 0)

    let maximumMaxWindow = s.clientSocket.currentMaxWindowSize

    check:
      # we can only assess that the window has grown, because the specific value
      # depends on particular timings
      maximumMaxWindow > startMaxWindow
      s.serverSocket.isConnected()
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      bytesReceivedFromClient == bytesToTransfer

    # wait long enough to trigger timeout
    await sleepAsync(seconds(5))

    check:
      # window should decay when idle
      s.clientSocket.currentMaxWindowSize < maximumMaxWindow

    await s.close()

  asyncTest "Data transfer over multiple sockets":
    const
      amountOfTransfers = 100
      dataToSend: seq[byte] = repeat(byte 0xA0, 1_000_000)

    var readFutures: seq[Future[void]]

    proc readAndCheck(
        socket: UtpSocket[TransportAddress],
      ): Future[void] {.async.} =
      let readData = await socket.read()
      check:
        readData == dataToSend
        socket.atEof()

    proc handleIncomingConnection(
        server: UtpRouter[TransportAddress],
        client: UtpSocket[TransportAddress]
      ): Future[void] =
      readFutures.add(client.readAndCheck())

      var fut = newFuture[void]("test.AcceptConnectionCallback")
      fut.complete()
      return fut

    proc handleIncomingConnectionDummy(
        server: UtpRouter[TransportAddress],
        client: UtpSocket[TransportAddress]
      ): Future[void] =
        var fut = newFuture[void]("test.AcceptConnectionCallback")
        fut.complete()
        return fut

    let
      address1 = initTAddress("127.0.0.1", 9079)
      utpProto1 = UtpProtocol.new(handleIncomingConnectionDummy, address1)
      address2 = initTAddress("127.0.0.1", 9080)
      utpProto2 = UtpProtocol.new(handleIncomingConnection, address2)

    proc connectSendAndCheck(
        utpProto: UtpProtocol,
        address: TransportAddress
      ): Future[void] {.async.} =
      let socketRes = await utpProto.connectTo(address)
      check:
        socketRes.isOk()
      let socket = socketRes.value()
      let dataSend = await socket.write(dataToSend)
      check:
        dataSend.isOk()
        dataSend.value() == dataToSend.len()

      await socket.closeWait()

    let t0 = Moment.now()
    for i in 0..<amountOfTransfers:
      asyncSpawn utpProto1.connectSendAndCheck(address2)

    while readFutures.len() < amountOfTransfers:
      await sleepAsync(milliseconds(100))

    await allFutures(readFutures)
    let elapsed = Moment.now() - t0

    await utpProto1.shutdownWait()
    await utpProto2.shutdownWait()

    let megabitsSent = amountOfTransfers * dataToSend.len() * 8 / 1_000_000
    let seconds = float(elapsed.nanoseconds) / 1_000_000_000
    let throughput = megabitsSent / seconds

    echo ""
    echo "Sent ", amountOfTransfers, " asynchronous uTP transfers in ", seconds,
      " seconds, payload throughput: ", throughput, " Mbit/s"
