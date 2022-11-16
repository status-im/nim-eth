# Copyright (c) 2020-2021 Status Research & Development GmbH
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
  ../../eth/utp/utp_router as rt,
  ../../eth/utp/utp_protocol,
  ../../eth/keys,
  ../stubloglevel

proc setAcceptedCallback(event: AsyncEvent): AcceptConnectionCallback[TransportAddress] =
  return (
    proc(server: UtpRouter[TransportAddress], client: UtpSocket[TransportAddress]): Future[void] =
      let fut = newFuture[void]()
      event.fire()
      fut.complete()
      fut
  )

proc registerIncomingSocketCallback(serverSockets: AsyncQueue): AcceptConnectionCallback[TransportAddress] =
  return (
    proc(server: UtpRouter[TransportAddress], client: UtpSocket[TransportAddress]): Future[void] =
      serverSockets.addLast(client)
  )

proc allowOneIdCallback(allowedId: uint16): AllowConnectionCallback[TransportAddress] =
  return (
     proc(r: UtpRouter[TransportAddress], remoteAddress: TransportAddress, connectionId: uint16): bool =
       connectionId == allowedId
  )

proc transferData(sender: UtpSocket[TransportAddress], receiver: UtpSocket[TransportAddress], data: seq[byte]): Future[seq[byte]] {.async.} =
  let bytesWritten = await sender.write(data)
  doAssert bytesWritten.get() == len(data)
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
    clientSocket1: UtpSocket[TransportAddress]
    clientSocket2: UtpSocket[TransportAddress]
    serverSocket1: UtpSocket[TransportAddress]
    serverSocket2: UtpSocket[TransportAddress]

proc initClientServerScenario(): Future[ClientServerScenario] {.async.} =
  let q = newAsyncQueue[UtpSocket[TransportAddress]]()
  var server1Called = newAsyncEvent()
  let address = initTAddress("127.0.0.1", 9079)
  let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address)

  let address1 = initTAddress("127.0.0.1", 9080)
  let utpProt2 = UtpProtocol.new(registerIncomingSocketCallback(q), address1)
  let clientSocket = await utpProt1.connectTo(address1)
    # this future will be completed when we called accepted connection callback
  let serverSocket = await q.popFirst()

  return ClientServerScenario(
    utp1: utpProt1,
    utp2: utpProt2,
    clientSocket: clientSocket.get(),
    serverSocket: serverSocket
  )

proc close(s: ClientServerScenario) {.async.} =
  await s.clientSocket.destroyWait()
  await s.serverSocket.destroyWait()
  await s.utp1.shutdownWait()
  await s.utp2.shutdownWait()

proc init2ClientsServerScenario(): Future[TwoClientsServerScenario] {.async.} =
  var serverSockets = newAsyncQueue[UtpSocket[TransportAddress]]()
  var server1Called = newAsyncEvent()
  let address1 = initTAddress("127.0.0.1", 9079)
  let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address1)

  let address2 = initTAddress("127.0.0.1", 9080)
  let utpProt2 = UtpProtocol.new(registerIncomingSocketCallback(serverSockets), address2)

  let address3 = initTAddress("127.0.0.1", 9081)
  let utpProt3 = UtpProtocol.new(registerIncomingSocketCallback(serverSockets), address3)

  let clientSocket1 = await utpProt1.connectTo(address2)
  let clientSocket2 = await utpProt1.connectTo(address3)

  await waitUntil(proc (): bool = len(serverSockets) == 2)

  # this future will be completed when we called accepted connection callback
  let serverSocket1 = serverSockets[0]
  let serverSocket2 = serverSockets[1]

  return TwoClientsServerScenario(
    utp1: utpProt1,
    utp2: utpProt2,
    utp3: utpProt3,
    clientSocket1: clientSocket1.get(),
    clientSocket2: clientSocket2.get(),
    serverSocket1: serverSocket1,
    serverSocket2: serverSocket2
  )

proc close(s: TwoClientsServerScenario) {.async.} =
  await s.utp1.shutdownWait()
  await s.utp2.shutdownWait()
  await s.utp3.shutdownWait()

procSuite "Utp protocol over udp tests":
  let rng = newRng()

  asyncTest "Success connect to remote host":
    let server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address)

    var server2Called = newAsyncEvent()
    let address1 = initTAddress("127.0.0.1", 9080)
    let utpProt2 = UtpProtocol.new(setAcceptedCallback(server2Called), address1)

    let sockResult = await utpProt1.connectTo(address1)
    let sock = sockResult.get()
    # this future will be completed when we called accepted connection callback
    await server2Called.wait()

    check:
      sock.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      sock.numPacketsInOutGoingBuffer() == 0

      server2Called.isSet()

    await utpProt1.shutdownWait()
    await utpProt2.shutdownWait()


  proc cbUserData(server: UtpRouter[TransportAddress], client: UtpSocket[TransportAddress]): Future[void] =
    let q = rt.getUserData[TransportAddress, AsyncQueue[UtpSocket[TransportAddress]]](server)
    q.addLast(client)

  asyncTest "Provide user data pointer and use it in callback":
    let incomingConnections = newAsyncQueue[UtpSocket[TransportAddress]]()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(cbUserData, address, incomingConnections)

    let address1 = initTAddress("127.0.0.1", 9080)
    let utpProt2 = UtpProtocol.new(cbUserData, address1, incomingConnections)

    let connResult = await utpProt1.connectTo(address1)

    check:
      connResult.isOk()

    let clientSocket = connResult.get()
    # this future will be completed when we called accepted connection callback
    let serverSocket = await incomingConnections.get()

    check:
      clientSocket.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      clientSocket.numPacketsInOutGoingBuffer() == 0

      not serverSocket.isConnected()

    await utpProt1.shutdownWait()
    await utpProt2.shutdownWait()

  asyncTest "Fail to connect to offline remote host":
    let server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address , nil, SocketConfig.init(milliseconds(200)))

    let address1 = initTAddress("127.0.0.1", 9080)

    let connectionResult = await utpProt1.connectTo(address1)

    check:
      connectionResult.isErr()

    let connectionError = connectionResult.error()

    check:
      connectionError.kind == ConnectionTimedOut

    await waitUntil(proc (): bool = utpProt1.openSockets() == 0)

    check:
      utpProt1.openSockets() == 0

    await utpProt1.shutdownWait()

  asyncTest "Success connect to remote host which initially was offline":
    let server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address, nil, SocketConfig.init(milliseconds(500)))

    let address1 = initTAddress("127.0.0.1", 9080)

    let futSock = utpProt1.connectTo(address1)

    # waiting 400 millisecond will trigger at least one re-send
    await sleepAsync(milliseconds(400))

    var server2Called = newAsyncEvent()
    let utpProt2 = UtpProtocol.new(setAcceptedCallback(server2Called), address1)

    # this future will be completed when we called accepted connection callback
    await server2Called.wait()

    yield futSock

    check:
      futSock.finished() and (not futSock.failed()) and (not futSock.cancelled())
      server2Called.isSet()

    await utpProt1.shutdownWait()
    await utpProt2.shutdownWait()

  asyncTest "Success data transfer when data fits into one packet":
    let s = await initClientServerScenario()

    check:
      s.clientSocket.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      # Server socket is not in connected state, until first data transfer
      (not s.serverSocket.isConnected())

    let bytesToTransfer = rng[].generateBytes(100)

    let bytesReceivedFromClient = await transferData(s.clientSocket, s.serverSocket, bytesToTransfer)

    check:
      bytesToTransfer == bytesReceivedFromClient
      s.serverSocket.isConnected()

    let bytesReceivedFromServer = await transferData(s.serverSocket, s.clientSocket, bytesToTransfer)

    check:
      bytesToTransfer == bytesReceivedFromServer

    await s.close()

  asyncTest "Success data transfer when data need to be sliced into multiple packets":
    let s = await initClientServerScenario()

    check:
      s.clientSocket.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      (not s.serverSocket.isConnected())

    # 5000 bytes is over maximal packet size
    let bytesToTransfer = rng[].generateBytes(5000)

    let bytesReceivedFromClient = await transferData(s.clientSocket, s.serverSocket, bytesToTransfer)
    let bytesReceivedFromServer = await transferData(s.serverSocket, s.clientSocket, bytesToTransfer)

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

  asyncTest "Success multiple data transfers when data need to be sliced into multiple packets":
    let s = await initClientServerScenario()

    check:
      s.clientSocket.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0


    # 5000 bytes is over maximal packet size
    let bytesToTransfer = rng[].generateBytes(5000)

    let written = await s.clientSocket.write(bytesToTransfer)

    check:
      written.get() == len(bytesToTransfer)

    let bytesToTransfer1 = rng[].generateBytes(5000)

    let written1 = await s.clientSocket.write(bytesToTransfer1)

    check:
      written1.get() == len(bytesToTransfer)

    let bytesReceived = await s.serverSocket.read(len(bytesToTransfer) + len(bytesToTransfer1))

    # ultimately all send packets will acked, and outgoing buffer will be empty
    await waitUntil(proc (): bool = s.clientSocket.numPacketsInOutGoingBuffer() == 0)

    check:
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      bytesToTransfer.concat(bytesToTransfer1) == bytesReceived

    await s.close()

  asyncTest "Success data transfers from multiple clients":
    let s = await init2ClientsServerScenario()

    check:
      s.clientSocket1.isConnected()
      s.clientSocket2.isConnected()
      s.clientSocket1.numPacketsInOutGoingBuffer() == 0
      s.clientSocket2.numPacketsInOutGoingBuffer() == 0

    let numBytesToTransfer = 5000
    let client1Data = rng[].generateBytes(numBytesToTransfer)
    let client2Data = rng[].generateBytes(numBytesToTransfer)

    discard s.clientSocket1.write(client1Data)
    discard s.clientSocket2.write(client2Data)

    let server1ReadBytes = await s.serverSocket1.read(numBytesToTransfer)
    let server2ReadBytes = await s.serverSocket2.read(numBytesToTransfer)

    check:
      client1Data == server1ReadBytes
      client2Data == server2ReadBytes

    await s.close()

  asyncTest "Gracefully stop of the socket":
    let s = await initClientServerScenario()
    check:
      s.clientSocket.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      # Server socket is not in connected state, until first data transfer
      (not s.serverSocket.isConnected())

    let bytesToTransfer = rng[].generateBytes(100)

    let bytesReceivedFromClient = await transferData(s.clientSocket, s.serverSocket, bytesToTransfer)

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

  asyncTest "Reading data until eof":
    let s = await initClientServerScenario()
    check:
      s.clientSocket.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      # Server socket is not in connected state, until first data transfer
      (not s.serverSocket.isConnected())

    let bytesToTransfer1 = rng[].generateBytes(1000)
    let bytesToTransfer2 = rng[].generateBytes(1000)
    let bytesToTransfer3 = rng[].generateBytes(1000)

    let w1 = await s.clientSocket.write(bytesToTransfer1)
    let w2 = await s.clientSocket.write(bytesToTransfer2)
    let w3 = await s.clientSocket.write(bytesToTransfer3)
    await s.clientSocket.closeWait()

    let readData = await s.serverSocket.read()

    check:
      readData == concat(bytesToTransfer1, bytesToTransfer2, bytesToTransfer3)
      s.serverSocket.atEof()
      s.utp1.openSockets() == 0

    await s.close()

  asyncTest "Accept connection only from allowed peers":
    let allowedId: uint16 = 10
    let lowSynTimeout = milliseconds(500)
    var serverSockets = newAsyncQueue[UtpSocket[TransportAddress]]()
    var server1Called = newAsyncEvent()
    let address1 = initTAddress("127.0.0.1", 9079)
    let utpProt1 =
      UtpProtocol.new(setAcceptedCallback(server1Called), address1, nil, SocketConfig.init(lowSynTimeout))

    let address2 = initTAddress("127.0.0.1", 9080)
    let utpProt2 =
      UtpProtocol.new(registerIncomingSocketCallback(serverSockets), address2, nil, SocketConfig.init(lowSynTimeout))

    let address3 = initTAddress("127.0.0.1", 9081)
    let utpProt3 =
      UtpProtocol.new(
        registerIncomingSocketCallback(serverSockets),
        address3,
        nil,
        SocketConfig.init(),
        allowOneIdCallback(allowedId)
      )

    let allowedSocketRes = await utpProt1.connectTo(address3, allowedId)
    let notAllowedSocketRes = await utpProt2.connectTo(address3, allowedId + 1)

    check:
      allowedSocketRes.isOk()
      notAllowedSocketRes.isErr()
      # remote did not allow this connection, and ultimately it did time out
      notAllowedSocketRes.error().kind == ConnectionTimedOut

    let clientSocket = allowedSocketRes.get()
    let serverSocket = await serverSockets.get()

    check:
      clientSocket.connectionId() == allowedId
      serverSocket.connectionId() == allowedId

    await utpProt1.shutdownWait()
    await utpProt2.shutdownWait()
    await utpProt3.shutdownWait()

  asyncTest "Success data transfer of a lot of data should increase available window on sender side":
    let s = await initClientServerScenario()
    let startMaxWindow = 2 * s.clientSocket.getSocketConfig().payloadSize
    check:
      s.clientSocket.isConnected()
      # initially window has value equal to some pre configured constant
      s.clientSocket.currentMaxWindowSize == startMaxWindow
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      (not s.serverSocket.isConnected())

    # big transfer of 50kb
    let bytesToTransfer = rng[].generateBytes(50000)

    let bytesReceivedFromClient = await transferData(s.clientSocket, s.serverSocket, bytesToTransfer)

    # ultimately all send packets will acked, and outgoing buffer will be empty
    await waitUntil(proc (): bool = s.clientSocket.numPacketsInOutGoingBuffer() == 0)

    check:
      # we can only assert that window has grown, because specific values depends on
      # particular timings
      s.clientSocket.currentMaxWindowSize > startMaxWindow
      s.serverSocket.isConnected()
      s.clientSocket.numPacketsInOutGoingBuffer() == 0
      bytesReceivedFromClient == bytesToTransfer

    await s.close()

  asyncTest "Not used socket should decay its max send window":
    let s = await initClientServerScenario()
    let startMaxWindow = 2 * s.clientSocket.getSocketConfig().payloadSize

    check:
      s.clientSocket.isConnected()
      # initially window has value equal to some pre configured constant
      s.clientSocket.currentMaxWindowSize == startMaxWindow
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      (not s.serverSocket.isConnected())

    # big transfer of 50kb
    let bytesToTransfer = rng[].generateBytes(50000)

    let bytesReceivedFromClient = await transferData(s.clientSocket, s.serverSocket, bytesToTransfer)

    # ultimately all send packets will acked, and outgoing buffer will be empty
    await waitUntil(proc (): bool = s.clientSocket.numPacketsInOutGoingBuffer() == 0)

    let maximumMaxWindow = s.clientSocket.currentMaxWindowSize

    check:
      # we can only assert that window has grown, because specific values depends on
      # particular timings
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
