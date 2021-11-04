# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  sequtils,
  chronos, bearssl,
  testutils/unittests,
  ./test_utils,
  ../../eth/utp/utp_router,
  ../../eth/utp/utp_protocol,
  ../../eth/keys

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

proc transferData(sender: UtpSocket[TransportAddress], receiver: UtpSocket[TransportAddress], data: seq[byte]): Future[seq[byte]] {.async.}=
  let bytesWritten = await sender.write(data)
  doAssert bytesWritten == len(data)
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
    clientSocket: clientSocket,
    serverSocket: serverSocket
  )

proc close(s: ClientServerScenario) {.async.} =
  await s.utp1.closeWait()
  await s.utp2.closeWait()

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
    clientSocket1: clientSocket1,
    clientSocket2: clientSocket2,
    serverSocket1: serverSocket1,
    serverSocket2: serverSocket2
  )

proc close(s: TwoClientsServerScenario) {.async.} =
  await s.utp1.closeWait()
  await s.utp2.closeWait()
  await s.utp3.closeWait()

procSuite "Utp protocol over udp tests":
  let rng = newRng()

  asyncTest "Success connect to remote host":
    let server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address)

    var server2Called = newAsyncEvent()
    let address1 = initTAddress("127.0.0.1", 9080)
    let utpProt2 = UtpProtocol.new(setAcceptedCallback(server2Called), address1)

    let sock = await utpProt1.connectTo(address1)
    
    # this future will be completed when we called accepted connection callback
    await server2Called.wait()
    
    check:
      sock.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      sock.numPacketsInOutGoingBuffer() == 0
      
      server2Called.isSet()

    await utpProt1.closeWait()
    await utpProt2.closeWait()

  asyncTest "Fail to connect to offline remote host":
    let server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address , SocketConfig.init(milliseconds(200)))

    let address1 = initTAddress("127.0.0.1", 9080)

    let fut = utpProt1.connectTo(address1)
    
    yield fut
  
    check:
      fut.failed()
    
    await waitUntil(proc (): bool = utpProt1.openSockets() == 0)
    
    check:
      utpProt1.openSockets() == 0

    await utpProt1.closeWait()

  asyncTest "Success connect to remote host which initialy was offline":
    let server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address, SocketConfig.init(milliseconds(500)))

    let address1 = initTAddress("127.0.0.1", 9080)
    
    let futSock = utpProt1.connectTo(address1)

    # waiting 400 milisecond will trigger at least one re-send
    await sleepAsync(milliseconds(400))

    var server2Called = newAsyncEvent()
    let utpProt2 = UtpProtocol.new(setAcceptedCallback(server2Called), address1)

    # this future will be completed when we called accepted connection callback
    await server2Called.wait()
    
    yield futSock

    check:
      futSock.finished() and (not futsock.failed()) and (not futsock.cancelled())
      server2Called.isSet()

    await utpProt1.closeWait()
    await utpProt2.closeWait()

  asyncTest "Success data transfer when data fits into one packet":
    let s = await initClientServerScenario()
    
    check:
      s.clientSocket.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      s.clientSocket.numPacketsInOutGoingBuffer() == 0

      # Server socket is not in connected state, until first data transfer
      (not s.serverSocket.isConnected())

    let bytesToTransfer = generateByteArray(rng[], 100)

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
    let bytesToTransfer = generateByteArray(rng[], 5000)
    
    let bytesReceivedFromClient = await transferData(s.clientSocket, s.serverSocket, bytesToTransfer)
    let bytesReceivedFromServer = await transferData(s.serverSocket, s.clientSocket, bytesToTransfer)

    # ultimatly all send packets will acked, and outgoing buffer will be empty
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
    let bytesToTransfer = generateByteArray(rng[], 5000)
    
    let written = await s.clientSocket.write(bytesToTransfer)

    check:
      written == len(bytesToTransfer)

    let bytesToTransfer1 = generateByteArray(rng[], 5000)

    let written1 = await s.clientSocket.write(bytesToTransfer1)

    check:
      written1 == len(bytesToTransfer)

    let bytesReceived = await s.serverSocket.read(len(bytesToTransfer) + len(bytesToTransfer1))
    
    # ultimatly all send packets will acked, and outgoing buffer will be empty
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
    let client1Data = generateByteArray(rng[], numBytesToTransfer)
    let client2Data = generateByteArray(rng[], numBytesToTransfer)

    discard s.clientSocket1.write(client1Data)
    discard s.clientSocket2.write(client2Data)
    
    let server1ReadBytes = await s.serverSocket1.read(numBytesToTransfer)
    let server2ReadBytes = await s.serverSocket2.read(numBytesToTransfer)

    check:
      client1Data == server1ReadBytes
      client2Data == server2ReadBytes

    await s.close()
