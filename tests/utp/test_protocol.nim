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
  ../../eth/utp/utp_socket,
  ../../eth/utp/utp_protocol,
  ../../eth/keys
  
proc generateByteArray(rng: var BrHmacDrbgContext, length: int): seq[byte] =
  var bytes = newSeq[byte](length)
  brHmacDrbgGenerate(rng, bytes)
  return bytes

type AssertionCallback = proc(): bool {.gcsafe, raises: [Defect].}

proc waitUntil(f: AssertionCallback): Future[void] {.async.} =
  while true:
    let res = f()
    if res:
      break
    else:
      await sleepAsync(milliseconds(50))

proc transferData(sender: UtpSocket, receiver: UtpSocket, data: seq[byte]): Future[seq[byte]] {.async.}=
  let bytesWritten = await sender.write(data)
  doAssert bytesWritten == len(data)
  let received = await receiver.read(len(data))
  return received

template withClientAndServerSocket(body: untyped): untyped =
  var server1Called = newAsyncEvent()
  let address = initTAddress("127.0.0.1", 9079)
  let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address)

  var serverSocketFut = newFuture[UtpSocket]()
  let address1 = initTAddress("127.0.0.1", 9080)
  let utpProt2 = UtpProtocol.new(setIncomingSocketCallback(serverSocketFut), address1)

  let clientSocket {.inject.} = await utpProt1.connectTo(address1)

  # this future will be completed when we called accepted connection callback
  let serverSocket {.inject.} = await serverSocketFut

  block:
    body

  await utpProt1.closeWait()
  await utpProt2.closeWait()

template with2ClientAndServerSockets(body: untyped): untyped =
  var serverSockets = newAsyncQueue[UtpSocket]()
  var server1Called = newAsyncEvent()
  let address1 = initTAddress("127.0.0.1", 9079)
  let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address1)

  let address2 = initTAddress("127.0.0.1", 9080)
  let utpProt2 = UtpProtocol.new(registerIncomingSocketCallback(serverSockets), address2)

  let address3 = initTAddress("127.0.0.1", 9081)
  let utpProt3 = UtpProtocol.new(registerIncomingSocketCallback(serverSockets), address3)

  let clientSocket1 {.inject.} = await utpProt1.connectTo(address2)
  let clientSocket2 {.inject.} = await utpProt1.connectTo(address3)

  await waitUntil(proc (): bool = len(serverSockets) == 2)

  # this future will be completed when we called accepted connection callback
  let serverSocket1 {.inject.} = serverSockets[0]
  let serverSocket2 {.inject.} = serverSockets[1]

  block:
    body

  await utpProt1.closeWait()
  await utpProt2.closeWait()
  await utpProt3.closeWait()

procSuite "Utp protocol tests":
  let rng = newRng()

  proc setAcceptedCallback(event: AsyncEvent): AcceptConnectionCallback =
    return (
      proc(server: UtpProtocol, client: UtpSocket): Future[void] =
        let fut = newFuture[void]()
        event.fire()
        fut.complete()
        fut
    )

  proc setIncomingSocketCallback(socketPromise: Future[UtpSocket]): AcceptConnectionCallback =
    return (
      proc(server: UtpProtocol, client: UtpSocket): Future[void] =
        let fut = newFuture[void]()
        socketPromise.complete(client)
        fut.complete()
        fut
    )
  
  proc registerIncomingSocketCallback(serverSockets: AsyncQueue): AcceptConnectionCallback =
    return (
      proc(server: UtpProtocol, client: UtpSocket): Future[void] =
        serverSockets.addLast(client)
    )

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
    withClientAndServerSocket():
      check:
        clientSocket.isConnected()
        # after successful connection outgoing buffer should be empty as syn packet
        # should be correctly acked
        clientSocket.numPacketsInOutGoingBuffer() == 0

        # Server socket is not in connected state, until first data transfer
        (not serverSocket.isConnected())

      let bytesToTransfer = generateByteArray(rng[], 100)

      let bytesReceivedFromClient = await transferData(clientSocket, serverSocket, bytesToTransfer)

      check:
        bytesToTransfer == bytesReceivedFromClient
        serverSocket.isConnected()

      let bytesReceivedFromServer = await transferData(serverSocket, clientSocket, bytesToTransfer)

      check:
        bytesToTransfer == bytesReceivedFromServer

  asyncTest "Success data transfer when data need to be sliced into multiple packets":
    withClientAndServerSocket():
      check:
        clientSocket.isConnected()
        # after successful connection outgoing buffer should be empty as syn packet
        # should be correctly acked
        clientSocket.numPacketsInOutGoingBuffer() == 0

        (not serverSocket.isConnected())

      # 5000 bytes is over maximal packet size
      let bytesToTransfer = generateByteArray(rng[], 5000)
      
      let bytesReceivedFromClient = await transferData(clientSocket, serverSocket, bytesToTransfer)
      let bytesReceivedFromServer = await transferData(serverSocket, clientSocket, bytesToTransfer)

      # ultimatly all send packets will acked, and outgoing buffer will be empty
      await waitUntil(proc (): bool = clientSocket.numPacketsInOutGoingBuffer() == 0)
      await waitUntil(proc (): bool = serverSocket.numPacketsInOutGoingBuffer() == 0)

      check:
        serverSocket.isConnected()
        clientSocket.numPacketsInOutGoingBuffer() == 0
        serverSocket.numPacketsInOutGoingBuffer() == 0
        bytesReceivedFromClient == bytesToTransfer
        bytesReceivedFromServer == bytesToTransfer

  asyncTest "Success multiple data transfers when data need to be sliced into multiple packets":
    withClientAndServerSocket():
      check:
        clientSocket.isConnected()
        # after successful connection outgoing buffer should be empty as syn packet
        # should be correctly acked
        clientSocket.numPacketsInOutGoingBuffer() == 0


      # 5000 bytes is over maximal packet size
      let bytesToTransfer = generateByteArray(rng[], 5000)
      
      let written = await clientSocket.write(bytesToTransfer)

      check:
        written == len(bytesToTransfer)

      let bytesToTransfer1 = generateByteArray(rng[], 5000)

      let written1 = await clientSocket.write(bytesToTransfer1)

      check:
        written1 == len(bytesToTransfer)

      let bytesReceived = await serverSocket.read(len(bytesToTransfer) + len(bytesToTransfer1))
      
      # ultimatly all send packets will acked, and outgoing buffer will be empty
      await waitUntil(proc (): bool = clientSocket.numPacketsInOutGoingBuffer() == 0)

      check:
        clientSocket.numPacketsInOutGoingBuffer() == 0
        bytesToTransfer.concat(bytesToTransfer1) == bytesReceived

  asyncTest "Success data transfers from multiple clients":
    with2ClientAndServerSockets():
      check:
        clientSocket1.isConnected()
        clientSocket2.isConnected()
        clientSocket1.numPacketsInOutGoingBuffer() == 0
        clientSocket2.numPacketsInOutGoingBuffer() == 0
      
      let numBytesToTransfer = 5000
      let client1Data = generateByteArray(rng[], numBytesToTransfer)
      let client2Data = generateByteArray(rng[], numBytesToTransfer)

      discard clientSocket1.write(client1Data)
      discard clientSocket2.write(client2Data)
      
      let server1ReadBytes = await serverSocket1.read(numBytesToTransfer)
      let server2ReadBytes = await serverSocket2.read(numBytesToTransfer)

      check:
        client1Data == server1ReadBytes
        client2Data == server2ReadBytes
