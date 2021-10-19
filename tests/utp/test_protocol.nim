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

  asyncTest "Success data transfer when data fits into one packet":
    var server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address)

    var serverSocketFut = newFuture[UtpSocket]()
    let address1 = initTAddress("127.0.0.1", 9080)
    let utpProt2 = UtpProtocol.new(setIncomingSocketCallback(serverSocketFut), address1)

    let clientSocket = await utpProt1.connectTo(address1)

    # this future will be completed when we called accepted connection callback
    discard await serverSocketFut

    let serverSocket = 
      try:
        serverSocketFut.read()
      except:
        raiseAssert "Unexpected error when reading finished future"

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

    await utpProt1.closeWait()
    await utpProt2.closeWait()

  asyncTest "Success data transfer when data need to be sliced into multiple packets":
    var server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address)

    var serverSocketFut = newFuture[UtpSocket]()
    let address1 = initTAddress("127.0.0.1", 9080)
    let utpProt2 = UtpProtocol.new(setIncomingSocketCallback(serverSocketFut), address1)

    let clientSocket = await utpProt1.connectTo(address1)

    # this future will be completed when we called accepted connection callback
    discard await serverSocketFut

    let serverSocket = 
      try:
        serverSocketFut.read()
      except:
        raiseAssert "Unexpected error when reading finished future"

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

    await utpProt1.closeWait()
    await utpProt2.closeWait()

  asyncTest "Success multiple data transfers when data need to be sliced into multiple packets":
    var server1Called = newAsyncEvent()
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(setAcceptedCallback(server1Called), address)

    var serverSocketFut = newFuture[UtpSocket]()
    let address1 = initTAddress("127.0.0.1", 9080)
    let utpProt2 = UtpProtocol.new(setIncomingSocketCallback(serverSocketFut), address1)

    let clientSocket = await utpProt1.connectTo(address1)

    # this future will be completed when we called accepted connection callback
    discard await serverSocketFut

    let serverSocket = 
      try:
        serverSocketFut.read()
      except:
        raiseAssert "Unexpected error when reading finished future"

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
    
    await utpProt1.closeWait()
    await utpProt2.closeWait()
