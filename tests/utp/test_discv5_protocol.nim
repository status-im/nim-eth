# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  chronos, bearssl,
  stew/shims/net, stew/byteutils,
  testutils/unittests,
  ../../eth/p2p/discoveryv5/[enr, node, routing_table],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol,
  ../../eth/utp/utp_router,
  ../../eth/utp/utp_discov5_protocol,
  ../../eth/keys

proc localAddress*(port: int): Address =
  Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(port))

proc initDiscoveryNode*(rng: ref BrHmacDrbgContext,
    privKey: PrivateKey,
    address: Address,
    bootstrapRecords: openarray[Record] = [],
    localEnrFields: openarray[(string, seq[byte])] = [],
    previousRecord = none[enr.Record]()): discv5_protocol.Protocol =
  # set bucketIpLimit to allow bucket split
  let tableIpLimits = TableIpLimits(tableIpLimit: 1000,  bucketIpLimit: 24)

  result = newProtocol(privKey,
    some(address.ip),
    some(address.port), some(address.port),
    bindPort = address.port,
    bootstrapRecords = bootstrapRecords,
    localEnrFields = localEnrFields,
    previousRecord = previousRecord,
    tableIpLimits = tableIpLimits,
    rng = rng)

  result.open()

proc generateByteArray(rng: var BrHmacDrbgContext, length: int): seq[byte] =
  var bytes = newSeq[byte](length)
  brHmacDrbgGenerate(rng, bytes)
  return bytes

procSuite "Utp protocol over discovery v5 tests":
  let rng = newRng()
  let utpProtId = "test-utp".toBytes()

  proc registerIncomingSocketCallback(serverSockets: AsyncQueue): AcceptConnectionCallback[Node] =
    return (
      proc(server: UtpRouter[Node], client: UtpSocket[Node]): Future[void] =
        serverSockets.addLast(client)
    )
  
  # TODO Add more tests to discovery v5 suite, especially those which will differ
  # from standard utp case
  asyncTest "Success connect to remote host":
    let
      queue = newAsyncQueue[UtpSocket[Node]]()
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))

      utp1 = UtpDiscv5Protocol.new(node1, utpProtId, registerIncomingSocketCallback(queue))
      utp2 = UtpDiscv5Protocol.new(node2, utpProtId, registerIncomingSocketCallback(queue))

    # nodes must know about each other
    check:
      node1.addNode(node2.localNode)
      node2.addNode(node1.localNode)

    let clientSocket = await utp1.connectTo(node2.localNode)
  
    check:
      clientSocket.isConnected()

    clientSocket.close()
    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Success write data over packet size to remote host":
    let
      queue = newAsyncQueue[UtpSocket[Node]]()
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))

      utp1 = UtpDiscv5Protocol.new(node1, utpProtId, registerIncomingSocketCallback(queue))
      utp2 = UtpDiscv5Protocol.new(node2, utpProtId, registerIncomingSocketCallback(queue))

    # nodes must know about each other
    check:
      node1.addNode(node2.localNode)
      node2.addNode(node1.localNode)

    let numOfBytes = 5000  
    let clientSocket = await utp1.connectTo(node2.localNode)
    let serverSocket = await queue.get()

    let bytesToTransfer = generateByteArray(rng[], numOfBytes)
    let written = await clientSocket.write(bytesToTransfer)

    let received = await serverSocket.read(numOfBytes)

    check:
      written == numOfBytes
      bytesToTransfer == received
      clientSocket.isConnected()
      serverSocket.isConnected()

    clientSocket.close()
    serverSocket.close()
    await node1.closeWait()
    await node2.closeWait()
