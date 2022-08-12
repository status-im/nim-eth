# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/options,
  chronos,
  stew/shims/net, stew/byteutils,
  testutils/unittests,
  ../../eth/p2p/discoveryv5/[enr, node, routing_table],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol,
  ../../eth/utp/utp_discv5_protocol,
  ../../eth/keys,
  ../../eth/utp/utp_router as rt,
  ../p2p/discv5_test_helper

procSuite "Utp protocol over discovery v5 tests":
  let rng = newRng()
  let utpProtId = "test-utp".toBytes()

  proc registerIncomingSocketCallback(serverSockets: AsyncQueue): AcceptConnectionCallback[NodeAddress] =
    return (
      proc(server: UtpRouter[NodeAddress], client: UtpSocket[NodeAddress]): Future[void] =
        serverSockets.addLast(client)
    )

  proc allowOneIdCallback(allowedId: uint16): AllowConnectionCallback[NodeAddress] =
    return (
      proc(r: UtpRouter[NodeAddress], remoteAddress: NodeAddress, connectionId: uint16): bool =
        connectionId == allowedId
    )

  # TODO Add more tests to discovery v5 suite, especially those which will differ
  # from standard utp case
  asyncTest "Success connect to remote host":
    let
      queue = newAsyncQueue[UtpSocket[NodeAddress]]()
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))

      utp1 = UtpDiscv5Protocol.new(node1, utpProtId, registerIncomingSocketCallback(queue))
      utp2 = UtpDiscv5Protocol.new(node2, utpProtId, registerIncomingSocketCallback(queue))

    # nodes must have session between each other
    check:
      (await node1.ping(node2.localNode)).isOk()

    let clientSocketResult = await utp1.connectTo(NodeAddress.init(node2.localNode).unsafeGet())
    let clientSocket = clientSocketResult.get()
    let serverSocket = await queue.get()

    check:
      clientSocket.isConnected()
      # in this test we do not configure the socket to be connected just after
      # accepting incoming connection
      not serverSocket.isConnected()

    await clientSocket.destroyWait()
    await serverSocket.destroyWait()
    await node1.closeWait()
    await node2.closeWait()

  proc cbUserData(server: UtpRouter[NodeAddress], client: UtpSocket[NodeAddress]): Future[void] =
    let queue = rt.getUserData[NodeAddress, AsyncQueue[UtpSocket[NodeAddress]]](server)
    queue.addLast(client)

  asyncTest "Provide user data pointer and use it in callback":
    let
      queue = newAsyncQueue[UtpSocket[NodeAddress]]()
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))

      # constructor which uses connection callback and user data pointer as ref
      utp1 = UtpDiscv5Protocol.new(node1, utpProtId, cbUserData, queue)
      utp2 = UtpDiscv5Protocol.new(node2, utpProtId, cbUserData, queue)

    # nodes must have session between each other
    check:
      (await node1.ping(node2.localNode)).isOk()

    let clientSocketResult = await utp1.connectTo(NodeAddress.init(node2.localNode).unsafeGet())
    let clientSocket = clientSocketResult.get()
    let serverSocket = await queue.get()

    check:
      clientSocket.isConnected()
      # in this test we do not configure the socket to be connected just after
      # accepting incoming connection
      not serverSocket.isConnected()

    await clientSocket.destroyWait()
    await serverSocket.destroyWait()
    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Success write data over packet size to remote host":
    let
      queue = newAsyncQueue[UtpSocket[NodeAddress]]()
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))

      utp1 = UtpDiscv5Protocol.new(node1, utpProtId, registerIncomingSocketCallback(queue))
      utp2 = UtpDiscv5Protocol.new(node2, utpProtId, registerIncomingSocketCallback(queue))

    # nodes must have session between each other
    check:
      (await node1.ping(node2.localNode)).isOk()

    let numOfBytes = 5000
    let clientSocketResult = await utp1.connectTo(NodeAddress.init(node2.localNode).unsafeGet())
    let clientSocket = clientSocketResult.get()

    let serverSocket = await queue.get()

    let bytesToTransfer = rng[].generateBytes(numOfBytes)
    let written = await clientSocket.write(bytesToTransfer)

    let received = await serverSocket.read(numOfBytes)

    check:
      written.get() == numOfBytes
      bytesToTransfer == received
      clientSocket.isConnected()
      serverSocket.isConnected()

    await clientSocket.destroyWait()
    await serverSocket.destroyWait()
    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Accept connection only from allowed peers":
    let
      allowedId: uint16 = 10
      lowSynTimeout = milliseconds(500)
      queue = newAsyncQueue[UtpSocket[NodeAddress]]()
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))

      utp1 = UtpDiscv5Protocol.new(
        node1,
        utpProtId,
        registerIncomingSocketCallback(queue),
        socketConfig = SocketConfig.init(lowSynTimeout))
      utp2 =
        UtpDiscv5Protocol.new(
          node2,
          utpProtId,
          registerIncomingSocketCallback(queue),
          nil,
          allowOneIdCallback(allowedId),
          SocketConfig.init())

    # nodes must have session between each other
    check:
      (await node1.ping(node2.localNode)).isOk()

    let clientSocketResult1 = await utp1.connectTo(NodeAddress.init(node2.localNode).unsafeGet(), allowedId)
    let clientSocketResult2 = await utp1.connectTo(NodeAddress.init(node2.localNode).unsafeGet(), allowedId + 1)

    check:
      clientSocketResult1.isOk()
      clientSocketResult2.isErr()

    let clientSocket = clientSocketResult1.get()
    let serverSocket = await queue.get()

    check:
      clientSocket.connectionId() == allowedId
      serverSocket.connectionId() == allowedId

    await clientSocket.destroyWait()
    await serverSocket.destroyWait()
    await node1.closeWait()
    await node2.closeWait()

  asyncTest "Configure incoming connections to be in connected state":
    let
      queue = newAsyncQueue[UtpSocket[NodeAddress]]()
      node1 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20302))
      node2 = initDiscoveryNode(
        rng, PrivateKey.random(rng[]), localAddress(20303))

      utp1 = UtpDiscv5Protocol.new(node1, utpProtId, registerIncomingSocketCallback(queue))
      utp2 = UtpDiscv5Protocol.new(
        node2,
        utpProtId,
        registerIncomingSocketCallback(queue),
        socketConfig = SocketConfig.init(incomingSocketReceiveTimeout = none[Duration]())
      )

    # nodes must have session between each other
    check:
      (await node1.ping(node2.localNode)).isOk()

    let clientSocketResult = await utp1.connectTo(NodeAddress.init(node2.localNode).unsafeGet())
    let clientSocket = clientSocketResult.get()
    let serverSocket = await queue.get()

    check:
      clientSocket.isConnected()
      serverSocket.isConnected()

    let serverData = @[1'u8]

    let wResult = await serverSocket.write(serverData)

    check:
      wResult.isOk()

    let readData = await clientSocket.read(len(serverData))

    check:
      readData == serverData

    await clientSocket.destroyWait()
    await serverSocket.destroyWait()
    await node1.closeWait()
    await node2.closeWait()
