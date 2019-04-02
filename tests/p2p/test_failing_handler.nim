#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  unittest, tables, chronos, eth/[keys, p2p], eth/p2p/[discovery, enode]

var nextPort = 30303

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))

proc startDiscoveryNode(privKey: PrivateKey, address: Address,
                        bootnodes: seq[ENode]): Future[DiscoveryProtocol] {.async.} =
  result = newDiscoveryProtocol(privKey, address, bootnodes)
  result.open()
  await result.bootstrap()

proc setupBootNode(): Future[ENode] {.async.} =
  let
    bootNodeKey = newPrivateKey()
    bootNodeAddr = localAddress(30301)
    bootNode = await startDiscoveryNode(bootNodeKey, bootNodeAddr, @[])
  result = initENode(bootNodeKey.getPublicKey, bootNodeAddr)

template asyncTest(name, body: untyped) =
  test name:
    proc scenario {.async.} = body
    waitFor scenario()

type
  network = ref object
    count*: int

p2pProtocol abc(version = 1,
                shortName = "abc",
                networkState = network):

  onPeerConnected do (peer: Peer):
    peer.networkState.count += 1

  onPeerDisconnected do (peer: Peer, reason: DisconnectionReason) {.gcsafe.}:
    peer.networkState.count -= 1
    if true:
      raise newException(UnsupportedProtocol, "Fake abc exception")

p2pProtocol xyz(version = 1,
                shortName = "xyz",
                networkState = network):

  onPeerConnected do (peer: Peer):
    peer.networkState.count += 1

  onPeerDisconnected do (peer: Peer, reason: DisconnectionReason) {.gcsafe.}:
    peer.networkState.count -= 1
    if true:
      raise newException(UnsupportedProtocol, "Fake xyz exception")

proc prepTestNode(): EthereumNode =
  let keys1 = newKeyPair()
  result = newEthereumNode(keys1, localAddress(nextPort), 1, nil,
                           addAllCapabilities = false)
  nextPort.inc
  result.addCapability abc
  result.addCapability xyz

suite "Failing handlers":
  asyncTest "Failing disconnect handler":
    let bootENode = waitFor setupBootNode()
    var node1 = prepTestNode()
    var node2 = prepTestNode()
    # node2 listening and node1 not, to avoid many incoming vs outgoing
    var node1Connected = node1.connectToNetwork(@[bootENode], false, true)
    var node2Connected = node2.connectToNetwork(@[bootENode], true, true)
    waitFor node1Connected
    waitFor node2Connected
    check:
      node1.peerPool.connectedNodes.len() == 1
      node2.peerPool.connectedNodes.len() == 1

    for peer in node1.peers():
      waitFor peer.disconnect(SubprotocolReason, true)
    check:
      # we want to check that even though the exceptions in the disconnect
      # handlers, each handler still ran
      node1.protocolState(abc).count == 0
      node1.protocolState(xyz).count == 0
