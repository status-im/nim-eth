#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  unittest, tables, chronos, eth/p2p,
  ./p2p_test_helper

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
      raise newException(CatchableError, "Fake abc exception")

p2pProtocol xyz(version = 1,
                shortName = "xyz",
                networkState = network):

  onPeerConnected do (peer: Peer):
    peer.networkState.count += 1

  onPeerDisconnected do (peer: Peer, reason: DisconnectionReason) {.gcsafe.}:
    peer.networkState.count -= 1
    if true:
      raise newException(CatchableError, "Fake xyz exception")

p2pProtocol hah(version = 1,
                shortName = "hah",
                networkState = network):

  onPeerConnected do (peer: Peer):
    if true:
      raise newException(UselessPeerError, "Fake hah exception")
    peer.networkState.count += 1

  onPeerDisconnected do (peer: Peer, reason: DisconnectionReason) {.gcsafe.}:
    peer.networkState.count -= 1

suite "Testing protocol handlers":
  asyncTest "Failing disconnection handler":
    let bootENode = await setupBootNode()
    var node1 = setupTestNode(abc, xyz)
    var node2 = setupTestNode(abc, xyz)

    node2.startListening()
    let peer = await node1.rlpxConnect(newNode(initENode(node2.keys.pubKey,
                                                         node2.address)))
    check:
      peer.isNil == false

    await peer.disconnect(SubprotocolReason, true)
    check:
      # we want to check that even though the exceptions in the disconnect
      # handlers, each handler still ran
      node1.protocolState(abc).count == 0
      node1.protocolState(xyz).count == 0

  asyncTest "Failing connection handler":
    var node1 = setupTestNode(hah)
    var node2 = setupTestNode(hah)
    node2.startListening()
    let peer = await node1.rlpxConnect(newNode(initENode(node2.keys.pubKey,
                                                         node2.address)))
    check:
      peer.isNil == true
      # To check if the disconnection handler did not run
      node1.protocolState(hah).count == 0
