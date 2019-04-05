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

suite "Testing protocol handlers":
  asyncTest "Failing disconnect handler":
    let bootENode = waitFor setupBootNode()
    var node1 = setupTestNode(abc, xyz)
    var node2 = setupTestNode(abc, xyz)
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
