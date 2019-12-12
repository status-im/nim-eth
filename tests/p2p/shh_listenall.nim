#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  sequtils, options, strutils, parseopt, chronos,
  eth/[keys, p2p], eth/common/eth_types, eth/p2p/rlpx_protocols/whisper_protocol,
  eth/p2p/[discovery, peer_pool, whispernodes]

  # enode, bootnodes


let port = Port(30303)
let address = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("0.0.0.0"))
var netId: uint
netId = 1
let keypair = newKeyPair()

echo("keypair ", keypair)

var node = newEthereumNode(keypair, address, netId, nil, addAllCapabilities = false)
node.addCapability Whisper

# Add bootnodes
var bootnodes: seq[ENode] = @[]
for nodeId in WhisperNodes:
  var whisperENode: ENode
  discard initENode(nodeId, whisperENode)
  var whisperNode = newNode(whisperENode)
  asyncCheck node.peerPool.connectToNode(whisperNode)

proc handler(msg: ReceivedMessage) =
  echo("*** handler")
  echo msg.decoded.payload.repr

# TODO: listen to all
#discard node.subscribeFilter(newFilter(topics = @[topic]), handler)
discard node.subscribeFilter(newFilter(), handler)

while true:
  poll()

echo "done"
