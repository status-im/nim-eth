#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  std/[sequtils, strformat, options],
  testutils/unittests, chronicles, chronos,
  ../../eth/[rlp, keys, p2p], ../../eth/p2p/mock_peers

const
  clientId = "nim-eth-p2p/0.0.1"

type
  AbcPeer = ref object
    peerName: string
    lastResponse: string

  XyzPeer = ref object
    messages: int

  AbcNetwork = ref object
    peers: seq[string]

p2pProtocol abc(version = 1,
                peerState = AbcPeer,
                networkState = AbcNetwork,
                timeout = 100):

  onPeerConnected do (peer: Peer):
    await peer.hi "Bob"
    let response = await peer.nextMsg(abc.hi)
    peer.networkState.peers.add response.name

  onPeerDisconnected do (peer: Peer, reason: DisconnectionReason):
    echo "peer disconnected", peer

  requestResponse:
    proc abcReq(p: Peer, n: int) =
      echo "got req ", n
      await response.send(&"response to #{n}")

    proc abcRes(p: Peer, data: string) =
      echo "got response ", data

  proc hi(p: Peer, name: string) =
    echo "got hi from ", name
    p.state.peerName = name
    let query = 123
    echo "sending req #", query
    var r = await p.abcReq(query)
    if r.isSome:
      p.state.lastResponse = r.get.data
    else:
      p.state.lastResponse = "timeout"

p2pProtocol xyz(version = 1,
                peerState = XyzPeer,
                useRequestIds = false,
                timeout = 100):

  proc foo(p: Peer, s: string, a, z: int) =
    p.state.messages += 1
    if p.supports(abc):
      echo p.state(abc).peerName

  proc bar(p: Peer, i: int, s: string)

  requestResponse:
    proc xyzReq(p: Peer, n: int, timeout = 3.seconds) =
      echo "got req ", n

    proc xyzRes(p: Peer, data: string) =
      echo "got response ", data

proc defaultTestingHandshake(_: type abc): abc.hi =
  result.name = "John Doe"

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))

template asyncTest(name, body: untyped) =
  test name:
    proc scenario {.async.} = body
    waitFor scenario()

template sendResponseWithId(peer: Peer, proto, msg: untyped, reqId: int, data: varargs[untyped]): auto =
  msg(ResponseWithId[proto.msg](peer: peer, id: reqId), data)

template sendResponse(peer: Peer, proto, msg: untyped, data: varargs[untyped]): auto =
  msg(Response[proto.msg](peer), data)

asyncTest "network with 3 peers using custom protocols":
  const useCompression = defined(useSnappy)
  let localKeys = KeyPair.random()[]
  let localAddress = localAddress(30303)
  var localNode = newEthereumNode(localKeys, localAddress, 1, nil, useCompression = useCompression)
  localNode.startListening()

  var mock1 = newMockPeer do (m: MockConf):
    m.addHandshake abc.hi(name: "Alice")

    m.expect(abc.abcReq) do (peer: Peer, data: Rlp):
      let reqId = data.readReqId()
      await sendResponseWithId(peer, abc, abcRes, reqId, "mock response")
      await sleepAsync(100)
      let r = await peer.abcReq(1)
      doAssert r.get.data == "response to #1"

    m.expect(abc.abcRes)

  var mock2 = newMockPeer do (m: MockConf):
    m.addCapability xyz
    m.addCapability abc

    m.expect(abc.abcReq) # we'll let this one time out

    m.expect(xyz.xyzReq) do (peer: Peer):
      echo "got xyz req"
      await sendResponse(peer, xyz, xyzRes, "mock peer data")

    when useCompression:
      m.useCompression = useCompression

  discard await mock1.rlpxConnect(localNode)
  let mock2Connection = await localNode.rlpxConnect(mock2)

  let r = await mock2Connection.xyzReq(10)
  check r.get.data == "mock peer data"

  let abcNetState = localNode.protocolState(abc)

  check:
    abcNetState.peers.len == 2
    "Alice" in abcNetState.peers
    "John Doe" in abcNetState.peers
