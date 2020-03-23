import
  unittest, chronos, nimcrypto, strutils,
  eth/[keys, p2p], eth/p2p/[discovery, enode]

var nextPort = 30303

proc localAddress*(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port,
                   ip: parseIpAddress("127.0.0.1"))

proc startDiscoveryNode*(privKey: PrivateKey, address: Address,
                        bootnodes: seq[ENode]): Future[DiscoveryProtocol] {.async.} =
  result = newDiscoveryProtocol(privKey, address, bootnodes)
  result.open()
  await result.bootstrap()

proc setupBootNode*(): Future[ENode] {.async.} =
  let
    bootNodeKey = newPrivateKey()
    bootNodeAddr = localAddress(30301)
    bootNode = await startDiscoveryNode(bootNodeKey, bootNodeAddr, @[])
  result = initENode(bootNodeKey.getPublicKey, bootNodeAddr)

proc setupTestNode*(capabilities: varargs[ProtocolInfo, `protocolInfo`]): EthereumNode =
  let keys1 = newKeyPair()
  result = newEthereumNode(keys1, localAddress(nextPort), 1, nil,
                           addAllCapabilities = false)
  nextPort.inc
  for capability in capabilities:
    result.addCapability capability

template asyncTest*(name, body: untyped) =
  test name:
    proc scenario {.async.} = body
    waitFor scenario()

template procSuite*(name, body: untyped) =
  proc suitePayload =
    suite name:
      body

  suitePayload()

proc packData*(payload: openArray[byte], pk: PrivateKey): seq[byte] =
  let
    payloadSeq = @payload
    signature = @(pk.signMessage(payload).getRaw())
    msgHash = keccak256.digest(signature & payloadSeq)
  result = @(msgHash.data) & signature & payloadSeq

template sourceDir*: string = currentSourcePath.rsplit(DirSep, 1)[0]

proc recvMsgMock*(msg: openArray[byte]): tuple[msgId: int, msgData: Rlp] =
  var rlp = rlpFromBytes(@msg.toRange)

  let msgId = rlp.read(int32)
  return (msgId.int, rlp)
