import
  std/strutils,
  chronos, bearssl,
  ../../eth/[keys, p2p], ../../eth/p2p/[discovery, enode]

var nextPort = 30303

proc localAddress*(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port,
                   ip: parseIpAddress("127.0.0.1"))

proc setupTestNode*(
    rng: ref BrHmacDrbgContext,
    capabilities: varargs[ProtocolInfo, `protocolInfo`]): EthereumNode {.gcsafe.} =
  # Don't create new RNG every time in production code!
  let keys1 = KeyPair.random(rng[])
  var node = newEthereumNode(
    keys1, localAddress(nextPort), NetworkId(1), nil,
    addAllCapabilities = false,
    bindUdpPort = Port(nextPort), bindTcpPort = Port(nextPort),
    rng = rng)
  nextPort.inc
  for capability in capabilities:
    node.addCapability capability

  node

template sourceDir*: string = currentSourcePath.rsplit(DirSep, 1)[0]

proc recvMsgMock*(msg: openArray[byte]): tuple[msgId: int, msgData: Rlp] =
  var rlp = rlpFromBytes(msg)

  let msgId = rlp.read(int32)
  return (msgId.int, rlp)
