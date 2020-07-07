import
  unittest, chronos, nimcrypto, strutils, bearssl,
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

proc setupTestNode*(
    rng: ref BrHmacDrbgContext,
    capabilities: varargs[ProtocolInfo, `protocolInfo`]): EthereumNode {.gcsafe.} =
  # Don't create new RNG every time in production code!
  let keys1 = KeyPair.random(rng[])
  result = newEthereumNode(keys1, localAddress(nextPort), 1, nil,
                           addAllCapabilities = false, rng = rng)
  nextPort.inc
  for capability in capabilities:
    result.addCapability capability

proc packData*(payload: openArray[byte], pk: PrivateKey): seq[byte] =
  let
    payloadSeq = @payload
    signature = @(pk.sign(payload).toRaw())
    msgHash = keccak256.digest(signature & payloadSeq)
  result = @(msgHash.data) & signature & payloadSeq

template sourceDir*: string = currentSourcePath.rsplit(DirSep, 1)[0]

proc recvMsgMock*(msg: openArray[byte]): tuple[msgId: int, msgData: Rlp] =
  var rlp = rlpFromBytes(msg)

  let msgId = rlp.read(int32)
  return (msgId.int, rlp)
