# nim-eth
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at
#     https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at
#     https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

import
  std/strutils,
  chronos,
  ../../eth/p2p, ../../eth/common/keys, ../../eth/p2p/[discovery, enode]

var nextPort = 30303

proc localAddress*(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port,
                   ip: parseIpAddress("127.0.0.1"))

proc setupTestNode*(
    rng: ref HmacDrbgContext,
    capabilities: varargs[ProtocolInfo, `protocolInfo`]): EthereumNode {.gcsafe.} =
  # Don't create new RNG every time in production code!
  let keys1 = KeyPair.random(rng[])
  var node = newEthereumNode(
    keys1, localAddress(nextPort), NetworkId(1),
    addAllCapabilities = false,
    bindUdpPort = Port(nextPort), bindTcpPort = Port(nextPort),
    rng = rng)
  nextPort.inc
  for capability in capabilities:
    node.addCapability capability

  node

template sourceDir*: string = currentSourcePath.rsplit(DirSep, 1)[0]

proc recvMsgMock*(msg: openArray[byte]): tuple[msgId: uint, msgData: Rlp] =
  var rlp = rlpFromBytes(msg)

  let msgId = rlp.read(uint32)
  return (msgId.uint, rlp)
