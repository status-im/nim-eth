import
  std/tables,
  chronos,
  ../../eth/p2p, ../../eth/p2p/peer_pool,
  ../../eth/p2p/rlpx_protocols/bzz_protocol,
  ./p2p_test_helper

# Basic bzz test to test handshake with ethersphere/swarm node
# Fixed enode string for now

var node = setupTestNode(Bzz, Hive)

let nodeId = "enode://10420addaa648ffcf09c4ba9df7ce876f276f77aae015bc9346487780c9c04862dc47cec17c86be10d4fb7d93f2cae3f8e702f94cb6dea5807bfedad218a53df@127.0.0.1:30399"
let enode = ENode.fromString(nodeId)[]
waitFor node.peerPool.connectToNode(newNode(enode))

doAssert node.peerPool.connectedNodes.len() == 1

while true:
  poll()
