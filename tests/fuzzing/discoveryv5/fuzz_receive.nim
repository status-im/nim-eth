import
  testutils/fuzzing, bearssl, stew/shims/net,
  eth/[keys, trie/db], eth/p2p/discoveryv5/[protocol, discovery_db],
  ../p2p/discv5_test_helper

var targetNode: protocol.Protocol

init:
  let
    rng = newRng()
    privKey = PrivateKey.random(rng[])
    ip = some(ValidIpAddress.init("127.0.0.1"))
    port = Port(20301)
    dbb = DiscoveryDB.init(newMemoryDB())
  targetNode = newProtocol(privKey, dbb, ip, port, port, rng = rng)
  # Need to open socket else the response part will fail, would be nice if we
  # could skip that part during fuzzing.
  targetNode.open()

test:
  # Some dummy address
  let address = localAddress(20302)
  # This is a quick and easy, high level fuzzing test and considering that the
  # auth-response and the message gets encrypted, and that a handshake needs to
  # be done, it will not be able to reach into testing those depths. However, it
  # should still be of use hitting the more "simple" code paths (random-packet,
  # whoareyou-packet, and the beginnings of other packets).
  targetNode.receive(address, payload)
