import
  chronicles, eth/p2p/[discovery, enode], eth/[keys, rlp],
  ../../p2p/p2p_test_helper, ../fuzztest

const DefaultListeningPort = 30303
var targetNode: DiscoveryProtocol

init:
  # Set up a discovery node, this is the node we target when fuzzing
  var
    targetNodeKey = PrivateKey.fromRaw("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
    targetNodeAddr = localAddress(DefaultListeningPort)
  targetNode = newDiscoveryProtocol(targetNodeKey, targetNodeAddr, @[])
  # Create the transport as else replies on the messages send will fail.
  targetNode.open()

test:
  var
    msg: seq[byte]
    address: Address

  # Sending raw payload is possible but won't find us much. We need a hash and
  # a signature, and without it there is a big chance it will always result in
  # "Wrong msg mac from" error.
  let nodeKey = PrivateKey.fromRaw("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618")[]
  msg = packData(payload, nodeKey)
  address = localAddress(DefaultListeningPort + 1)

  try:
    targetNode.receive(address, msg)
  # These errors are also catched in `processClient` in discovery.nim
  # TODO: move them a layer down in discovery so we can do a cleaner test there?
  except RlpError, DiscProtocolError as e:
    debug "Receive failed", err = e.msg