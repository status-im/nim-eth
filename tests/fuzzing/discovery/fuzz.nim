import
  streams, posix, sequtils, strutils, chronicles, chronos, byteutils,
  eth/p2p/[discovery, kademlia, enode], eth/[keys, rlp],
  ../../p2p/p2p_test_helper

template fuzz(body) =
  # For code we want to fuzz.
  try:
    body
  except:
    let e = getCurrentException()
    debug "Fuzzer input created exception", exception=e.name, trace=e.repr
    discard kill(getpid(), SIGSEGV)

template noFuzz(body) =
  # For code not in the scope of the test.
  # Lets not have false negatives due to possible issues in this code.
  try:
    body
  except:
    let e = getCurrentException()
    debug "Exception out of scope of the fuzzing target",
      exception=e.name, trace=e.repr
    return

const DefaultListeningPort = 30303

proc fuzzTest() =
  var
    msg: seq[byte]
    address: Address
    targetNode: DiscoveryProtocol

  noFuzz:
    # Set up a discovery node, this is the node we target with fuzzing
    let
      targetNodeKey = initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")
      targetNodeAddr = localAddress(DefaultListeningPort)
    targetNode = newDiscoveryProtocol(targetNodeKey, targetNodeAddr, @[])
    # Create the transport as else replies on the messages send will fail.
    targetNode.open()

    # Read input from stdin (fastest for AFL)
    let s = newFileStream(stdin)
    # We use binary files as with hex we can get lots of "not hex" failures
    var input = s.readAll()
    s.close()
    # Remove newline if it is there
    input.removeSuffix
    # TODO: is there a better/faster way?
    let payload = input.mapIt(it.byte)

    # Sending raw payload is possible but won't find us much. We need a hash and
    # a signature, and without it there is a big chance it will always result in
    # "Wrong msg mac from" error.
    let nodeKey = initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618")
    msg = packData(payload, nodeKey)
    address = localAddress(DefaultListeningPort + 1)

  try:
    targetNode.receive(address, msg)
  # These errors are also catched in `processClient` in discovery.nim
  # TODO: move them a layer down in discovery so we can do a cleaner test there?
  except RlpError, DiscProtocolError:
    debug "Receive failed", err = getCurrentExceptionMsg()

fuzz:
  fuzzTest()
