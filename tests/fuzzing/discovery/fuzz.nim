import
  chronicles, eth/p2p/[discovery, enode], eth/[keys, rlp],
  ../../p2p/p2p_test_helper, ../fuzz_helpers

const DefaultListeningPort = 30303
var targetNode: DiscoveryProtocol

proc init() =
  # Set up a discovery node, this is the node we target when fuzzing
  var
    targetNodeKey = initPrivateKey("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")
    targetNodeAddr = localAddress(DefaultListeningPort)
  targetNode = newDiscoveryProtocol(targetNodeKey, targetNodeAddr, @[])
  # Create the transport as else replies on the messages send will fail.
  targetNode.open()

proc test(payload: seq[byte]) =
  var
    msg: seq[byte]
    address: Address

  fuzz:
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

proc NimMain() {.importc: "NimMain".}

proc fuzzerInit(): cint {.exportc: "LLVMFuzzerInitialize".} =
  NimMain()

  init()

  return 0

template `+`*[T](p: ptr T, off: int): ptr T =
  cast[ptr type(p[])](cast[ByteAddress](p) +% off * sizeof(p[]))

proc fuzzerCall(data: ptr byte, len: csize): cint {.exportc: "LLVMFuzzerTestOneInput".} =
  if len > 0:
    var input: seq[byte]

    # TODO: something better to get this data in the seq?
    newSeq(input, len)
    for i in 0..<len:
      input[i] = (data + i)[]

    test(input)

  return 0

when defined(afl):
  init()
  test(readStdin())