{.used.}

import
  unittest2,
  stew/byteutils,
  ../../eth/rlp

type
  HelloObj = object
    version*: uint
    clientId*: string
    capabilities*: seq[(string,uint)]
    listenPort*: uint
    nodeId*: array[64, byte]

const
  # Some hello message seen on rlpx
  a = "f84c0580c6c5836574684280b840"
  b = "8ee5fa75daaf0b96a01162f4e1d23daaa676246ccfa3b4787b09915bae9d66173827704c5b80c235ca32265ff04c36d19a2331173e8ff73880dd200648979bb4"

  hello = HelloObj(
    version: 5,
    clientId: "",
    capabilities: @[("eth", 66)],
    listenPort: 0,
    nodeId: hexToByteArray[64](b))

proc suite() =
  suite "Pathological zero string decoding":
    test "decode rlpx hello message":
      # Unless fixed, this check crashes with an `IndexDefect` in the
      # function `rlp.toString()`
      check (a & b).hexToSeqByte.decode(HelloObj) == hello

suite()
