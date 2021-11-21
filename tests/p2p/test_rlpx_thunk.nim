{.used.}

import
  std/[json, os],
  unittest2,
  chronos, stew/byteutils,
  ../../eth/p2p, ../../eth/p2p/rlpx_protocols/[whisper_protocol, eth_protocol],
  ./p2p_test_helper

let rng = newRng()

var
  node1 = setupTestNode(rng, eth, Whisper)
  node2 = setupTestNode(rng, eth, Whisper)

node2.startListening()
var peer = waitFor node1.rlpxConnect(newNode(node2.toENode()))

proc testThunk(payload: openArray[byte]) =
  var (msgId, msgData) = recvMsgMock(payload)
  waitFor peer.invokeThunk(msgId.int, msgData)

proc testPayloads(filename: string) =
  let js = json.parseFile(filename)

  suite extractFilename(filename):
    for testname, testdata in js:
      test testname:
        let
          payloadHex = testdata{"payload"}
          error = testdata{"error"}

        if payloadHex.isNil or payloadHex.kind != JString:
          skip()
          return

        let payload = hexToSeqByte(payloadHex.str)

        if error.isNil:
          testThunk(payload)
        else:
          if error.kind != JString:
            skip()
            return

          # TODO: can I convert the error string to an Exception type at runtime?
          expect CatchableError:
            try:
              testThunk(payload)
            except CatchableError as e:
              check: e.name == error.str
              raise e

testPayloads(sourceDir / "test_rlpx_thunk.json")
