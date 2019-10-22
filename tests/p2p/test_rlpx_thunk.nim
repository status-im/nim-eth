import
  json, os, stew/byteutils, unittest, chronos,
  eth/p2p, eth/p2p/rlpx_protocols/[whisper_protocol, eth_protocol],
  ../p2p/p2p_test_helper

var
  node1: EthereumNode
  node2: EthereumNode
  peer: Peer


node1 = setupTestNode(eth, Whisper)
node2 = setupTestNode(eth, Whisper)

node2.startListening()
peer = waitFor node1.rlpxConnect(newNode(initENode(node2.keys.pubKey,
                                                   node2.address)))

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
          continue

        let payload = hexToSeqByte(payloadHex.str)

        if error.isNil:
          testThunk(payload)
        else:
          if error.kind != JString:
            skip()
            continue

          # TODO: can I convert the error string to an Exception type at runtime?
          expect CatchableError:
            try:
              testThunk(payload)
            except CatchableError as e:
              check: e.name == error.str
              raise

testPayloads(sourceDir / "test_rlpx_thunk.json")
