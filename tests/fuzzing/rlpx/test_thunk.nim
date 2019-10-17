import
  json, os, stew/byteutils, unittest, chronos,
  eth/p2p, eth/p2p/rlpx_protocols/[whisper_protocol, eth_protocol],
  ../p2p/p2p_test_helper

template init(body: untyped) =
  proc fuzzerInit() =
    `body`

template test(body: untyped) =
  proc fuzzerTest(data: openArray[byte]) =
    template payload(): auto =
      data
    `body`

# TODO: make it reuse the code from the fuzzing test. This would mean a bit of
# reworking the exception part for the fuzzing test template.
proc recvMsgMock(msg: openArray[byte]): tuple[msgId: int, msgData: Rlp] =
  var rlp = rlpFromBytes(@msg.toRange)

  let msgid = rlp.read(int)
  return (msgId, rlp)

var
  node1: EthereumNode
  node2: EthereumNode
  peer: Peer

init:
  node1 = setupTestNode(eth, Whisper)
  node2 = setupTestNode(eth, Whisper)

  node2.startListening()
  peer = waitFor node1.rlpxConnect(newNode(initENode(node2.keys.pubKey,
                                                     node2.address)))

test:
  var (msgId, msgData) = recvMsgMock(payload)
  waitFor peer.invokeThunk(msgId.int, msgData)

proc testPayloads(filename: string) =
  let js = json.parseFile(filename)

  fuzzerInit()

  suite filename:

    for testname, testdata in js:
      let
        payloadHex = testdata{"payload"}
        result = testdata{"result"}
        # description = testdata{"description"}

      if payloadHex.isNil or payloadHex.kind != JString:
        continue
      if result.isNil or result.kind != JString:
        continue

      let payload = hexToSeqByte(payloadHex.str)

      # TODO: can I convert the result string to an Exception type at runtime?
      test testname:
        expect CatchableError:
          try:
            fuzzerTest(payload)
          except CatchableError as e:
            debug "Test input created exception", exception=e.name, msg=e.msg
            check: e.name == result.str
            raise

testPayloads(changeFileExt(currentSourcePath, "json"))
