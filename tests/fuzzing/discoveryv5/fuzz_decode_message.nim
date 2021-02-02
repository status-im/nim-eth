import
  testutils/fuzzing, stew/byteutils,
  eth/rlp, eth/p2p/discoveryv5/[encoding, messages]

test:
  block:
    let decoded = decodeMessage(payload)

    if decoded.isOK():
      let message = decoded.get()
      var encoded: seq[byte]
      case message.kind
      of unused: break
      of ping: encoded = encodeMessage(message.ping, message.reqId)
      of pong: encoded = encodeMessage(message.pong, message.reqId)
      of findNode: encoded = encodeMessage(message.findNode, message.reqId)
      of nodes: encoded = encodeMessage(message.nodes, message.reqId)
      of talkreq: encoded = encodeMessage(message.talkreq, message.reqId)
      of talkresp: encoded = encodeMessage(message.talkresp, message.reqId)
      of regtopic, ticket, regconfirmation, topicquery:
        break

      # This will hit assert because of issue:
      # https://github.com/status-im/nim-eth/issues/255
      # if encoded != payload:
      #   echo "payload: ", toHex(payload)
      #   echo "encoded: ", toHex(encoded)

      #   doAssert(false, "re-encoded result does not equal original payload")
