import
  std/[net],
  stint, bearssl, metrics,
  ".."/../[rlp, keys],
  "."/[messages, node, enr]

from stew/objects import checkedEnumAssign

type
  DecodeResult*[T] = Result[T, cstring]

proc numFields(T: typedesc): int =
  for k, v in fieldPairs(default(T)): inc result

proc encodeMessage*[T: SomeMessage](p: T, reqId: RequestId): seq[byte] =
  result = newSeqOfCap[byte](64)
  result.add(messageKind(T).ord)

  const sz = numFields(T)
  var writer = initRlpList(sz + 1)
  writer.append(reqId)
  for k, v in fieldPairs(p):
    writer.append(v)
  result.add(writer.finish())

proc decodeMessage*(body: openArray[byte]): DecodeResult[Message] =
  ## Decodes to the specific `Message` type.
  if body.len < 1:
    return err("No message data")

  var kind: MessageKind
  if not checkedEnumAssign(kind, body[0]):
    return err("Invalid message type")

  var message = Message(kind: kind)
  var rlp = rlpFromBytes(body.toOpenArray(1, body.high))
  if rlp.enterList:
    try:
      message.reqId = rlp.read(RequestId)
    except RlpError, ValueError:
      return err("Invalid request-id")

    proc decode[T](rlp: var Rlp, v: var T)
        {.nimcall, raises:[RlpError, ValueError, Defect].} =
      for k, v in v.fieldPairs:
        v = rlp.read(typeof(v))

    try:
      case kind
      of unused: return err("Invalid message type")
      of ping: rlp.decode(message.ping)
      of pong: rlp.decode(message.pong)
      of findNode: rlp.decode(message.findNode)
      of nodes: rlp.decode(message.nodes)
      of talkReq: rlp.decode(message.talkReq)
      of talkResp: rlp.decode(message.talkResp)
      of regTopic, ticket, regConfirmation, topicQuery:
        # We just pass the empty type of this message without attempting to
        # decode, so that the protocol knows what was received.
        # But we ignore the message as per specification as "the content and
        # semantics of this message are not final".
        discard
    except RlpError, ValueError:
      return err("Invalid message encoding")

    ok(message)
  else:
    err("Invalid message encoding: no rlp list")

