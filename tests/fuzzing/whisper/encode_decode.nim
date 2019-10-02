import
  options, sequtils, chronicles,
  eth/p2p/rlpx_protocols/whisper_protocol as whisper,
  ../fuzztest

test:
  let
    data = @payload.distribute(2)
    whisperPayload = Payload(payload: data[0], padding: some(data[1]))
    encoded = whisper.encode(whisperPayload)

    decoded = whisper.decode(encoded.get())

  doAssert data[0] == decoded.get().payload
  if data[1].len > 0:
    doAssert data[1] == decoded.get().padding.get()
  else:
    doAssert decoded.get().padding.isNone()
