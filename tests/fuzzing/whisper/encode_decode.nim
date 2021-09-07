import
  std/[options, sequtils],
  chronicles, testutils/fuzzing,
  ../../../eth/p2p/rlpx_protocols/whisper_protocol as whisper,
  ../../../eth/keys

test:
  let
    rng = newRng()
    data = @payload.distribute(2)
    whisperPayload = Payload(payload: data[0], padding: some(data[1]))
    encoded = whisper.encode(rng[], whisperPayload)

    decoded = whisper.decode(encoded.get())

  doAssert data[0] == decoded.get().payload
  if data[1].len > 0:
    doAssert data[1] == decoded.get().padding.get()
  else:
    doAssert decoded.get().padding.isNone()
