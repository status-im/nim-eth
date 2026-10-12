import
  std/streams,
  ../../eth/rlp

proc toFile*(data: seq[byte], fn: string) =
  var s = newFileStream(fn, fmWrite)
  for x in data:
    s.write(x)
  s.close()

template checkRoundTrip*(payload: openArray[byte], T: type) =
  ## Decoding must be canonical: whenever `payload` decodes to a `T` without
  ## leftover bytes, encoding that `T` must give back `payload`.
  mixin read, append
  block:
    var
      reader = rlpFromBytes(payload)
      decoded: T
      isDecoded = false
    try:
      decoded = reader.read(T)
      isDecoded = not reader.hasData
    except RlpError:
      discard
    if isDecoded:
      doAssert rlp.encode(decoded) == @payload, "non-canonical " & $T & " decoding"
