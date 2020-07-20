import
    std/streams

proc toFile*(data: seq[byte], fn: string) =
  var s = newFileStream(fn, fmWrite)
  for x in data:
    s.write(x)
  s.close()
