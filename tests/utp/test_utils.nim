import
  chronos,
  ./../eth/keys

type AssertionCallback = proc(): bool {.gcsafe, raises: [Defect].}

proc generateByteArray*(rng: var BrHmacDrbgContext, length: int): seq[byte] =
  var bytes = newSeq[byte](length)
  brHmacDrbgGenerate(rng, bytes)
  return bytes

proc waitUntil*(f: AssertionCallback): Future[void] {.async.} =
  while true:
    let res = f()
    if res:
      break
    else:
      await sleepAsync(milliseconds(50))
