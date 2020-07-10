import
  streams, os, strutils, options,
  stew/shims/net,
  eth/keys, eth/p2p/discoveryv5/enr

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
const inputsDir = sourceDir / "corpus"

proc toFile(data: seq[byte], fn: string) =
  var s = newFileStream(fn, fmWrite)
  for x in data:
    s.write(x)
  s.close()

proc generate() =
  let
    rng = newRng()
    privKey = PrivateKey.random(rng[])
    ip = some(ValidIpAddress.init("127.0.0.1"))
    port = Port(20301)

  block:
    let record = enr.Record.init(1, privKey, ip, port, port)[]
    record.raw.toFile(inputsDir / "enr1")
  block:
    let record = enr.Record.init(1, privKey, ip, port, port, [toFieldPair("test", 1'u)])[]
    record.raw.toFile(inputsDir / "enr2")

discard existsOrCreateDir(inputsDir)
generate()
