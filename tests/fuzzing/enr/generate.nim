import
  std/[os, strutils, options],
  stew/shims/net,
  ../../../eth/keys, ../../../eth/p2p/discoveryv5/enr,
  ../fuzzing_helpers

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
const inputsDir = sourceDir / "corpus"

proc generate() =
  let
    rng = newRng()
    privKey = PrivateKey.random(rng[])
    ip = some(ValidIpAddress.init("127.0.0.1"))
    port = some(Port(20301))

  block:
    let record = enr.Record.init(1, privKey, ip, port, port)[]
    record.raw.toFile(inputsDir / "enr1")
  block:
    let record = enr.Record.init(1, privKey, ip, port, port, [toFieldPair("test", 1'u)])[]
    record.raw.toFile(inputsDir / "enr2")

discard existsOrCreateDir(inputsDir)
generate()
