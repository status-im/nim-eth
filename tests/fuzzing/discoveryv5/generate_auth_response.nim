import
  std/[os, strutils],
  stew/shims/net,
  eth/[rlp, keys], eth/p2p/discoveryv5/[encoding, enr, types],
  ../fuzzing_helpers

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
const inputsDir = sourceDir / "corpus" & DirSep

proc generate() =
  let
    rng = keys.newRng()
    privKey = PrivateKey.random(rng[])
    pubKey = PrivateKey.random(rng[]).toPublicKey()
  var idNonce: IdNonce
  brHmacDrbgGenerate(rng[], idNonce)

  let
    ephKeys = KeyPair.random(rng[])
    signature = signIDNonce(privKey, idNonce, ephKeys.pubkey.toRaw)
    record = enr.Record.init(1, privKey, none(ValidIpAddress), Port(9000),
      Port(9000))[]
    authResponse =
      AuthResponse(version: 5, signature: signature.toRaw, record: some(record))
    authResponseNoRecord =
      AuthResponse(version: 5, signature: signature.toRaw, record: none(enr.Record))

  rlp.encode(authResponse).toFile(inputsDir & "auth-response")
  rlp.encode(authResponseNoRecord).toFile(inputsDir & "auth-response-no-enr")

discard existsOrCreateDir(inputsDir)
generate()
