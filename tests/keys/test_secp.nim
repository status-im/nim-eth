import unittest
import eth/keys/secp

# TODO test vectors

const
  msg0 = SkMessage()
  msg1 = SkMessage(data: [
    1'u8, 0, 0, 0, 0, 0, 0, 0,
    1'u8, 0, 0, 0, 0, 0, 0, 0,
    1'u8, 0, 0, 0, 0, 0, 0, 0,
    1'u8, 0, 0, 0, 0, 0, 0, 0,
  ])

suite "secp":
  test "Key ops":
    let
      sk = SkSecretKey.random().expect("should get a key")
      pk = sk.toPublicKey().expect("valid private key gives valid public key")

    check:
      sk.verify()
      SkSecretKey.fromRaw(sk.toRaw())[].toHex() == sk.toHex()
      SkSecretKey.fromHex(sk.toHex())[].toHex() == sk.toHex()
      SkPublicKey.fromRaw(pk.toRaw())[].toHex() == pk.toHex()
      SkPublicKey.fromRaw(pk.toRawCompressed())[].toHex() == pk.toHex()
      SkPublicKey.fromHex(pk.toHex())[].toHex() == pk.toHex()

  test "Invalid secret key ops":
    let
      sk = SkSecretKey()

    check:
      not sk.verify()
      sk.toPublicKey().isErr()
      sign(sk, msg0).isErr()
      signRecoverable(sk, msg0).isErr()
      ecdh(sk, SkPublicKey()).isErr()
      ecdhRaw(sk, SkPublicKey()).isErr()

  test "Signatures":
    let
      sk = SkSecretKey.random()[]
      pk = sk.toPublicKey()[]
      badPk = SkPublicKey()
      sig = sign(sk, msg0)[]
      sig2 = signRecoverable(sk, msg0)[]

    check:
      verify(sig, msg0, pk)
      not verify(sig, msg0, badPk)
      not verify(sig, msg1, pk)
      recover(sig2, msg0)[] == pk
      recover(sig2, msg1)[] != pk

  test "Bad signatures":
    let
      sk = SkSecretKey.random()[]
      pk = sk.toPublicKey()[]
      badPk = SkPublicKey()
      badSig = SkSignature()
      badSig2 = SkRecoverableSignature()

    check:
      not verify(badSig, msg0, pk)
      not verify(badSig, msg0, badPk)
      recover(badSig2, msg0).isErr
