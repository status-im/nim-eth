#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

{.used.}

import
  unittest2,
  nimcrypto/hash, nimcrypto/keccak, nimcrypto/utils, stew/byteutils,
  ../../eth/keys

from strutils import toLowerAscii

proc compare(x: openArray[byte], y: openArray[byte]): bool =
  result = len(x) == len(y)
  if result:
    for i in 0..(len(x) - 1):
      if x[i] != y[i]:
        result = false
        break

let message = "message".toBytes()
let rng = newRng()

const
  pkbytes = "58d23b55bc9cdce1f18c2500f40ff4ab7245df9a89505e9b1fa4851f623d241d"
  address = "dc544d1aa88ff8bbd2f2aec754b1f1e99e1812fd"

  alice = [
    "9c0257114eb9399a2985f8e75dad7600c5d89fe3824ffa99ec1c3eb8bf3b0501",
    """5eed5fa3a67696c334762bb4823e585e2ee579aba3558d9955296d6c04541b42
       6078dbd48d74af1fd0c72aa1a05147cf17be6b60bdbed6ba19b08ec28445b0ca""",
    """b20e2ea5d3cbaa83c1e0372f110cf12535648613b479b64c1a8c1a20c5021f38
       0434d07ec5795e3f789794351658e80b7faf47a46328f41e019d7b853745cdfd01"""
  ]
  bob = [
    "38e47a7b719dce63662aeaf43440326f551b8a7ee198cee35cb5d517f2d296a2",
    """347746ccb908e583927285fa4bd202f08e2f82f09c920233d89c47c79e48f937
       d049130e3d1c14cf7b21afefc057f71da73dec8e8ff74ff47dc6a574ccd5d570""",
    """5c48ea4f0f2257fa23bd25e6fcb0b75bbe2ff9bbda0167118dab2bb6e31ba76e
       691dbdaf2a231fc9958cd8edd99507121f8184042e075cf10f98ba88abff1f3601"""
  ]
  eve = [
    "876be0999ed9b7fc26f1b270903ef7b0c35291f89407903270fea611c85f515c",
    """c06641f0d04f64dba13eac9e52999f2d10a1ff0ca68975716b6583dee0318d91
       e7c2aed363ed22edeba2215b03f6237184833fd7d4ad65f75c2c1d5ea0abecc0""",
    """babeefc5082d3ca2e0bc80532ab38f9cfb196fb9977401b2f6a98061f15ed603
       603d0af084bf906b2cdf6cdde8b2e1c3e51a41af5e9adec7f3643b3f1aa2aadf00"""
  ]

suite "ECC/ECDSA/ECDHE tests suite":
  test "Known private to known public keys (test data from Ethereum eth-keys)":
    for person in [alice, bob, eve]:
      let privkey = PrivateKey.fromHex(person[0])[]
      var pubkeyHex = $privkey.toPublicKey()
      check:
        pubkeyHex == stripSpaces(person[1])

  test "Recover public key from message":
    for person in [alice, bob, eve]:
      let privkey = PrivateKey.fromHex(person[0])[]
      let signature = privkey.sign(message)
      let recoveredKey = signature.recover(message)[]
      check:
        $privkey.toPublicKey() == $recoveredKey

  test "Signature serialization and deserialization":
    for person in [alice, bob, eve]:
      let privkey = PrivateKey.fromHex(person[0])[]
      let signature = privkey.sign(message)
      let expectSignature = Signature.fromHex(stripSpaces(person[2]))[]
      check:
        $signature == $expectSignature

  test "test_recover_from_signature_obj":
    var s = PrivateKey.fromHex(pkbytes)[]
    var mhash = keccak256.digest(message)
    var signature = s.sign(message)
    var p = recover(signature, SkMessage(mhash.data))[]
    check:
      s.toPublicKey() == p

  test "test_to_address_from_public_key":
    var s = PrivateKey.fromHex(pkbytes)[]
    var chk = s.toPublicKey().toAddress()
    var expect = "0x" & address
    check chk == expect

  test "test_to_canonical_address_from_public_key":
    var s = PrivateKey.fromHex(pkbytes)[]
    var chk = s.toPublicKey().toCanonicalAddress()
    var expect = fromHex(stripSpaces(address))
    check compare(chk, expect) == true

  test "test_to_checksum_address_from_public_key":
    var s = PrivateKey.fromHex(pkbytes)[]
    var chk = s.toPublicKey().toChecksumAddress()
    var expect = "0x" & address
    check:
      chk.toLowerAscii() == expect

  test "EIP-55 checksum addresses test cases":
    var checks = [
      "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
      "0x52908400098527886E0F7030069857D2E4169EE7",
      "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
      "0xde709f2102306220921060314715629080e2fb77",
      "0x27b1fdb04752bbc536007a920d24acb045561c26",
      "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
      "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
      "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
      "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
    ]
    var badchecks = [
      "",
      "0xXB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
      "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d35X",
      "0XfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
      "XXfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
      "0xfB6916095"
    ]
    for item in checks:
      check validateChecksumAddress(item) == true
    for item in badchecks:
      check validateChecksumAddress(item) == false

  test "EIP-55 100 addresses":
    for i in 1..100:
      var kp = KeyPair.random(rng[])
      var chaddress = kp.pubkey.toChecksumAddress()
      var noaddress = kp.pubkey.toAddress()
      if noaddress != chaddress:
        check validateChecksumAddress(noaddress) == false
      check validateChecksumAddress(chaddress) == true

  test "ECDHE/py-evm test_ecies.py#L19":
    # ECDHE test vectors
    # Copied from
    # https://github.com/ethereum/py-evm/blob/master/tests/p2p/test_ecies.py#L19
    const privateKeys = [
      "332143e9629eedff7d142d741f896258f5a1bfab54dab2121d3ec5000093d74b",
      "7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad"
    ]
    const publicKeys = [
      """f0d2b97981bd0d415a843b5dfe8ab77a30300daab3658c578f2340308a2da1a07
         f0821367332598b6aa4e180a41e92f4ebbae3518da847f0b1c0bbfe20bcf4e1""",
      """83ede0f19c3c98649265956a4193677b14c338a22de2086a08d84e4446fe37e4e
         233478259ec90dbeef52f4f6c890f8c38660ec7b61b9d439b8a6d1c323dc025"""
    ]
    const sharedSecrets = [
      "ee1418607c2fcfb57fda40380e885a707f49000a5dda056d828b7d9bd1f29a08",
      "167ccc13ac5e8a26b131c3446030c60fbfac6aa8e31149d0869f93626a4cdf62"
    ]
    for i in 0..1:
      var s = PrivateKey.fromHex(privateKeys[i])[]
      var p = PublicKey.fromHex(stripSpaces(publicKeys[i]))[]
      let expect = fromHex(stripSpaces(sharedSecrets[i]))
      let secret = ecdhRaw(s, p)
      check:
        expect == secret.data

  test "ECDHE/cpp-ethereum crypto.cpp#L394":
    # ECDHE test vectors
    # Copied from https://github.com/ethereum/cpp-ethereum/blob/develop/test/unittests/libdevcrypto/crypto.cpp#L394
    var expectm = """
      8ac7e464348b85d9fdfc0a81f2fdc0bbbb8ee5fb3840de6ed60ad9372e718977"""
    var s = PrivateKey.fromRaw(keccak256.digest("ecdhAgree").data)[]
    var p = s.toPublicKey()
    let expect = fromHex(stripSpaces(expectm))
    let secret = ecdhRaw(s, p)
    check:
      expect == secret.data

  test "ECDHE/cpp-ethereum rlpx.cpp#L425":
    # ECDHE test vectors
    # Copied from https://github.com/ethereum/cpp-ethereum/blob/2409d7ec7d34d5ff5770463b87eb87f758e621fe/test/unittests/libp2p/rlpx.cpp#L425
    var s0 = """
      332143e9629eedff7d142d741f896258f5a1bfab54dab2121d3ec5000093d74b"""
    var p0 = """
      f0d2b97981bd0d415a843b5dfe8ab77a30300daab3658c578f2340308a2da1a0
      7f0821367332598b6aa4e180a41e92f4ebbae3518da847f0b1c0bbfe20bcf4e1"""
    var e0 = """
      ee1418607c2fcfb57fda40380e885a707f49000a5dda056d828b7d9bd1f29a08"""
    var s = PrivateKey.fromHex(stripSpaces(s0))[]
    var p = PublicKey.fromHex(stripSpaces(p0))[]
    let expect = fromHex(stripSpaces(e0))
    let secret = ecdhRaw(s, p)
    check:
      compare(expect, secret.data) == true

  test "ECDSA/cpp-ethereum crypto.cpp#L132":
    # ECDSA test vectors
    # Copied from https://github.com/ethereum/cpp-ethereum/blob/develop/test/unittests/libdevcrypto/crypto.cpp#L132
    var signature = """
      b826808a8c41e00b7c5d71f211f005a84a7b97949d5e765831e1da4e34c9b8295d
      2a622eee50f25af78241c1cb7cfff11bcf2a13fe65dee1e3b86fd79a4e3ed000"""
    var pubkey = """
      e40930c838d6cca526795596e368d16083f0672f4ab61788277abfa23c3740e1cc
      84453b0b24f49086feba0bd978bb4446bae8dff1e79fcc1e9cf482ec2d07c3"""
    var check1 = fromHex(stripSpaces(signature))
    var check2 = fromHex(stripSpaces(pubkey))

    var s = PrivateKey.fromRaw(keccak256.digest("sec").data)[]
    var m = keccak256.digest("msg")
    var sig = sign(s, SkMessage(m.data))
    var sersig = sig.toRaw()
    var key = recover(sig, SkMessage(m.data))[]
    var serkey = key.toRaw()
    check:
      compare(sersig, check1) == true
      compare(serkey, check2) == true

  test "ECDSA/100 signatures":
    # signature test
    for i in 1..100:
      let m = rng[].generate(array[32, byte])
      var s = PrivateKey.random(rng[])
      var key = s.toPublicKey()
      let sig = sign(s, SkMessage(m))
      let rkey = recover(sig, SkMessage(m))[]
      check:
        key == rkey

  test "KEYS/100 create/recovery keys":
    # key create/recovery test
    for i in 1..100:
      var s = PrivateKey.random(rng[])
      var key = s.toPublicKey()
      let rkey = PublicKey.fromRaw(key.toRaw())[]
      check:
        key == rkey

  test "ECDHE/100 shared secrets":
    # ECDHE shared secret test
    for i in 1..100:
      var aliceSecret = PrivateKey.random(rng[])
      var alicePublic = aliceSecret.toPublicKey()
      var bobSecret = PrivateKey.random(rng[])
      var bobPublic = bobSecret.toPublicKey()
      var secret1 = ecdhRaw(aliceSecret, bobPublic)
      var secret2 = ecdhRaw(bobSecret, alicePublic)
      check:
        secret1 == secret2

  test "Compressed public keys":
    let pubkeyCompressed = "03CA634CAE0D49ACB401D8A4C6B6FE8C55B70D115BF400769CC1400F3258CD3138".toLowerAscii
    let s = PublicKey.fromHex(pubkeyCompressed)[]
    check:
      s.toRaw.toHex == """CA634CAE0D49ACB401D8A4C6B6FE8C55B70D115BF400769CC1400F3258
          CD31387574077F301B421BC84DF7266C44E9E6D569FC56BE00812904767BF5CCD1FC7F""".stripSpaces.toLowerAscii

      s.toRawCompressed.toHex == pubkeyCompressed
