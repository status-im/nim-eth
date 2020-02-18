import
  unittest, stew/byteutils, stint,
  eth/[rlp, keys] , eth/p2p/discoveryv5/[types, encoding, enr]

# According to test vectors:
# https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

suite "Discovery v5 Packet Encodings":
  # TODO: These tests are currently not completely representative for the code
  # and thus will not necessarily notice failures. Refactor/restructure code
  # where possible to make this more useful.
  test "Random Packet":
    const
      # input
      tag = "0x0101010101010101010101010101010101010101010101010101010101010101"
      authTag = "0x020202020202020202020202"
      randomData = "0x0404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"
      # expected output
      randomPacketRlp = "0x01010101010101010101010101010101010101010101010101010101010101018c0202020202020202020202020404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"

    var data: seq[byte]
    data.add(hexToByteArray[32](tag))
    data.add(rlp.encode(hexToByteArray[12](authTag)))
    data.add(hexToSeqByte(randomData))

    check data == hexToSeqByte(randomPacketRlp)

  test "WHOAREYOU Packet":
    const
      # input
      magic = "0x0101010101010101010101010101010101010101010101010101010101010101"
      token = "0x020202020202020202020202"
      idNonce = "0x0303030303030303030303030303030303030303030303030303030303030303"
      enrSeq = 0x01'u64
      # expected output
      whoareyouPacketRlp = "0x0101010101010101010101010101010101010101010101010101010101010101ef8c020202020202020202020202a0030303030303030303030303030303030303030303030303030303030303030301"

    let challenge = Whoareyou(authTag: hexToByteArray[12](token),
      idNonce: hexToByteArray[32](idNonce),
      recordSeq: enrSeq)
    var data = hexToSeqByte(magic)
    data.add(rlp.encode(challenge[]))

    check data == hexToSeqByte(whoareyouPacketRlp)

  test "Authenticated Message Packet":
    const
      # input
      tag = "0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903"
      authTag = "0x27b5af763c446acd2749fe8e"
      idNonce = "0xe551b1c44264ab92bc0b3c9b26293e1ba4fed9128f3c3645301e8e119f179c65"
      ephemeralPubkey = "0xb35608c01ee67edff2cffa424b219940a81cf2fb9b66068b1cf96862a17d353e22524fbdcdebc609f85cbd58ebe7a872b01e24a3829b97dd5875e8ffbc4eea81"
      authRespCiphertext = "0x570fbf23885c674867ab00320294a41732891457969a0f14d11c995668858b2ad731aa7836888020e2ccc6e0e5776d0d4bc4439161798565a4159aa8620992fb51dcb275c4f755c8b8030c82918898f1ac387f606852"
      messageCiphertext = "0xa5d12a2d94b8ccb3ba55558229867dc13bfa3648"
      # expected output
      authMessageRlp = "0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903f8cc8c27b5af763c446acd2749fe8ea0e551b1c44264ab92bc0b3c9b26293e1ba4fed9128f3c3645301e8e119f179c658367636db840b35608c01ee67edff2cffa424b219940a81cf2fb9b66068b1cf96862a17d353e22524fbdcdebc609f85cbd58ebe7a872b01e24a3829b97dd5875e8ffbc4eea81b856570fbf23885c674867ab00320294a41732891457969a0f14d11c995668858b2ad731aa7836888020e2ccc6e0e5776d0d4bc4439161798565a4159aa8620992fb51dcb275c4f755c8b8030c82918898f1ac387f606852a5d12a2d94b8ccb3ba55558229867dc13bfa3648"

    let authHeader = AuthHeader(auth: hexToByteArray[12](authTag),
      idNonce: hexToByteArray[32](idNonce),
      scheme: authSchemeName,
      ephemeralKey: hexToByteArray[64](ephemeralPubkey),
      response: hexToSeqByte(authRespCiphertext))

    var data: seq[byte]
    data.add(hexToSeqByte(tag))
    data.add(rlp.encode(authHeader))
    data.add(hexToSeqByte(messageCiphertext))

    check data == hexToSeqByte(authMessageRlp)

  test "Message Packet":
    const
      # input
      tag = "0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903"
      authTag = "0x27b5af763c446acd2749fe8e"
      randomData = "0xa5d12a2d94b8ccb3ba55558229867dc13bfa3648"
      # expected output
      messageRlp = "0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f421079038c27b5af763c446acd2749fe8ea5d12a2d94b8ccb3ba55558229867dc13bfa3648"

    var data: seq[byte]
    data.add(hexToByteArray[32](tag))
    data.add(rlp.encode(hexToByteArray[12](authTag)))
    data.add(hexToSeqByte(randomData))

    check data == hexToSeqByte(messageRlp)

suite "Discovery v5 Protocol Message Encodings":
  test "Ping Request":
    var p: PingPacket
    p.enrSeq = 1
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "01c20101"

  test "Pong Response":
    var p: PongPacket
    p.enrSeq = 1
    p.port = 5000
    p.ip = @[127.byte, 0, 0, 1]
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "02ca0101847f000001821388"

  test "FindNode Request":
    var p: FindNodePacket
    p.distance = 0x0100
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "03c401820100"

  test "Nodes Response (empty)":
    var p: NodesPacket
    p.total = 0x1
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "04c30101c0"

  test "Nodes Response (multiple)":
    var p: NodesPacket
    p.total = 0x1
    var e1, e2: Record
    check e1.fromURI("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg")
    check e2.fromURI("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU")

    p.enrs = @[e1, e2]
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235"

suite "Discovery v5 Cryptographic Primitives":
  test "ECDH":
    const
      # input
      publicKey = "0x9961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231503061ac4aaee666073d7e5bc2c80c3f5c5b500c1cb5fd0a76abbb6b675ad157"
      secretKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      # expected output
      sharedSecret = "0x033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"

    let
      pub = initPublicKey(publicKey)
      priv = initPrivateKey(secretKey)
    var eph: SharedSecretFull

    check:
      ecdhAgree(priv, pub, eph) == EthKeysStatus.Success
      eph.data == hexToSeqByte(sharedSecret)

  test "Key Derivation":
    const
      # input
      secretKey = "0x02a77e3aa0c144ae7c0a3af73692b7d6e5b7a2fdc0eda16e8d5e6cb0d08e88dd04"
      nodeIdA = "0xa448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
      nodeIdB = "0x885bba8dfeddd49855459df852ad5b63d13a3fae593f3f9fa7e317fd43651409"
      idNonce = "0x0101010101010101010101010101010101010101010101010101010101010101"
      # expected output
      initiatorKey = "0x238d8b50e4363cf603a48c6cc3542967"
      recipientKey = "0xbebc0183484f7e7ca2ac32e3d72c8891"
      authRespKey = "0xe987ad9e414d5b4f9bfe4ff1e52f2fae"

    # Code doesn't allow to start from shared `secretKey`, but only from the
    # public and private key. Would require pulling `ecdhAgree` out of
    # `deriveKeys`
    skip()

  test "Nonce Signing":
    const
      # input
      idNonce = "0xa77e3aa0c144ae7c0a3af73692b7d6e5b7a2fdc0eda16e8d5e6cb0d08e88dd04"
      ephemeralKey = "0x9961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231503061ac4aaee666073d7e5bc2c80c3f5c5b500c1cb5fd0a76abbb6b675ad157"
      localSecretKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      # expected output
      idNonceSig = "0xc5036e702a79902ad8aa147dabfe3958b523fd6fa36cc78e2889b912d682d8d35fdea142e141f690736d86f50b39746ba2d2fc510b46f82ee08f08fd55d133a4"

    let
      c = Codec(privKey: initPrivateKey(localSecretKey))
      signature = signIDNonce(c, hexToByteArray[32](idNonce),
        hexToByteArray[64](ephemeralKey))
    check signature.getRaw() == hexToByteArray[64](idNonceSig)

  test "Encryption/Decryption":
    const
      # input
      encryptionKey = "0x9f2d77db7004bf8a1a85107ac686990b"
      nonce = "0x27b5af763c446acd2749fe8e"
      pt = "0x01c20101"
      ad = "0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903"
      # expected output
      messageCiphertext = "0xa5d12a2d94b8ccb3ba55558229867dc13bfa3648"

    let encrypted = encryptGCM(hexToByteArray[16](encryptionKey),
                               hexToByteArray[12](nonce),
                               hexToSeqByte(pt),
                               hexToByteArray[32](ad))
    check encrypted == hexToSeqByte(messageCiphertext)

  test "Authentication Header and Encrypted Message Generation":
    # Can't work directly with the provided shared secret as keys are derived
    # inside makeAuthHeader, and passed on one call up.
    # The encryption of the auth-resp-pt uses one of these keys, as does the
    # encryption of the message itself. So the whole test depends on this.
    skip()
