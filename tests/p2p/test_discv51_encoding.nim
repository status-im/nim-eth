import
  std/[unittest, options, sequtils, tables],
  stint, stew/byteutils, stew/shims/net,
  eth/[rlp, keys],
  eth/p2p/discoveryv5/[typesv1, encodingv1, enr, node, sessions]

# According to test vectors:
# https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

let rng = newRng()

suite "Discovery v5 Protocol Message Encodings":
  test "Ping Request":
    var p: PingMessage
    p.enrSeq = 1
    var reqId: RequestId = 1
    check encodeMessage(p, reqId).toHex == "01c20101"

  test "Pong Response":
    var p: PongMessage
    p.enrSeq = 1
    p.port = 5000
    p.ip = @[127.byte, 0, 0, 1]
    var reqId: RequestId = 1
    check encodeMessage(p, reqId).toHex == "02ca0101847f000001821388"

  test "FindNode Request":
    var p: FindNodeMessage
    p.distances = @[0x0100'u32]
    var reqId: RequestId = 1
    check encodeMessage(p, reqId).toHex == "03c501c3820100"

  test "Nodes Response (empty)":
    var p: NodesMessage
    p.total = 0x1
    var reqId: RequestId = 1
    check encodeMessage(p, reqId).toHex == "04c30101c0"

  test "Nodes Response (multiple)":
    var p: NodesMessage
    p.total = 0x1
    var e1, e2: Record
    check e1.fromURI("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg")
    check e2.fromURI("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU")

    p.enrs = @[e1, e2]
    var reqId: RequestId = 1
    check encodeMessage(p, reqId).toHex == "04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235"

suite "Discovery v5 Cryptographic Primitives":
  test "ECDH":
    const
      # input
      publicKey = "0x9961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231503061ac4aaee666073d7e5bc2c80c3f5c5b500c1cb5fd0a76abbb6b675ad157"
      secretKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      # expected output
      sharedSecret = "0x033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"

    let
      pub = PublicKey.fromHex(publicKey)[]
      priv = PrivateKey.fromHex(secretKey)[]
    let eph = ecdhRawFull(priv, pub)
    check:
      eph.data == hexToSeqByte(sharedSecret)

  test "Key Derivation":
    # const
    #   # input
    #   secretKey = "0x02a77e3aa0c144ae7c0a3af73692b7d6e5b7a2fdc0eda16e8d5e6cb0d08e88dd04"
    #   nodeIdA = "0xa448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
    #   nodeIdB = "0x885bba8dfeddd49855459df852ad5b63d13a3fae593f3f9fa7e317fd43651409"
    #   idNonce = "0x0101010101010101010101010101010101010101010101010101010101010101"
    #   # expected output
    #   initiatorKey = "0x238d8b50e4363cf603a48c6cc3542967"
    #   recipientKey = "0xbebc0183484f7e7ca2ac32e3d72c8891"
    #   authRespKey = "0xe987ad9e414d5b4f9bfe4ff1e52f2fae"

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
      privKey = PrivateKey.fromHex(localSecretKey)[]
      signature = signIDNonce(privKey, hexToByteArray[idNonceSize](idNonce),
        hexToByteArray[64](ephemeralKey))
    check signature.toRaw() == hexToByteArray[64](idNonceSig)

  test "Encryption/Decryption":
    const
      # input
      encryptionKey = "0x9f2d77db7004bf8a1a85107ac686990b"
      nonce = "0x27b5af763c446acd2749fe8e"
      pt = "0x01c20101"
      ad = "0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903"
      # expected output
      messageCiphertext = "0xa5d12a2d94b8ccb3ba55558229867dc13bfa3648"

    let encrypted = encryptGCM(hexToByteArray[aesKeySize](encryptionKey),
                               hexToByteArray[gcmNonceSize](nonce),
                               hexToSeqByte(pt),
                               hexToByteArray[32](ad))
    check encrypted == hexToSeqByte(messageCiphertext)

  test "Authentication Header and Encrypted Message Generation":
    # Can't work directly with the provided shared secret as keys are derived
    # inside makeAuthHeader, and passed on one call up.
    # The encryption of the auth-resp-pt uses one of these keys, as does the
    # encryption of the message itself. So the whole test depends on this.
    skip()

suite "Discovery v5.1 Test Vectors":
  const
    nodeAKey = "0xeef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
    nodeBKey = "0x66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
  setup:
    let
      privKeyA = PrivateKey.fromHex(nodeAKey)[] # sender -> encode
      privKeyB = PrivateKey.fromHex(nodeBKey)[] # receive -> decode

      enrRecA = enr.Record.init(1, privKeyA,
        some(ValidIpAddress.init("127.0.0.1")), Port(9000),
        Port(9000)).expect("Properly intialized private key")
      nodeA = newNode(enrRecA).expect("Properly initialized record")

      enrRecB = enr.Record.init(1, privKeyB,
        some(ValidIpAddress.init("127.0.0.1")), Port(9000),
        Port(9000)).expect("Properly intialized private key")
      nodeB = newNode(enrRecB).expect("Properly initialized record")

    var
      codecA {.used.} = Codec(localNode: nodeA, privKey: privKeyA,
        sessions: Sessions.init(5))
      codecB = Codec(localNode: nodeB, privKey: privKeyB,
        sessions: Sessions.init(5))

  test "Whoareyou Packet":
    const
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f1000000000000000000000000000000000"
      whoareyouEnrSeq = 0

      encodedPacket = "0x00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3ecb9ad5e368892ec562137bf19c6d0a9191a5651c4f415117bdfa0c7ab86af62b7a9784eceb28008d03ede83bd1369631f9f3d8da0b45"

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOK()
      decoded.get().flag == Flag.Whoareyou
      decoded.get().whoareyou.requestNonce == hexToByteArray[gcmNonceSize](whoareyouRequestNonce)
      decoded.get().whoareyou.idNonce == hexToByteArray[idNonceSize](whoareyouIdNonce)
      decoded.get().whoareyou.recordSeq == whoareyouEnrSeq

  test "Ping Ordinary Message Packet":
    const
      # nonce = "0xffffffffffffffffffffffff"
      readKey = "0x00000000000000000000000000000000"
      pingReqId = 0x00000001'u64
      pingEnrSeq = 2'u64

      encodedPacket = "00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3fcba22b1e9472d43c9ae48d04689eb84102ed931f66d180cbb4219f369a24f4e6b24d7bdc2a04"

    let dummyKey = "0x00000000000000000000000000000001" # of no importance
    codecA.sessions.store(nodeB.id, nodeB.address.get(),
      hexToByteArray[aesKeySize](dummyKey), hexToByteArray[aesKeySize](readKey))
    codecB.sessions.store(nodeA.id, nodeA.address.get(),
      hexToByteArray[aesKeySize](readKey), hexToByteArray[aesKeySize](dummyKey))

    # Note: Noticed when comparing these test vectors that we encode reqId as
    # integer while it seems the test vectors have it encoded as byte seq,
    # meaning having potentially heaving leading zeroes.

    let decoded = codecB.decodePacket(nodeA.address.get(), hexToSeqByte(encodedPacket))
    check:
      decoded.isOK()
      decoded.get().messageOpt.isSome()
      decoded.get().messageOpt.get().reqId == pingReqId
      decoded.get().messageOpt.get().kind == ping
      decoded.get().messageOpt.get().ping.enrSeq == pingEnrSeq

  test "Ping Handshake Message Packet":
    const
      # srcNodeId = "0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
      # destNodeId = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
      # nonce = "0xffffffffffffffffffffffff"
      # readKey = "0x4917330b5aeb51650213f90d5f253c45"

      pingReqId = 0x00000001'u64
      pingEnrSeq = 1'u64
      #
      # handshake inputs:
      #
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f1000000000000000000000000000000000"
      whoareyouEnrSeq = 1'u64
      # ephemeralKey = "0x0288ef00023598499cb6c940146d050d2b1fb914198c327f76aad590bead68b6"
      # ephemeralPubkey = "0x039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5"

      encodedPacket = "00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3dcbded51e9472d43c9ae48d04689ef4d3b340a9cb02d3f5cb5c73f266876372a497ef20dccc83eebcf61f61bc2bb13655118c2dddd4fa7f66210832e7c45c2af87b635121ae132057cce99aa7d2760b31390fea5142053c97feb5fc3f5d0ff3d71008a5b6724bbfc8c97746524e695129d2bd7fccc3d4569a69fd8a783849a117bd23ec5b5d02be0a0c57"

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouEnrSeq)
      pubkey = some(privKeyA.toPublicKey())
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandShakeKey(nodeId: nodeA.id, address: $(nodeA.address.get()))

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    skip()
    # TODO: This test fails at the deriveKeys step. The readkey is not the
    # expected value of above. Hardcoding that values makes decryption work.
    # TBI.

    # check:
    #   decoded.isOk()
    #   decoded.get().message.reqId == pingReqId
    #   decoded.get().message.kind == ping
    #   decoded.get().message.ping.enrSeq == pingEnrSeq
    #   decoded.get().node.isNone()

  test "Ping Handshake Message Packet with ENR":
    const
      # srcNodeId = "0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
      # destNodeId = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
      # nonce = "0xffffffffffffffffffffffff"
      # readKey = "0x4917330b5aeb51650213f90d5f253c45"

      pingReqId = 0x00000001'u64
      pingEnrSeq = 1'u64
      #
      # handshake inputs:
      #
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f1000000000000000000000000000000000"
      whoareyouEnrSeq = 0'u64
      # ephemeralKey = "0x0288ef00023598499cb6c940146d050d2b1fb914198c327f76aad590bead68b6"
      # ephemeralPubkey = "0x039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5"

      encodedPacket = "00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3dcaa0d51e9472d43c9ae48d04689ef4d3d2602a5e89ac340f9e81e722b1d7dac2578d520dd5bc6dc1e38ad3ab33012be1a5d259267a0947bf242219834c5702d1c694c0ceb4a6a27b5d68bd2c2e32e6cb9696706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef52417d9c40a31564e8d5f31a7f08c38045ff5e30d9661838b1eabee9f1e561120bcc4d9f2f9c839152b4ab970e029b2395b97e8c3aa8d3b497ee98a15e865bcd34effa8b83eb6396bca60ad8f0bff1e047e278454bc2b3d6404c12106a9d0b6107fc2383976fc05fbda2c954d402c28c8fb53a2b3a4b111c286ba2ac4ff880168323c6e97b01dbcbeef4f234e5849f75ab007217c919820aaa1c8a7926d3625917fccc3d4569a69fd8aca026be87afab8e8e645d1ee888992"

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouEnrSeq)
      pubkey = none(PublicKey)
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandShakeKey(nodeId: nodeA.id, address: $(nodeA.address.get()))

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    skip()
    # TODO: This test fails at the deriveKeys step. The readkey is not the
    # expected value of above. Hardcoding that values makes decryption work.
    # TBI.

    # check:
    #   decoded.isOk()
    #   decoded.get().message.reqId == pingReqId
    #   decoded.get().message.kind == ping
    #   decoded.get().message.ping.enrSeq == pingEnrSeq
    #   decoded.get().node.isSome()

suite "Discovery v5.1 Additional":
  test "Encryption/Decryption":
    let
      encryptionKey = hexToByteArray[aesKeySize]("0x9f2d77db7004bf8a1a85107ac686990b")
      nonce = hexToByteArray[gcmNonceSize]("0x27b5af763c446acd2749fe8e")
      ad = hexToByteArray[32]("0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
      pt = hexToSeqByte("0xa1")

    let ct = encryptGCM(encryptionKey, nonce, pt, ad)
    let decrypted = decryptGCM(encryptionKey, nonce, ct, ad)

    check decrypted.get() == pt

  test "Decryption":
    let
      encryptionKey = hexToByteArray[aesKeySize]("0x9f2d77db7004bf8a1a85107ac686990b")
      nonce = hexToByteArray[gcmNonceSize]("0x27b5af763c446acd2749fe8e")
      ad = hexToByteArray[32]("0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
      pt = hexToSeqByte("0x01c20101")
      ct = hexToSeqByte("0xa5d12a2d94b8ccb3ba55558229867dc13bfa3648")

    # valid case
    check decryptGCM(encryptionKey, nonce, ct, ad).get() == pt

    # invalid tag/data sizes
    var invalidCipher: seq[byte] = @[]
    check decryptGCM(encryptionKey, nonce, invalidCipher, ad).isNone()

    invalidCipher = repeat(byte(4), gcmTagSize)
    check decryptGCM(encryptionKey, nonce, invalidCipher, ad).isNone()

    # invalid tag/data itself
    invalidCipher = repeat(byte(4), gcmTagSize + 1)
    check decryptGCM(encryptionKey, nonce, invalidCipher, ad).isNone()

  test "Encrypt / Decrypt header":
    let
      privKey = PrivateKey.random(rng[])
      nodeId = privKey.toPublicKey().toNodeId()
      authdata = [byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
      staticHeader = encodeStaticHeader(nodeId, Flag.OrdinaryMessage,
        authdata.len())
      header = @staticHeader & @authdata

    var iv: array[128 div 8, byte]
    brHmacDrbgGenerate(rng[], iv)

    let
      encrypted = encryptHeader(nodeId, iv, header)
      decoded = decodeHeader(nodeId, iv, encrypted)

    check decoded.isOk()

  setup:
    let
      privKeyA = PrivateKey.random(rng[]) # sender -> encode
      privKeyB = PrivateKey.random(rng[]) # receiver -> decode

      enrRecA = enr.Record.init(1, privKeyA, some(ValidIpAddress.init("127.0.0.1")), Port(9000),
        Port(9000)).expect("Properly intialized private key")
      nodeA = newNode(enrRecA).expect("Properly initialized record")

      enrRecB = enr.Record.init(1, privKeyB, some(ValidIpAddress.init("127.0.0.1")), Port(9000),
        Port(9000)).expect("Properly intialized private key")
      nodeB = newNode(enrRecB).expect("Properly initialized record")

    var
      codecA = Codec(localNode: nodeA, privKey: privKeyA, sessions: Sessions.init(5))
      codecB = Codec(localNode: nodeB, privKey: privKeyB, sessions: Sessions.init(5))

  test "Encode / Decode Ordinary Random Message Packet":
    let
      m = PingMessage(enrSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)

    let (data, nonce) = encodeMessagePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message)

    let decoded = codecB.decodePacket(nodeA.address.get(), data)
    check:
      decoded.isOk()
      decoded[].flag == OrdinaryMessage
      decoded[].messageOpt.isNone()
      decoded[].requestNonce == nonce

  test "Encode / Decode Whoareyou Packet":
    var
      requestNonce: AESGCMNonce
      idNonce: IdNonce
    brHmacDrbgGenerate(rng[], idNonce)
    brHmacDrbgGenerate(rng[], requestNonce)
    let recordSeq = 0'u64

    let data = encodeWhoareyouPacket(rng[], codecA, nodeB.id, requestNonce, idNonce,
      recordSeq)

    let decoded = codecB.decodePacket(nodeA.address.get(), data)
    check:
      decoded.isOk()
      decoded[].flag == Flag.Whoareyou
      decoded[].whoareyou.requestNonce == requestNonce
      decoded[].whoareyou.idNonce == idNonce
      decoded[].whoareyou.recordSeq == recordSeq

  test "Encode / Decode Handshake Message Packet":
    var
      requestNonce: AESGCMNonce
      idNonce: IdNonce
    brHmacDrbgGenerate(rng[], idNonce)
    brHmacDrbgGenerate(rng[], requestNonce)
    let recordSeq = 1'u64

    let
      m = PingMessage(enrSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)
    let
      whoareyouData = WhoareyouData(
        requestNonce: requestNonce,
        idNonce: idNonce,
        recordSeq: recordSeq)
      pubkey = some(privKeyA.toPublicKey())
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandShakeKey(nodeId: nodeA.id, address: $(nodeA.address.get()))

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let data = encodeHandshakePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, idNonce, recordSeq, privKeyB.toPublicKey())

    let decoded = codecB.decodePacket(nodeA.address.get(), data)

    check:
      decoded.isOk()
      decoded.get().message.reqId == reqId
      decoded.get().message.kind == ping
      decoded.get().message.ping.enrSeq == 0
      decoded.get().node.isNone()

  test "Encode / Decode Handshake Message Packet with ENR":
    var
      requestNonce: AESGCMNonce
      idNonce: IdNonce
    brHmacDrbgGenerate(rng[], idNonce)
    brHmacDrbgGenerate(rng[], requestNonce)
    let
      recordSeq = 0'u64

      m = PingMessage(enrSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)

      whoareyouData = WhoareyouData(requestNonce: requestNonce,
        idNonce: idNonce, recordSeq: recordSeq)
      pubkey = none(PublicKey)
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandShakeKey(nodeId: nodeA.id, address: $(nodeA.address.get()))

    # Need to manually add the handshake, which would normally be done when
    # sending a whoareyou Packet.
    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let data = encodeHandshakePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, idNonce, recordSeq, privKeyB.toPublicKey())

    let decoded = codecB.decodePacket(nodeA.address.get(), data)

    check:
      decoded.isOk()
      decoded.get().message.reqId == reqId
      decoded.get().message.kind == ping
      decoded.get().message.ping.enrSeq == 0
      decoded.get().node.isSome()
      decoded.get().node.get().record.seqNum == 1

  test "Encode / Decode Ordinary Message Packet":
    let
      m = PingMessage(enrSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)

    # Need to manually add the secrets the normally get negotiated in the
    # handshake packet.
    var secrets: HandshakeSecrets
    codecA.sessions.store(nodeB.id, nodeB.address.get(), secrets.readKey, secrets.writeKey)
    codecB.sessions.store(nodeA.id, nodeA.address.get(), secrets.writeKey, secrets.readKey)

    let (data, nonce) = encodeMessagePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message)

    let decoded = codecB.decodePacket(nodeA.address.get(), data)
    check:
      decoded.isOk()
      decoded.get().flag == OrdinaryMessage
      decoded.get().messageOpt.isSome()
      decoded.get().messageOpt.get().reqId == reqId
      decoded.get().messageOpt.get().kind == ping
      decoded.get().messageOpt.get().ping.enrSeq == 0
      decoded[].requestNonce == nonce
