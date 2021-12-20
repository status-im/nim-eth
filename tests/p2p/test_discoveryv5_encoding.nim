{.used.}

import
  std/[options, sequtils, tables],
  unittest2,
  stint, stew/byteutils, stew/shims/net,
  ../../eth/keys,
  ../../eth/p2p/discoveryv5/[messages, encoding, enr, node, sessions]

let rng = newRng()

suite "Discovery v5.1 Protocol Message Encodings":
  test "Ping Request":
    let
      enrSeq = 1'u64
      p = PingMessage(enrSeq: enrSeq)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(p, reqId)
    check encoded.toHex == "01c20101"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == ping
      message.ping.enrSeq == enrSeq

  test "Pong Response":
    let
      enrSeq = 1'u64
      ip = IpAddress(family: IPv4, address_v4: [127.byte, 0, 0, 1])
      port = 5000'u16
      p = PongMessage(enrSeq: enrSeq, ip: ip, port: port)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(p, reqId)
    check encoded.toHex == "02ca0101847f000001821388"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == pong
      message.pong.enrSeq == enrSeq
      message.pong.ip == ip
      message.pong.port == port

  test "FindNode Request":
    let
      distances = @[0x0100'u16]
      fn = FindNodeMessage(distances: distances)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(fn, reqId)
    check encoded.toHex == "03c501c3820100"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == findnode
      message.findnode.distances == distances

  test "Nodes Response (empty)":
    let
      total = 0x1'u32
      n = NodesMessage(total: total)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(n, reqId)
    check encoded.toHex == "04c30101c0"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == nodes
      message.nodes.total == total
      message.nodes.enrs.len() == 0

  test "Nodes Response (multiple)":
    var e1, e2: Record
    check e1.fromURI("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg")
    check e2.fromURI("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU")
    let
      total = 0x1'u32
      n = NodesMessage(total: total, enrs: @[e1, e2])
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(n, reqId)
    check encoded.toHex == "04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == nodes
      message.nodes.total == total
      message.nodes.enrs.len() == 2
      message.nodes.enrs[0] == e1
      message.nodes.enrs[1] == e2

  test "Talk Request":
    let
      tr = TalkReqMessage(protocol: "echo".toBytes(), request: "hi".toBytes())
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(tr, reqId)
    check encoded.toHex == "05c901846563686f826869"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == talkreq
      message.talkreq.protocol == "echo".toBytes()
      message.talkreq.request == "hi".toBytes()

  test "Talk Response":
    let
      tr = TalkRespMessage(response: "hi".toBytes())
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(tr, reqId)
    check encoded.toHex == "06c401826869"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == talkresp
      message.talkresp.response == "hi".toBytes()

  test "Ping with too large RequestId":
    let
      enrSeq = 1'u64
      p = PingMessage(enrSeq: enrSeq)
      # 1 byte too large
      reqId = RequestId(id: @[0.byte, 1, 2, 3, 4, 5, 6, 7, 8])
    let encoded = encodeMessage(p, reqId)
    check encoded.toHex == "01cb8900010203040506070801"

    let decoded = decodeMessage(encoded)
    check decoded.isErr()

  test "Pong with invalid IP address size":
    # pong message with ip field of 5 bytes
    let encodedPong = "02cb0101857f00000102821388"

    let decoded = decodeMessage(hexToSeqByte(encodedPong))
    check decoded.isErr()

# According to test vectors:
# https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md#cryptographic-primitives
suite "Discovery v5.1 Cryptographic Primitives Test Vectors":
  test "ECDH":
    const
      # input
      publicKey = "0x039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"
      secretKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      # expected output
      sharedSecret = "0x033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"

    let
      pub = PublicKey.fromHex(publicKey)[]
      priv = PrivateKey.fromHex(secretKey)[]
      eph = ecdhRawFull(priv, pub)
    check:
      eph.data == hexToSeqByte(sharedSecret)

  test "Key Derivation":
    const
      # input
      ephemeralKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      destPubkey = "0x0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
      nodeIdA = "0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
      nodeIdB = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
      challengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      # expected output
      initiatorKey = "0xdccc82d81bd610f4f76d3ebe97a40571"
      recipientKey = "0xac74bb8773749920b0d3a8881c173ec5"

    let secrets = deriveKeys(
      NodeId.fromHex(nodeIdA),
      NodeId.fromHex(nodeIdB),
      PrivateKey.fromHex(ephemeralKey)[],
      PublicKey.fromHex(destPubkey)[],
      hexToSeqByte(challengeData))

    check:
      secrets.initiatorKey == hexToByteArray[aesKeySize](initiatorKey)
      secrets.recipientKey == hexToByteArray[aesKeySize](recipientKey)

  test "Nonce Signing":
    const
      # input
      staticKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      challengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      ephemeralPubkey = "0x039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"
      nodeIdB = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
      # expected output
      idSignature = "0x94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6"

    let
      privKey = PrivateKey.fromHex(staticKey)[]
      signature = createIdSignature(
        privKey,
        hexToSeqByte(challengeData),
        hexToSeqByte(ephemeralPubkey),
        NodeId.fromHex(nodeIdB))
    check:
      signature.toRaw() == hexToByteArray[64](idSignature)
      verifyIdSignature(signature, hexToSeqByte(challengeData),
        hexToSeqByte(ephemeralPubkey), NodeId.fromHex(nodeIdB),
        privKey.toPublicKey())

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

# According to test vectors:
# https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md#packet-encodings
suite "Discovery v5.1 Packet Encodings Test Vectors":
  const
    nodeAKey = "0xeef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
    nodeBKey = "0x66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
  setup:
    let
      privKeyA = PrivateKey.fromHex(nodeAKey)[] # sender -> encode
      privKeyB = PrivateKey.fromHex(nodeBKey)[] # receive -> decode

      enrRecA = enr.Record.init(1, privKeyA,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")
      nodeA = newNode(enrRecA).expect("Properly initialized record")

      enrRecB = enr.Record.init(1, privKeyB,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")
      nodeB = newNode(enrRecB).expect("Properly initialized record")

    var
      codecA {.used.} = Codec(localNode: nodeA, privKey: privKeyA,
        sessions: Sessions.init(5))
      codecB = Codec(localNode: nodeB, privKey: privKeyB,
        sessions: Sessions.init(5))

  test "Ping Ordinary Message Packet":
    const
      readKey = "0x00000000000000000000000000000000"
      pingReqId = "0x00000001"
      pingEnrSeq = 2'u64

      encodedPacket =
        "00000000000000000000000000000000088b3d4342774649325f313964a39e55" &
        "ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" &
        "4c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc"

    let dummyKey = "0x00000000000000000000000000000001" # of no importance
    codecA.sessions.store(nodeB.id, nodeB.address.get(),
      hexToByteArray[aesKeySize](dummyKey), hexToByteArray[aesKeySize](readKey))
    codecB.sessions.store(nodeA.id, nodeA.address.get(),
      hexToByteArray[aesKeySize](readKey), hexToByteArray[aesKeySize](dummyKey))

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))
    check:
      decoded.isOk()
      decoded.get().messageOpt.isSome()
      decoded.get().messageOpt.get().reqId.id == hexToSeqByte(pingReqId)
      decoded.get().messageOpt.get().kind == ping
      decoded.get().messageOpt.get().ping.enrSeq == pingEnrSeq

  test "Whoareyou Packet":
    const
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouEnrSeq = 0

      encodedPacket =
        "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad" &
        "1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d"

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOk()
      decoded.get().flag == Flag.Whoareyou
      decoded.get().whoareyou.requestNonce == hexToByteArray[gcmNonceSize](whoareyouRequestNonce)
      decoded.get().whoareyou.idNonce == hexToByteArray[idNonceSize](whoareyouIdNonce)
      decoded.get().whoareyou.recordSeq == whoareyouEnrSeq
      decoded.get().whoareyou.challengeData == hexToSeqByte(whoareyouChallengeData)

      codecB.decodePacket(nodeA.address.get(),
        hexToSeqByte(encodedPacket & "00")).isErr()

  test "Ping Handshake Message Packet":
    const
      pingReqId = "0x00000001"
      pingEnrSeq = 1'u64
      #
      # handshake inputs:
      #
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouEnrSeq = 1'u64

      encodedPacket =
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55" &
        "ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" &
        "4c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef" &
        "268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfb" &
        "a776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1" &
        "f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d83" &
        "9cf8"

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouEnrSeq,
        challengeData: hexToSeqByte(whoareyouChallengeData))
      pubkey = some(privKeyA.toPublicKey())
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandshakeKey(nodeId: nodeA.id, address: nodeA.address.get())

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOk()
      decoded.get().message.reqId.id == hexToSeqByte(pingReqId)
      decoded.get().message.kind == ping
      decoded.get().message.ping.enrSeq == pingEnrSeq
      decoded.get().node.isNone()

      codecB.decodePacket(nodeA.address.get(),
        hexToSeqByte(encodedPacket & "00")).isErr()

  test "Ping Handshake Message Packet with ENR":
    const
      pingReqId = "0x00000001"
      pingEnrSeq = 1'u64
      #
      # handshake inputs:
      #
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouEnrSeq = 0'u64

      encodedPacket =
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55" &
        "ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" &
        "4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856" &
        "2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2" &
        "1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1" &
        "f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6" &
        "cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1" &
        "2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a" &
        "80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e" &
        "4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394" &
        "71"

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouEnrSeq,
        challengeData: hexToSeqByte(whoareyouChallengeData))
      pubkey = none(PublicKey)
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandshakeKey(nodeId: nodeA.id, address: nodeA.address.get())

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOk()
      decoded.get().message.reqId.id == hexToSeqByte(pingReqId)
      decoded.get().message.kind == ping
      decoded.get().message.ping.enrSeq == pingEnrSeq
      decoded.get().node.isSome()

      codecB.decodePacket(nodeA.address.get(),
        hexToSeqByte(encodedPacket & "00")).isErr()

suite "Discovery v5.1 Additional Encode/Decode":
  test "Encryption/Decryption":
    let
      encryptionKey = hexToByteArray[aesKeySize]("0x9f2d77db7004bf8a1a85107ac686990b")
      nonce = hexToByteArray[gcmNonceSize]("0x27b5af763c446acd2749fe8e")
      ad = hexToByteArray[32]("0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
      pt = hexToSeqByte("0xa1")

    let
      ct = encryptGCM(encryptionKey, nonce, pt, ad)
      decrypted = decryptGCM(encryptionKey, nonce, ct, ad)

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
    var nonce: AESGCMNonce
    brHmacDrbgGenerate(rng[], nonce)
    let
      privKey = PrivateKey.random(rng[])
      nodeId = privKey.toPublicKey().toNodeId()
      authdata = newSeq[byte](32)
      staticHeader = encodeStaticHeader(Flag.OrdinaryMessage, nonce,
        authdata.len())
      header = staticHeader & authdata

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

      enrRecA = enr.Record.init(1, privKeyA,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")
      nodeA = newNode(enrRecA).expect("Properly initialized record")

      enrRecB = enr.Record.init(1, privKeyB,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")
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
    var requestNonce: AESGCMNonce
    brHmacDrbgGenerate(rng[], requestNonce)
    let recordSeq = 0'u64

    let data = encodeWhoareyouPacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), requestNonce, recordSeq, none(PublicKey))

    let decoded = codecB.decodePacket(nodeA.address.get(), data)

    let key = HandshakeKey(nodeId: nodeB.id, address: nodeB.address.get())
    var challenge: Challenge

    check:
      codecA.handshakes.pop(key, challenge)
      decoded.isOk()
      decoded[].flag == Flag.Whoareyou
      decoded[].whoareyou.requestNonce == requestNonce
      decoded[].whoareyou.idNonce == challenge.whoareyouData.idNonce
      decoded[].whoareyou.recordSeq == recordSeq

  test "Encode / Decode Handshake Message Packet":
    var requestNonce: AESGCMNonce
    brHmacDrbgGenerate(rng[], requestNonce)
    let
      recordSeq = 1'u64
      m = PingMessage(enrSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)
      pubkey = some(privKeyA.toPublicKey())

    # Encode/decode whoareyou packet to get the handshake stored and the
    # whoareyou data returned. It's either that or construct the header for the
    # whoareyouData manually.
    let
      encodedDummy = encodeWhoareyouPacket(rng[], codecB, nodeA.id,
        nodeA.address.get(), requestNonce, recordSeq, pubkey)
      decodedDummy = codecA.decodePacket(nodeB.address.get(), encodedDummy)

    let data = encodeHandshakePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, decodedDummy[].whoareyou,
      privKeyB.toPublicKey())

    let decoded = codecB.decodePacket(nodeA.address.get(), data)

    check:
      decoded.isOk()
      decoded.get().message.reqId == reqId
      decoded.get().message.kind == ping
      decoded.get().message.ping.enrSeq == 0
      decoded.get().node.isNone()

  test "Encode / Decode Handshake Message Packet with ENR":
    var requestNonce: AESGCMNonce
    brHmacDrbgGenerate(rng[], requestNonce)
    let
      recordSeq = 0'u64
      m = PingMessage(enrSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)
      pubkey = none(PublicKey)

    # Encode/decode whoareyou packet to get the handshake stored and the
    # whoareyou data returned. It's either that or construct the header for the
    # whoareyouData manually.
    let
      encodedDummy = encodeWhoareyouPacket(rng[], codecB, nodeA.id,
        nodeA.address.get(), requestNonce, recordSeq, pubkey)
      decodedDummy = codecA.decodePacket(nodeB.address.get(), encodedDummy)

    let encoded = encodeHandshakePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, decodedDummy[].whoareyou,
      privKeyB.toPublicKey())

    let decoded = codecB.decodePacket(nodeA.address.get(), encoded)

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

    # Need to manually add the secrets that normally get negotiated in the
    # handshake packet.
    var secrets: HandshakeSecrets
    codecA.sessions.store(nodeB.id, nodeB.address.get(), secrets.recipientKey,
      secrets.initiatorKey)
    codecB.sessions.store(nodeA.id, nodeA.address.get(), secrets.initiatorKey,
      secrets.recipientKey)

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
