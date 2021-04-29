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
  std/unittest,
  nimcrypto/[utils, sysrand, keccak],
  ../../eth/keys, ../../eth/p2p/[auth, rlpxcrypt]

const data = [
  ("initiator_private_key",
   "5e173f6ac3c669587538e7727cf19b782a4f2fda07c1eaa662c593e5e85e3051"),
  ("receiver_private_key",
   "c45f950382d542169ea207959ee0220ec1491755abe405cd7498d6b16adb6df8"),
  ("initiator_ephemeral_private_key",
   "19c2185f4f40634926ebed3af09070ca9e029f2edd5fae6253074896205f5f6c"),
  ("receiver_ephemeral_private_key",
   "d25688cf0ab10afa1a0e2dba7853ed5f1e5bf1c631757ed4e103b593ff3f5620"),
  ("auth_plaintext",
   """884c36f7ae6b406637c1f61b2f57e1d2cab813d24c6559aaf843c3f48962f32f
      46662c066d39669b7b2e3ba14781477417600e7728399278b1b5d801a519aa57
      0034fdb5419558137e0d44cd13d319afe5629eeccb47fd9dfe55cc6089426e46
      cc762dd8a0636e07a54b31169eba0c7a20a1ac1ef68596f1f283b5c676bae406
      4abfcce24799d09f67e392632d3ffdc12e3d6430dcb0ea19c318343ffa7aae74
      d4cd26fecb93657d1cd9e9eaf4f8be720b56dd1d39f190c4e1c6b7ec66f077bb
      1100"""),
  ("authresp_plaintext",
   """802b052f8b066640bba94a4fc39d63815c377fced6fcb84d27f791c9921ddf3e
      9bf0108e298f490812847109cbd778fae393e80323fd643209841a3b7f110397
      f37ec61d84cea03dcc5e8385db93248584e8af4b4d1c832d8c7453c0089687a7
      00"""),
  ("auth_ciphertext",
   """04a0274c5951e32132e7f088c9bdfdc76c9d91f0dc6078e848f8e3361193dbdc
      43b94351ea3d89e4ff33ddcefbc80070498824857f499656c4f79bbd97b6c51a
      514251d69fd1785ef8764bd1d262a883f780964cce6a14ff206daf1206aa073a
      2d35ce2697ebf3514225bef186631b2fd2316a4b7bcdefec8d75a1025ba2c540
      4a34e7795e1dd4bc01c6113ece07b0df13b69d3ba654a36e35e69ff9d482d88d
      2f0228e7d96fe11dccbb465a1831c7d4ad3a026924b182fc2bdfe016a6944312
      021da5cc459713b13b86a686cf34d6fe6615020e4acf26bf0d5b7579ba813e77
      23eb95b3cef9942f01a58bd61baee7c9bdd438956b426a4ffe238e61746a8c93
      d5e10680617c82e48d706ac4953f5e1c4c4f7d013c87d34a06626f498f34576d
      c017fdd3d581e83cfd26cf125b6d2bda1f1d56"""),
  ("authresp_ciphertext",
   """049934a7b2d7f9af8fd9db941d9da281ac9381b5740e1f64f7092f3588d4f87f
      5ce55191a6653e5e80c1c5dd538169aa123e70dc6ffc5af1827e546c0e958e42
      dad355bcc1fcb9cdf2cf47ff524d2ad98cbf275e661bf4cf00960e74b5956b79
      9771334f426df007350b46049adb21a6e78ab1408d5e6ccde6fb5e69f0f4c92b
      b9c725c02f99fa72b9cdc8dd53cff089e0e73317f61cc5abf6152513cb7d833f
      09d2851603919bf0fbe44d79a09245c6e8338eb502083dc84b846f2fee1cc310
      d2cc8b1b9334728f97220bb799376233e113"""),
  ("ecdhe_shared_secret",
   "e3f407f83fc012470c26a93fdff534100f2c6f736439ce0ca90e9914f7d1c381"),
  ("initiator_nonce",
   "cd26fecb93657d1cd9e9eaf4f8be720b56dd1d39f190c4e1c6b7ec66f077bb11"),
  ("receiver_nonce",
   "f37ec61d84cea03dcc5e8385db93248584e8af4b4d1c832d8c7453c0089687a7"),
  ("aes_secret",
   "c0458fa97a5230830e05f4f20b7c755c1d4e54b1ce5cf43260bb191eef4e418d"),
  ("mac_secret",
   "48c938884d5067a1598272fcddaa4b833cd5e7d92e8228c0ecdfabbe68aef7f1"),
  ("token",
   "3f9ec2592d1554852b1f54d228f042ed0a9310ea86d038dc2b401ba8cd7fdac4"),
  ("initial_egress_MAC",
   "09771e93b1a6109e97074cbe2d2b0cf3d3878efafe68f53c41bb60c0ec49097e"),
  ("initial_ingress_MAC",
   "75823d96e23136c89666ee025fb21a432be906512b3dd4a3049e898adb433847"),
  ("initiator_hello_packet",
   """6ef23fcf1cec7312df623f9ae701e63b550cdb8517fefd8dd398fc2acd1d935e
      6e0434a2b96769078477637347b7b01924fff9ff1c06df2f804df3b0402bbb9f
      87365b3c6856b45e1e2b6470986813c3816a71bff9d69dd297a5dbd935ab578f
      6e5d7e93e4506a44f307c332d95e8a4b102585fd8ef9fc9e3e055537a5cec2e9"""),
  ("receiver_hello_packet",
   """6ef23fcf1cec7312df623f9ae701e63be36a1cdd1b19179146019984f3625d4a
      6e0434a2b96769050577657247b7b02bc6c314470eca7e3ef650b98c83e9d7dd
      4830b3f718ff562349aead2530a8d28a8484604f92e5fced2c6183f304344ab0
      e7c301a0c05559f4c25db65e36820b4b909a226171a60ac6cb7beea09376d6d8""")
]

let rng = newRng()

proc testValue(s: string): string =
  for item in data:
    if item[0] == s:
      result = item[1]
      break

suite "Ethereum RLPx encryption/decryption test suite":
  proc newTestHandshake(flags: set[HandshakeFlag]): Handshake =
    if Initiator in flags:
      let pk = PrivateKey.fromHex(testValue("initiator_private_key"))[]
      result = Handshake.tryInit(rng[], pk.toKeyPair(), flags)[]
      let epki = testValue("initiator_ephemeral_private_key")
      result.ephemeral = PrivateKey.fromHex(epki)[].toKeyPair()
      let nonce = fromHex(stripSpaces(testValue("initiator_nonce")))
      result.initiatorNonce[0..^1] = nonce[0..^1]
    elif Responder in flags:
      let pk = PrivateKey.fromHex(testValue("receiver_private_key"))[]
      result = Handshake.tryInit(rng[], pk.toKeyPair(), flags)[]
      let epkr = testValue("receiver_ephemeral_private_key")
      result.ephemeral = PrivateKey.fromHex(epkr)[].toKeyPair()
      let nonce = fromHex(stripSpaces(testValue("receiver_nonce")))
      result.responderNonce[0..^1] = nonce[0..^1]

  test "Encrypt/Decrypt Hello packet test vectors":
    var initiator = newTestHandshake({Initiator})
    var responder = newTestHandshake({Responder})
    var authm = fromHex(stripSpaces(testValue("auth_ciphertext")))
    var ackm = fromHex(stripSpaces(testValue("authresp_ciphertext")))
    var stateInitiator0, stateInitiator1: SecretState
    var stateResponder0, stateResponder1: SecretState
    responder.decodeAuthMessage(authm).expect("success")
    initiator.decodeAckMessage(ackm).expect("success")

    var csecInitiator = initiator.getSecrets(authm, ackm)[]
    var csecResponder = responder.getSecrets(authm, ackm)[]
    initSecretState(csecInitiator, stateInitiator0)
    initSecretState(csecResponder, stateResponder0)
    initSecretState(csecInitiator, stateInitiator1)
    initSecretState(csecResponder, stateResponder1)
    var packet0 = testValue("initiator_hello_packet")
    var initiatorHello = fromHex(stripSpaces(packet0))
    var packet1 = testValue("receiver_hello_packet")
    var responderHello = fromHex(stripSpaces(packet1))
    var header: array[RlpHeaderLength, byte]

    block:
      check stateResponder0.decryptHeader(toOpenArray(initiatorHello, 0, 31),
                                          header).isOk()
      let bodysize = getBodySize(header)
      check bodysize == 79
      # we need body size to be rounded to 16 bytes boundary to properly
      # encrypt/decrypt it.
      var body = newSeq[byte](decryptedLength(bodysize))
      var decrsize = 0
      check:
        stateResponder0.decryptBody(
          toOpenArray(initiatorHello, 32, len(initiatorHello) - 1),
          getBodySize(header), body, decrsize).isOk()
        decrsize == 79
      body.setLen(decrsize)
      var hello = newSeq[byte](encryptedLength(bodysize))
      check:
        stateInitiator1.encrypt(header, body, hello).isOk()
        hello == initiatorHello
    block:
      check stateInitiator0.decryptHeader(toOpenArray(responderHello, 0, 31),
                                          header).isOk()
      let bodysize = getBodySize(header)
      check bodysize == 79
      # we need body size to be rounded to 16 bytes boundary to properly
      # encrypt/decrypt it.
      var body = newSeq[byte](decryptedLength(bodysize))
      var decrsize = 0
      check:
        stateInitiator0.decryptBody(
          toOpenArray(responderHello, 32, len(initiatorHello) - 1),
          getBodySize(header), body, decrsize).isOk()
        decrsize == 79
      body.setLen(decrsize)
      var hello = newSeq[byte](encryptedLength(bodysize))
      check:
        stateResponder1.encrypt(header, body, hello).isOk()
        hello == responderHello

  test "Continuous stream of different lengths (1000 times)":
    var initiator = newTestHandshake({Initiator})
    var responder = newTestHandshake({Responder})
    var m0 = newSeq[byte](initiator.authSize())
    var k0 = 0
    var k1 = 0
    check initiator.authMessage(rng[], responder.host.pubkey,
                                m0, k0).isOk
    m0.setLen(k0)
    check responder.decodeAuthMessage(m0).isOk
    var m1 = newSeq[byte](responder.ackSize())
    check responder.ackMessage(rng[], m1, k1).isOk
    m1.setLen(k1)
    check initiator.decodeAckMessage(m1).isOk

    var csecInitiator = initiator.getSecrets(m0, m1)[]
    var csecResponder = responder.getSecrets(m0, m1)[]
    var stateInitiator: SecretState
    var stateResponder: SecretState
    var iheader, rheader: array[16, byte]
    initSecretState(csecInitiator, stateInitiator)
    initSecretState(csecResponder, stateResponder)
    burnMem(iheader)
    burnMem(rheader)
    for i in 1..1000:
      # initiator -> responder
      block:
        var ibody = newSeq[byte](i)
        var encrypted = newSeq[byte](encryptedLength(len(ibody)))
        iheader[0] = byte((len(ibody) shr 16) and 0xFF)
        iheader[1] = byte((len(ibody) shr 8) and 0xFF)
        iheader[2] = byte(len(ibody) and 0xFF)
        check:
          randomBytes(ibody) == len(ibody)
          stateInitiator.encrypt(iheader, ibody,
                                 encrypted).isOk()
          stateResponder.decryptHeader(toOpenArray(encrypted, 0, 31),
                                       rheader).isOk()
        var length = getBodySize(rheader)
        check length == len(ibody)
        var rbody = newSeq[byte](decryptedLength(length))
        var decrsize = 0
        check:
          stateResponder.decryptBody(
            toOpenArray(encrypted, 32, len(encrypted) - 1),
            length, rbody, decrsize).isOk()
          decrsize == length
        rbody.setLen(decrsize)
        check:
          iheader == rheader
          ibody == rbody
        burnMem(iheader)
        burnMem(rheader)
      # responder -> initiator
      block:
        var ibody = newSeq[byte](i * 3)
        var encrypted = newSeq[byte](encryptedLength(len(ibody)))
        iheader[0] = byte((len(ibody) shr 16) and 0xFF)
        iheader[1] = byte((len(ibody) shr 8) and 0xFF)
        iheader[2] = byte(len(ibody) and 0xFF)
        check:
          randomBytes(ibody) == len(ibody)
          stateResponder.encrypt(iheader, ibody,
                                 encrypted).isOk()
          stateInitiator.decryptHeader(toOpenArray(encrypted, 0, 31),
                                       rheader).isOk()
        var length = getBodySize(rheader)
        check length == len(ibody)
        var rbody = newSeq[byte](decryptedLength(length))
        var decrsize = 0
        check:
          stateInitiator.decryptBody(
            toOpenArray(encrypted, 32, len(encrypted) - 1),
            length, rbody, decrsize).isOk()
          decrsize == length
        rbody.setLen(length)
        check:
          iheader == rheader
          ibody == rbody
        burnMem(iheader)
        burnMem(rheader)
