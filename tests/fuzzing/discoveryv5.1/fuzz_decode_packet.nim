import
  testutils/fuzzing, stew/shims/net, stew/byteutils,
  eth/p2p/discoveryv5/[encodingv1, enr, sessions, node]

init:
  const
    nodeAKey = "0xeef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"
    nodeBKey = "0x66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"
  let
    rng = newRng()
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

  var codecB = Codec(localNode: nodeB, privKey: privKeyB,
    sessions: Sessions.init(5))

test:
  # It is not the best idea to generate extra data and encrypt data but we do
  # it like this as the decodeHeader proc does decrypt + decode + decrypt.
  # There is no separate decrypt step that can be skipped because of this.
  var iv: array[ivSize, byte]
  brHmacDrbgGenerate(rng[], iv)
  let maskedHeader = encryptHeader(nodeB.id, iv, payload)

  let decoded = decodePacket(codecB, nodeA.address.get(), @iv & maskedHeader)
  if decoded.isErr():
    debug "Error occured", error = decoded.error
