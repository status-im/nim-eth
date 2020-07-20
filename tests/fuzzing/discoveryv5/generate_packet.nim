import
  std/[os, strutils],
  stew/shims/net,
  eth/[keys, rlp, trie/db],
  eth/p2p/discoveryv5/[protocol, discovery_db, enr, node, types, encoding],
  ../fuzzing_helpers

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
const inputsDir = sourceDir / "corpus" & DirSep

proc generate() =
  let
    rng = keys.newRng()
    privKey = PrivateKey.random(rng[])
    ip = some(ValidIpAddress.init("127.0.0.1"))
    port = Port(20301)
    dbb = DiscoveryDB.init(newMemoryDB())
    d = newProtocol(privKey, dbb, ip, port, port, rng = rng)

    # Same as the on in the fuzz test to have at least one working packet for
    # the whoareyou-packet.
    toPrivKey = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    toRecord = enr.Record.init(1, toPrivKey,
      some(ValidIpAddress.init("127.0.0.1")), Port(9000), Port(9000))[]
    toNode = newNode(toRecord)[]

  block: # random packet
    # No handshake done obviously so a new packet will be a random packet.
    let
      reqId = RequestId.init(d.rng[])
      message = encodeMessage(PingMessage(enrSeq: d.localNode.record.seqNum), reqId)
      (data, _) = encodePacket(d.rng[], d.codec, toNode.id, toNode.address.get(),
        message, challenge = nil)

    data.toFile(inputsDir & "random-packet")

  block: # whoareyou packet
    var authTag: AuthTag
    var idNonce: IdNonce
    brHmacDrbgGenerate(d.rng[], authTag)
    brHmacDrbgGenerate(d.rng[], idNonce)

    let challenge = Whoareyou(authTag: authTag, idNonce: idNonce, recordSeq: 0)
    var data = @(whoareyouMagic(toNode.id))
    data.add(rlp.encode(challenge[]))

    data.toFile(inputsDir & "whoareyou-packet")

discard existsOrCreateDir(inputsDir)
generate()
