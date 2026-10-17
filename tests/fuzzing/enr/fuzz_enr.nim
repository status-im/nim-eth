{.push raises: [].}

import
  std/algorithm,
  testutils/fuzzing,
  ../../../eth/enr/enr

const enrKeys = [
  "attnets", "eth2", "id", "ip", "ip6", "quic", "quic6",
  "secp256k1", "syncnets", "tcp", "tcp6", "udp", "udp6"]

let
  privKey = PrivateKey.fromHex(
    "0000000000000000000000000000000000000000000000000000000000000001")
    .expect("valid private key")
  pubKey = privKey.toPublicKey().toRawCompressed()

proc signedRecord(
    seqNum: uint64, pk: PrivateKey,
    pairs: openArray[(string, seq[byte])]): seq[byte] =
  ## Build a raw, signed ENR from an explicit ordered list of
  ## (key, encoded-value) pairs
  template appendPairs(w: var RlpWriter) =
    w.append(seqNum)
    for (k, v) in pairs:
      w.append(k)
      w.appendRawBytes(v)

  let content = block:
    var w = initRlpList(pairs.len * 2 + 1)
    w.appendPairs()
    w.finish()

  var w = initRlpList(pairs.len * 2 + 2)
  w.append(signNR(pk, content).toRaw())
  w.appendPairs()
  w.finish()

proc buildRecord(payload: openArray[byte]): seq[byte] =
  var i = 0
  template nextByte(): byte =
    if i < payload.len:
      inc i
      payload[i - 1]
    else:
      0'u8

  let
    flags = nextByte()
    sortPairs = (flags and 1) == 0
    withMandatoryPairs = (flags and 2) == 0
    seqNum = uint64(flags shr 2)
    numPairs = int(nextByte() mod 12)

  var pairs: seq[(string, seq[byte])]
  if withMandatoryPairs:
    pairs.add ("id", rlp.encode("v4"))
    pairs.add ("secp256k1", rlp.encode(pubKey))

  for _ in 0 ..< numPairs:
    let
      k = nextByte()
      key =
        if k >= 0xf0: "x" & $k
        else: enrKeys[int(k) mod enrKeys.len]
      v = nextByte()
      value =
        case key
        of "id":
          rlp.encode(if v mod 4 == 0: "v5" else: "v4")
        of "secp256k1":
          rlp.encode(pubKey)
        else:
          if v mod 2 == 0:
            rlp.encode(uint64(nextByte()) shl 8 or uint64(nextByte()))
          else:
            var bytes: seq[byte]
            for _ in 0 ..< int(v shr 3):
              bytes.add nextByte()
            rlp.encode(bytes)
    pairs.add (key, value)

  if sortPairs:
    pairs = pairs.sortedByIt(it[0])

  signedRecord(seqNum, privKey, pairs)

func checkRecord(r: Record) =
  # EIP-778 requires the keys to be sorted and unique
  for i in 1 ..< r.pairs.len:
    doAssert r.pairs[i - 1][0] < r.pairs[i][0],
      "accepted record has unsorted or duplicate keys"

  let fromUri = Record.fromURI(r.toURI())
  doAssert fromUri.isOk() and fromUri.value().raw == r.raw,
    "URI round trip failed"

  discard TypedRecord.fromRecord(r)
  discard r.get(PublicKey)
  for key in enrKeys:
    discard r.rawFieldValue(key)
    discard r.tryGet(key, uint16)
    discard r.tryGet(key, seq[byte])

test:
  try:
    checkRecord(rlp.decode(payload, Record))
  except RlpError:
    discard

  # The raw payload practically never has a valid signature, so sign one too
  let decoded = Record.fromBytes(buildRecord(payload))
  if decoded.isOk():
    checkRecord(decoded.value())
