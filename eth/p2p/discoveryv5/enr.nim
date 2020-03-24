# ENR implemetation according to spec:
# https://github.com/ethereum/EIPs/blob/master/EIPS/eip-778.md

import
  net, strutils, macros, algorithm, options,
  nimcrypto, stew/base64,
  eth/[rlp, keys], ../enode

const
  maxEnrSize = 300
  minRlpListLen = 4 # for signature, seqId, "id" key, id

type
  Record* = object
    seqNum*: uint64
    # signature: seq[byte]
    raw*: seq[byte] # RLP encoded record
    pairs: seq[(string, Field)] # sorted list of all key/value pairs

  EnrUri* = distinct string

  TypedRecord* = object
    id*: string
    secp256k1*: Option[array[33, byte]]
    ip*: Option[array[4, byte]]
    ip6*: Option[array[16, byte]]
    tcp*: Option[int]
    udp*: Option[int]
    tcp6*: Option[int]
    udp6*: Option[int]

  FieldKind = enum
    kString,
    kNum,
    kBytes

  Field = object
    case kind: FieldKind
    of kString:
      str: string
    of kNum:
      num: BiggestUInt
    of kBytes:
      bytes: seq[byte]

template toField[T](v: T): Field =
  when T is string:
    Field(kind: kString, str: v)
  elif T is array:
    Field(kind: kBytes, bytes: @v)
  elif T is seq[byte]:
    Field(kind: kBytes, bytes: v)
  elif T is SomeUnsignedInt:
    Field(kind: kNum, num: BiggestUInt(v))
  else:
    {.error: "Unsupported field type".}

proc makeEnrAux(seqNum: uint64, pk: PrivateKey, pairs: openarray[(string, Field)]): Record =
  result.pairs = @pairs
  result.seqNum = seqNum

  let pubkey = pk.getPublicKey()

  result.pairs.add(("id", Field(kind: kString, str: "v4")))
  result.pairs.add(("secp256k1", Field(kind: kBytes, bytes: @(pubkey.getRawCompressed()))))

  # Sort by key
  result.pairs.sort() do(a, b: (string, Field)) -> int:
    cmp(a[0], b[0])

  proc append(w: var RlpWriter, seqNum: uint64, pairs: openarray[(string, Field)]): seq[byte] =
    w.append(seqNum)
    for (k, v) in pairs:
      w.append(k)
      case v.kind
      of kString: w.append(v.str)
      of kNum: w.append(v.num)
      of kBytes: w.append(v.bytes)
    w.finish()

  let toSign = block:
    var w = initRlpList(result.pairs.len * 2 + 1)
    w.append(seqNum, result.pairs)

  var sig: SignatureNR
  if signRawMessage(keccak256.digest(toSign).data, pk, sig) != EthKeysStatus.Success:
    raise newException(EthKeysException, "Could not sign ENR (internal error)")

  result.raw = block:
    var w = initRlpList(result.pairs.len * 2 + 2)
    w.append(sig.getRaw())
    w.append(seqNum, result.pairs)

macro initRecord*(seqNum: uint64, pk: PrivateKey, pairs: untyped{nkTableConstr}): untyped =
  for c in pairs:
    c.expectKind(nnkExprColonExpr)
    c[1] = newCall(bindSym"toField", c[1])

  result = quote do:
    makeEnrAux(`seqNum`, `pk`, `pairs`)

proc init*(T: type Record, seqNum: uint64,
                           pk: PrivateKey,
                           address: Option[enode.Address]): T =
  if address.isSome():
    let
      a = address.get()
      isV6 = a.ip.family == IPv6
      ipField = if isV6: ("ip6", a.ip.address_v6.toField)
                else: ("ip", a.ip.address_v4.toField)
      tcpField = ((if isV6: "tcp6" else: "tcp"), a.tcpPort.uint16.toField)
      udpField = ((if isV6: "udp6" else: "udp"), a.udpPort.uint16.toField)

    makeEnrAux(seqNum, pk, [ipField, tcpField, udpField])
  else:
    makeEnrAux(seqNum, pk, [])

proc getField(r: Record, name: string, field: var Field): bool =
  # It might be more correct to do binary search,
  # as the fields are sorted, but it's unlikely to
  # make any difference in reality.
  for (k, v) in r.pairs:
    if k == name:
      field = v
      return true

proc requireKind(f: Field, kind: FieldKind) =
  if f.kind != kind:
    raise newException(ValueError, "Wrong field kind")

proc get*(r: Record, key: string, T: type): T =
  var f: Field
  if r.getField(key, f):
    when T is SomeInteger:
      requireKind(f, kNum)
      return T(f.num)
    elif T is seq[byte]:
      requireKind(f, kBytes)
      return f.bytes
    elif T is string:
      requireKind(f, kString)
      return f.str
    elif T is PublicKey:
      requireKind(f, kBytes)
      if recoverPublicKey(f.bytes, result) != EthKeysStatus.Success:
        raise newException(ValueError, "Invalid public key")
    elif T is array:
      when type(result[0]) is byte:
        requireKind(f, kBytes)
        if f.bytes.len != result.len:
          raise newException(ValueError, "Invalid byte blob length")
        copyMem(addr result[0], addr f.bytes[0], result.len)
      else:
        {.fatal: "Unsupported output type in enr.get".}
    else:
      {.fatal: "Unsupported output type in enr.get".}
  else:
    raise newException(KeyError, "Key not found in ENR: " & key)

proc get*(r: Record, pubKey: var PublicKey): bool =
  var pubkeyField: Field
  if r.getField("secp256k1", pubkeyField) and pubkeyField.kind == kBytes:
    result = recoverPublicKey(pubkeyField.bytes, pubKey) == EthKeysStatus.Success

proc tryGet*(r: Record, key: string, T: type): Option[T] =
  try:
    return some get(r, key, T)
  except CatchableError:
    discard

proc toTypedRecord*(r: Record): Option[TypedRecord] =
  let id = r.tryGet("id", string)
  if id.isSome:
    var tr: TypedRecord
    tr.id = id.get

    template readField(fieldName: untyped) {.dirty.} =
      tr.fieldName = tryGet(r, astToStr(fieldName), type(tr.fieldName.get))

    readField secp256k1
    readField ip
    readField ip6
    readField tcp
    readField tcp6
    readField udp
    readField udp6

    return some(tr)

proc verifySignatureV4(r: Record, sigData: openarray[byte], content: seq[byte]): bool =
  var publicKey: PublicKey
  if r.get(publicKey):
    var sig: SignatureNR
    if sig.parseCompact(sigData) == EthKeysStatus.Success:
      var h = keccak256.digest(content)
      if verifySignatureRaw(sig, h.data, publicKey) == EthKeysStatus.Success:
        return true

proc verifySignature(r: Record): bool =
  var rlp = rlpFromBytes(r.raw.toRange)
  let sz = rlp.listLen
  if not rlp.enterList:
    return false
  let sigData = rlp.read(Bytes)
  let content = block:
    var writer = initRlpList(sz - 1)
    var reader = rlp
    for i in 1 ..< sz:
      writer.appendRawBytes(reader.rawData)
      reader.skipElem
    writer.finish()

  var id: Field
  if r.getField("id", id) and id.kind == kString:
    case id.str
    of "v4":
      result = verifySignatureV4(r, sigData, content)
    else:
      # Unknown Identity Scheme
      discard

proc fromBytesAux(r: var Record): bool =
  if r.raw.len > maxEnrSize:
    return false

  var rlp = rlpFromBytes(r.raw.toRange)
  if not rlp.isList:
    return false

  let sz = rlp.listLen
  if sz < minRlpListLen or sz mod 2 != 0:
    # Wrong rlp object
    return false

  # We already know we are working with a list
  doAssert rlp.enterList()
  rlp.skipElem() # Skip signature

  r.seqNum = rlp.read(uint64)

  let numPairs = (sz - 2) div 2

  for i in 0 ..< numPairs:
    let k = rlp.read(string)
    case k
    of "id":
      let id = rlp.read(string)
      r.pairs.add((k, Field(kind: kString, str: id)))
    of "secp256k1":
      let pubkeyData = rlp.read(seq[byte])
      r.pairs.add((k, Field(kind: kBytes, bytes: pubkeyData)))
    of "tcp", "udp", "tcp6", "udp6":
      let v = rlp.read(uint16)
      r.pairs.add((k, Field(kind: kNum, num: v)))
    else:
      r.pairs.add((k, Field(kind: kBytes, bytes: rlp.read(Bytes))))

  verifySignature(r)

proc fromBytes*(r: var Record, s: openarray[byte]): bool =
  # Loads ENR from rlp-encoded bytes, and validated the signature.
  r.raw = @s
  try:
    result = fromBytesAux(r)
  except CatchableError:
    discard

proc fromBase64*(r: var Record, s: string): bool =
  # Loads ENR from base64-encoded rlp-encoded bytes, and validated the signature.
  try:
    r.raw = Base64Url.decode(s)
    result = fromBytesAux(r)
  except CatchableError:
    discard

proc fromURI*(r: var Record, s: string): bool =
  # Loads ENR from its text encoding: base64-encoded rlp-encoded bytes, prefixed with "enr:".
  const prefix = "enr:"
  if s.startsWith(prefix):
    result = r.fromBase64(s[prefix.len .. ^1])

template fromURI*(r: var Record, url: EnrUri): bool =
  fromURI(r, string(url))

proc toBase64*(r: Record): string =
  result = Base64Url.encode(r.raw)

proc toURI*(r: Record): string = "enr:" & r.toBase64

proc `$`(f: Field): string =
  case f.kind
  of kNum:
    $f.num
  of kBytes:
    "0x" & f.bytes.toHex
  of kString:
    "\"" & f.str & "\""

proc `$`*(r: Record): string =
  result = "("
  var first = true
  for (k, v) in r.pairs:
    if first:
      first = false
    else:
      result &= ", "
    result &= k
    result &= ": "
    result &= $v
  result &= ')'

proc `==`*(a, b: Record): bool = a.raw == b.raw

proc read*(rlp: var Rlp, T: typedesc[Record]): T {.inline.} =
  if not result.fromBytes(rlp.rawData.toOpenArray):
    raise newException(ValueError, "Could not deserialize")
  rlp.skipElem()

proc append*(rlpWriter: var RlpWriter, value: Record) =
  rlpWriter.appendRawBytes(value.raw.toRange)
