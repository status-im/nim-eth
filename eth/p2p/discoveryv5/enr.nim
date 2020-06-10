# ENR implemetation according to spec:
# https://github.com/ethereum/EIPs/blob/master/EIPS/eip-778.md

import
  strutils, macros, algorithm, options,
  stew/shims/net, nimcrypto, stew/base64,
  eth/[rlp, keys]

export options

{.push raises: [Defect].}

const
  maxEnrSize = 300
  minRlpListLen = 4 # for signature, seqId, "id" key, id

type
  FieldPair* = (string, Field)

  Record* = object
    seqNum*: uint64
    # signature: seq[byte]
    raw*: seq[byte] # RLP encoded record
    pairs: seq[FieldPair] # sorted list of all key/value pairs

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

  EnrResult*[T] = Result[T, cstring]

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

proc makeEnrAux(seqNum: uint64, pk: PrivateKey,
    pairs: openarray[(string, Field)]): EnrResult[Record] =
  var record: Record
  record.pairs = @pairs
  record.seqNum = seqNum

  let pubkey = ? pk.toPublicKey()

  record.pairs.add(("id", Field(kind: kString, str: "v4")))
  record.pairs.add(("secp256k1",
    Field(kind: kBytes, bytes: @(pubkey.toRawCompressed()))))

  # Sort by key
  record.pairs.sort() do(a, b: (string, Field)) -> int:
    cmp(a[0], b[0])

  proc append(w: var RlpWriter, seqNum: uint64,
      pairs: openarray[(string, Field)]): seq[byte] =
    w.append(seqNum)
    for (k, v) in pairs:
      w.append(k)
      case v.kind
      of kString: w.append(v.str)
      of kNum: w.append(v.num)
      of kBytes: w.append(v.bytes)
    w.finish()

  let toSign = block:
    var w = initRlpList(record.pairs.len * 2 + 1)
    w.append(seqNum, record.pairs)

  let sig = ? signNR(pk, toSign)

  record.raw = block:
    var w = initRlpList(record.pairs.len * 2 + 2)
    w.append(sig.toRaw())
    w.append(seqNum, record.pairs)

  ok(record)

macro initRecord*(seqNum: uint64, pk: PrivateKey,
    pairs: untyped{nkTableConstr}): untyped =
  for c in pairs:
    c.expectKind(nnkExprColonExpr)
    c[1] = newCall(bindSym"toField", c[1])

  result = quote do:
    makeEnrAux(`seqNum`, `pk`, `pairs`)

template toFieldPair*(key: string, value: auto): FieldPair =
  (key, toField(value))

proc init*(T: type Record, seqNum: uint64,
                           pk: PrivateKey,
                           ip: Option[ValidIpAddress],
                           tcpPort, udpPort: Port,
                           extraFields: openarray[FieldPair] = []):
                           EnrResult[T] =
  var fields = newSeq[FieldPair]()

  if ip.isSome():
    let
      ipExt = ip.get()
      isV6 = ipExt.family == IPv6

    fields.add(if isV6: ("ip6", ipExt.address_v6.toField)
               else: ("ip", ipExt.address_v4.toField))
    fields.add(((if isV6: "tcp6" else: "tcp"), tcpPort.uint16.toField))
    fields.add(((if isV6: "udp6" else: "udp"), udpPort.uint16.toField))
  else:
    fields.add(("tcp", tcpPort.uint16.toField))
    fields.add(("udp", udpPort.uint16.toField))

  fields.add extraFields
  makeEnrAux(seqNum, pk, fields)

proc getField(r: Record, name: string, field: var Field): bool =
  # It might be more correct to do binary search,
  # as the fields are sorted, but it's unlikely to
  # make any difference in reality.
  for (k, v) in r.pairs:
    if k == name:
      field = v
      return true

proc requireKind(f: Field, kind: FieldKind) {.raises: [ValueError].} =
  if f.kind != kind:
    raise newException(ValueError, "Wrong field kind")

proc get*(r: Record, key: string, T: type): T {.raises: [ValueError, Defect].} =
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
      let pk = PublicKey.fromRaw(f.bytes)
      if pk.isErr:
        raise newException(ValueError, "Invalid public key")
      return pk[]
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

proc get*(r: Record, T: type PublicKey): Option[T] =
  var pubkeyField: Field
  if r.getField("secp256k1", pubkeyField) and pubkeyField.kind == kBytes:
    let pk = PublicKey.fromRaw(pubkeyField.bytes)
    if pk.isOk:
      return some pk[]

proc tryGet*(r: Record, key: string, T: type): Option[T] =
  try:
    return some get(r, key, T)
  except ValueError:
    discard

proc toTypedRecord*(r: Record): EnrResult[TypedRecord] =
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

    ok(tr)
  else:
    err("Record without id field")

proc contains*(r: Record, fp: (string, seq[byte])): bool =
  # TODO: use FieldPair for this, but that is a bit cumbersome. Perhaps the
  # `get` call can be improved to make this easier.
  let field = r.tryGet(fp[0], seq[byte])
  if field.isSome():
    if field.get() == fp[1]:
      return true

proc verifySignatureV4(r: Record, sigData: openarray[byte], content: seq[byte]):
    bool =
  let publicKey = r.get(PublicKey)
  if publicKey.isSome:
    let sig = SignatureNR.fromRaw(sigData)
    if sig.isOk:
      var h = keccak256.digest(content)
      return verify(sig[], h, publicKey.get)

proc verifySignature(r: Record): bool {.raises: [RlpError, Defect].} =
  var rlp = rlpFromBytes(r.raw)
  let sz = rlp.listLen
  if not rlp.enterList:
    return false
  let sigData = rlp.read(seq[byte])
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

proc fromBytesAux(r: var Record): bool {.raises: [RlpError, Defect].} =
  if r.raw.len > maxEnrSize:
    return false

  var rlp = rlpFromBytes(r.raw)
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
      r.pairs.add((k, Field(kind: kBytes, bytes: rlp.read(seq[byte]))))

  verifySignature(r)

proc fromBytes*(r: var Record, s: openarray[byte]): bool =
  ## Loads ENR from rlp-encoded bytes, and validated the signature.
  r.raw = @s
  try:
    result = fromBytesAux(r)
  except RlpError:
    discard

proc fromBase64*(r: var Record, s: string): bool =
  ## Loads ENR from base64-encoded rlp-encoded bytes, and validated the
  ## signature.
  try:
    r.raw = Base64Url.decode(s)
    result = fromBytesAux(r)
  except RlpError, Base64Error:
    discard

proc fromURI*(r: var Record, s: string): bool =
  ## Loads ENR from its text encoding: base64-encoded rlp-encoded bytes,
  ## prefixed with "enr:".
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

proc read*(rlp: var Rlp, T: typedesc[Record]):
    T {.inline, raises:[RlpError, ValueError, Defect].} =
  if not result.fromBytes(rlp.rawData):
    # TODO: This could also just be an invalid signature, would be cleaner to
    # split of RLP deserialisation errors from this.
    raise newException(ValueError, "Could not deserialize")
  rlp.skipElem()

proc append*(rlpWriter: var RlpWriter, value: Record) =
  rlpWriter.appendRawBytes(value.raw)
