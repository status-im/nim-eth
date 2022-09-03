# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## ENR implementation according to specification in EIP-778:
## https://github.com/ethereum/EIPs/blob/master/EIPS/eip-778.md

{.push raises: [Defect].}

import
  std/[strutils, macros, algorithm, options],
  nimcrypto/[keccak, utils], stew/shims/net, stew/[base64, results],
  ".."/../[rlp, keys]

export options, results, keys

const
  maxEnrSize = 300  ## Maximum size of an encoded node record, in bytes.
  minRlpListLen = 4 ## Minimum node record RLP list has: signature, seqId,
  ## "id" key and value.

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
    kBytes,
    kList

  Field = object
    case kind: FieldKind
    of kString:
      str: string
    of kNum:
      num: BiggestUInt
    of kBytes:
      bytes: seq[byte]
    of kList:
      listRaw: seq[byte] ## Differently from the other kinds, this is is stored
      ## as raw (encoded) RLP data, and thus treated as such further on.

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
  elif T is object|tuple:
    Field(kind: kList, listRaw: rlp.encode(v))
  else:
    {.error: "Unsupported field type".}

proc `==`(a, b: Field): bool =
  if a.kind == b.kind:
    case a.kind
    of kString:
      return a.str == b.str
    of kNum:
      return a.num == b.num
    of kBytes:
      return a.bytes == b.bytes
    of kList:
      return a.listRaw == b.listRaw
  else:
    return false

proc cmp(a, b: FieldPair): int = cmp(a[0], b[0])

proc makeEnrRaw(seqNum: uint64, pk: PrivateKey,
    pairs: openArray[FieldPair]): EnrResult[seq[byte]] =
  proc append(w: var RlpWriter, seqNum: uint64,
      pairs: openArray[FieldPair]): seq[byte] =
    w.append(seqNum)
    for (k, v) in pairs:
      w.append(k)
      case v.kind
      of kString: w.append(v.str)
      of kNum: w.append(v.num)
      of kBytes: w.append(v.bytes)
      of kList: w.appendRawBytes(v.listRaw) # No encoding needs to happen
    w.finish()

  let toSign = block:
    var w = initRlpList(pairs.len * 2 + 1)
    w.append(seqNum, pairs)

  let sig = signNR(pk, toSign)

  var raw = block:
    var w = initRlpList(pairs.len * 2 + 2)
    w.append(sig.toRaw())
    w.append(seqNum, pairs)

  if raw.len > maxEnrSize:
    err("Record exceeds maximum size")
  else:
    ok(raw)

proc makeEnrAux(seqNum: uint64, pk: PrivateKey,
    pairs: openArray[FieldPair]): EnrResult[Record] =
  var record: Record
  record.pairs = @pairs
  record.seqNum = seqNum

  let pubkey = pk.toPublicKey()

  record.pairs.add(("id", Field(kind: kString, str: "v4")))
  record.pairs.add(("secp256k1",
    Field(kind: kBytes, bytes: @(pubkey.toRawCompressed()))))

  # Sort by key
  record.pairs.sort(cmp)
  # TODO: Should deduplicate on keys here also. Should we error on that or just
  # deal with it?

  record.raw = ? makeEnrRaw(seqNum, pk, record.pairs)
  ok(record)

macro initRecord*(seqNum: uint64, pk: PrivateKey,
    pairs: untyped{nkTableConstr}): untyped =
  ## Initialize a `Record` with given sequence number, private key and k:v
  ## pairs.
  ##
  ## Can fail in case the record exceeds the `maxEnrSize`.
  for c in pairs:
    c.expectKind(nnkExprColonExpr)
    c[1] = newCall(bindSym"toField", c[1])

  result = quote do:
    makeEnrAux(`seqNum`, `pk`, `pairs`)

template toFieldPair*(key: string, value: auto): FieldPair =
  (key, toField(value))

proc addAddress(fields: var seq[FieldPair], ip: Option[ValidIpAddress],
    tcpPort, udpPort: Option[Port]) =
  ## Add address information in new fields. Incomplete address
  ## information is allowed (example: Port but not IP) as that information
  ## might be already in the ENR or added later.
  if ip.isSome():
    let
      ipExt = ip.get()
      isV6 = ipExt.family == IPv6

    fields.add(if isV6: ("ip6", ipExt.address_v6.toField)
               else: ("ip", ipExt.address_v4.toField))
    if tcpPort.isSome():
      fields.add(((if isV6: "tcp6" else: "tcp"), tcpPort.get().uint16.toField))
    if udpPort.isSome():
      fields.add(((if isV6: "udp6" else: "udp"), udpPort.get().uint16.toField))
  else:
    if tcpPort.isSome():
      fields.add(("tcp", tcpPort.get().uint16.toField))
    if udpPort.isSome():
      fields.add(("udp", udpPort.get().uint16.toField))

proc init*(T: type Record, seqNum: uint64,
                           pk: PrivateKey,
                           ip: Option[ValidIpAddress],
                           tcpPort, udpPort: Option[Port],
                           extraFields: openArray[FieldPair] = []):
                           EnrResult[T] =
  ## Initialize a `Record` with given sequence number, private key, optional
  ## ip address, tcp port, udp port, and optional custom k:v pairs.
  ##
  ## Can fail in case the record exceeds the `maxEnrSize`.
  var fields = newSeq[FieldPair]()

  # TODO: Allow for initializing ENR with both ip4 and ipv6 address.
  fields.addAddress(ip, tcpPort, udpPort)
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

proc requireKind(f: Field, kind: FieldKind): EnrResult[void] =
  if f.kind != kind:
    err("Wrong field kind")
  else:
    ok()

proc get*(r: Record, key: string, T: type): EnrResult[T] =
  ## Get the value from the provided key.
  var f: Field
  if r.getField(key, f):
    when T is SomeInteger:
      ? requireKind(f, kNum)
      ok(T(f.num))
    elif T is seq[byte]:
      ? requireKind(f, kBytes)
      ok(f.bytes)
    elif T is string:
      ? requireKind(f, kString)
      ok(f.str)
    elif T is PublicKey:
      ? requireKind(f, kBytes)
      let pk = PublicKey.fromRaw(f.bytes)
      if pk.isErr:
        err("Invalid public key")
      else:
        ok(pk[])
    elif T is array:
      when type(default(T)[low(T)]) is byte:
        ? requireKind(f, kBytes)
        if f.bytes.len != T.len:
          err("Invalid byte blob length")
        else:
          var res: T
          copyMem(addr res[0], addr f.bytes[0], res.len)
          ok(res)
      else:
        {.fatal: "Unsupported output type in enr.get".}
    else:
      {.fatal: "Unsupported output type in enr.get".}
  else:
    err("Key not found in ENR")

proc get*(r: Record, T: type PublicKey): Option[T] =
  ## Get the `PublicKey` from provided `Record`. Return `none` when there is
  ## no `PublicKey` in the record.
  var pubkeyField: Field
  if r.getField("secp256k1", pubkeyField) and pubkeyField.kind == kBytes:
    let pk = PublicKey.fromRaw(pubkeyField.bytes)
    if pk.isOk:
      return some pk[]

proc find(r: Record, key: string): Option[int] =
  ## Search for key in record key:value pairs.
  ##
  ## Returns some(index of key) if key is found in record. Else return none.
  for i, (k, v) in r.pairs:
    if k == key:
      return some(i)

proc update*(record: var Record, pk: PrivateKey,
    fieldPairs: openArray[FieldPair]): EnrResult[void] =
  ## Update a `Record` k:v pairs.
  ##
  ## In case any of the k:v pairs is updated or added (new), the sequence number
  ## of the `Record` will be incremented and a new signature will be applied.
  ##
  ## Can fail in case of wrong `PrivateKey`, if the size of the resulting record
  ## exceeds `maxEnrSize` or if maximum sequence number is reached. The `Record`
  ## will not be altered in these cases.
  var r = record

  let pubkey = r.get(PublicKey)
  if pubkey.isNone() or pubkey.get() != pk.toPublicKey():
    return err("Public key does not correspond with given private key")

  var updated = false
  for fieldPair in fieldPairs:
    let index = r.find(fieldPair[0])
    if(index.isSome()):
      if r.pairs[index.get()][1] == fieldPair[1]:
        # Exact k:v pair is already in record, nothing to do here.
        continue
      else:
        # Need to update the value.
        r.pairs[index.get()] = fieldPair
        updated = true
    else:
      # Add new k:v pair.
      r.pairs.insert(fieldPair, lowerBound(r.pairs, fieldPair, cmp))
      updated = true

  if updated:
    if r.seqNum == high(r.seqNum): # highly unlikely
      return err("Maximum sequence number reached")
    r.seqNum.inc()
    r.raw = ? makeEnrRaw(r.seqNum, pk, r.pairs)
    record = r

  ok()

proc update*(r: var Record, pk: PrivateKey,
                            ip: Option[ValidIpAddress],
                            tcpPort, udpPort: Option[Port] = none[Port](),
                            extraFields: openArray[FieldPair] = []):
                            EnrResult[void] =
  ## Update a `Record` with given ip address, tcp port, udp port and optional
  ## custom k:v pairs.
  ##
  ## In case any of the k:v pairs is updated or added (new), the sequence number
  ## of the `Record` will be incremented and a new signature will be applied.
  ##
  ## Can fail in case of wrong `PrivateKey`, if the size of the resulting record
  ## exceeds `maxEnrSize` or if maximum sequence number is reached. The `Record`
  ## will not be altered in these cases.
  var fields = newSeq[FieldPair]()

  # TODO: Make updating of both ipv4 and ipv6 address in ENR more convenient.
  fields.addAddress(ip, tcpPort, udpPort)
  fields.add extraFields
  r.update(pk, fields)

proc tryGet*(r: Record, key: string, T: type): Option[T] =
  ## Get the value from the provided key.
  ## Return `none` if the key does not exist or if the value is invalid
  ## according to type `T`.
  let val = get(r, key, T)
  if val.isOk():
    some(val.get())
  else:
    none(T)

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

proc verifySignatureV4(r: Record, sigData: openArray[byte], content: seq[byte]):
    bool =
  let publicKey = r.get(PublicKey)
  if publicKey.isSome:
    let sig = SignatureNR.fromRaw(sigData)
    if sig.isOk:
      var h = keccak256.digest(content)
      return verify(sig[], SkMessage(h.data), publicKey.get)

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
      # Don't know really what this is supposed to represent so drop it in
      # `kBytes` field pair when a single byte or blob.
      if rlp.isSingleByte() or rlp.isBlob():
        r.pairs.add((k, Field(kind: kBytes, bytes: rlp.read(seq[byte]))))
      elif rlp.isList():
        # Not supporting decoding lists as value (especially unknown ones),
        # just drop the raw RLP value in there.
        r.pairs.add((k, Field(kind: kList, listRaw: @(rlp.rawData()))))
        # Need to skip the element still.
        rlp.skipElem()

  verifySignature(r)

proc fromBytes*(r: var Record, s: openArray[byte]): bool =
  ## Loads ENR from rlp-encoded bytes, and validates the signature.
  r.raw = @s
  try:
    result = fromBytesAux(r)
  except RlpError:
    discard

proc fromBase64*(r: var Record, s: string): bool =
  ## Loads ENR from base64-encoded rlp-encoded bytes, and validates the
  ## signature.
  try:
    r.raw = Base64Url.decode(s)
    result = fromBytesAux(r)
  except RlpError, Base64Error:
    discard

proc fromURI*(r: var Record, s: string): bool =
  ## Loads ENR from its text encoding: base64-encoded rlp-encoded bytes,
  ## prefixed with "enr:". Validates the signature.
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
  of kList:
    "(Raw RLP list) " & "0x" & f.listRaw.toHex

proc `$`*(r: Record): string =
  result = "("
  result &= $r.seqNum
  for (k, v) in r.pairs:
    result &= ", "
    result &= k
    result &= ": "
    # For IP addresses we print something prettier than the default kinds
    # Note: Could disallow for invalid IPs in ENR also.
    if k == "ip":
      let ip = r.tryGet("ip", array[4, byte])
      if ip.isSome():
        result &= $ipv4(ip.get())
      else:
        result &= "(Invalid) " & $v
    elif k == "ip6":
      let ip = r.tryGet("ip6", array[16, byte])
      if ip.isSome():
        result &= $ipv6(ip.get())
      else:
        result &= "(Invalid) " & $v
    else:
      result &= $v
  result &= ')'

proc `==`*(a, b: Record): bool = a.raw == b.raw

proc read*(rlp: var Rlp, T: typedesc[Record]):
    T {.raises: [RlpError, ValueError, Defect].} =
  if not rlp.hasData() or not result.fromBytes(rlp.rawData):
    # TODO: This could also just be an invalid signature, would be cleaner to
    # split of RLP deserialisation errors from this.
    raise newException(ValueError, "Could not deserialize")
  rlp.skipElem()

proc append*(rlpWriter: var RlpWriter, value: Record) =
  rlpWriter.appendRawBytes(value.raw)
