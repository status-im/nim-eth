# nim-eth - enr
# Copyright (c) 2020-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## ENR implementation according to specification in EIP-778:
## https://github.com/ethereum/EIPs/blob/master/EIPS/eip-778.md

{.push raises: [], gcsafe.}

import
  std/[strutils, sequtils, macros, algorithm, net],
  nimcrypto/[keccak, utils],
  stew/base64,
  results,
  chronicles,
  ../rlp,
  ../common/keys,
  ../net/utils

export results, rlp, keys

const
  maxEnrSize = 300  ## Maximum size of an encoded node record, in bytes.
  minRlpListLen = 4 ## Minimum node record RLP list has: signature, seqId,
  ## "id" key and value.
  PreDefinedKeys = ["id", "secp256k1", "ip", "ip6", "tcp", "tcp6", "udp", "udp6"]
  ## Predefined keys in the ENR spec, these have specific constraints on the
  ## type of the associated value.

type
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

  FieldPair* = (string, Field)

  Record* = object
    seqNum*: uint64 ## ENR sequence number
    pairs*: seq[FieldPair] ## List of all key:value pairs. List must have
    ## at least the id k:v pair and the secp256k1 k:v pair. The list of pairs
    ## must remain sorted and without duplicate keys. Use the insert func to
    ## ensure this.
    raw*: seq[byte] ## RLP encoded record
    publicKey*: PublicKey ## Public key of the record

  EnrUri* = distinct string

  # TODO: I think it makes more sense to have the directly usable types for the
  # fields here because in its current for you might as well just access the
  # pairs in a Record directly. This would break the current API unless the type
  # gets renamed.
  TypedRecord* = object
    id*: string
    secp256k1*: Opt[array[33, byte]] # compressed secp256k1 public key
    ip*: Opt[array[4, byte]]
    ip6*: Opt[array[16, byte]]
    tcp*: Opt[int]
    udp*: Opt[int]
    tcp6*: Opt[int]
    udp6*: Opt[int]

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

func `==`(a, b: Field): bool =
  if a.kind == b.kind:
    case a.kind
    of kString:
      a.str == b.str
    of kNum:
      a.num == b.num
    of kBytes:
      a.bytes == b.bytes
    of kList:
      a.listRaw == b.listRaw
  else:
    false

template toFieldPair*(key: string, value: auto): FieldPair =
  (key, toField(value))

func cmp(a, b: FieldPair): int = cmp(a[0], b[0])

func hasPredefinedKey(pair: FieldPair): bool =
  PreDefinedKeys.contains(pair[0])

func hasPredefinedKey(pairs: openArray[FieldPair]): bool =
  for pair in pairs:
    if hasPredefinedKey(pair):
      return true
  false

func find(pairs: openArray[FieldPair], key: string): Opt[int] =
  ## Search for key in key:value pairs.
  ##
  ## Returns some(index of key) if key is found. Else returns none.
  for i, (k, v) in pairs:
    if k == key:
      return Opt.some(i)
  Opt.none(int)

func insert(pairs: var seq[FieldPair], item: FieldPair) =
  ## Insert item in key:value pairs.
  ##
  ## If a FieldPair with key is already present, the value is updated, otherwise
  ## the pair is inserted in the correct position to keep the pairs sorted.
  let index = find(pairs, item[0])
  if index.isSome():
    pairs[index.get()] = item
  else:
    pairs.insert(item, pairs.lowerBound(item, cmp))

func insert(pairs: var seq[FieldPair], b: openArray[FieldPair]) =
  ## Insert all items in key:value pairs.
  for item in b:
    pairs.insert(item)

func makeEnrRaw(
    seqNum: uint64, pk: PrivateKey,
    pairs: openArray[FieldPair]): EnrResult[seq[byte]] =
  func append(
      w: var RlpWriter, seqNum: uint64,
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

  let content =
    block:
      var w = initRlpList(pairs.len * 2 + 1)
      w.append(seqNum, pairs)

  let signature = signNR(pk, content)

  let raw =
    block:
      var w = initRlpList(pairs.len * 2 + 2)
      w.append(signature.toRaw())
      w.append(seqNum, pairs)

  if raw.len > maxEnrSize:
    err("Record exceeds maximum size")
  else:
    ok(raw)

func makeEnrAux(
    seqNum: uint64, id: string, pk: PrivateKey,
    pairs: openArray[FieldPair]): EnrResult[Record] =
  var record: Record
  record.pairs = @pairs
  record.seqNum = seqNum

  let pubkey = pk.toPublicKey()

  record.pairs.insert(("id", Field(kind: kString, str: id)))
  record.pairs.insert(("secp256k1",
    Field(kind: kBytes, bytes: @(pubkey.toRawCompressed()))))

  record.raw = ? makeEnrRaw(seqNum, pk, record.pairs)
  record.publicKey = pubkey
  ok(record)

macro initRecord*(
    seqNum: uint64, pk: PrivateKey,
    pairs: untyped{nkTableConstr}): untyped {.deprecated: "Please use Record.init instead".} =
  ## Initialize a `Record` with given sequence number, private key and k:v
  ## pairs.
  ##
  ## Can fail in case the record exceeds the `maxEnrSize`.
  # Note: Deprecated as it is flawed. It allows for any type to be stored in the
  # predefined keys. It also allows for duplicate keys (which could be fixed)
  # and no longer sorts the pairs. It can however be moved and used for testing
  # purposes.

  for c in pairs:
    c.expectKind(nnkExprColonExpr)
    c[1] = newCall(bindSym"toField", c[1])

  result = quote do:
    makeEnrAux(`seqNum`, "v4", `pk`, `pairs`)

func insertAddress(
    fields: var seq[FieldPair],
    ip: Opt[IpAddress],
    tcpPort, udpPort: Opt[Port]) =
  ## Insert address data.
  ## Incomplete address information is allowed (example: Port but not IP) as
  ## that information might be already in the ENR or added later.
  if ip.isSome():
    case ip.value.family
    of IPv4:
      fields.insert(("ip", ip.value.address_v4.toField))
    of IPv6:
      fields.insert(("ip6", ip.value.address_v6.toField))

  if tcpPort.isSome():
    fields.insert(("tcp", tcpPort.get().uint16.toField))
  if udpPort.isSome():
    fields.insert(("udp", udpPort.get().uint16.toField))

func init*(
    T: type Record,
    seqNum: uint64, pk: PrivateKey,
    ip: Opt[IpAddress] = Opt.none(IpAddress),
    tcpPort: Opt[Port] = Opt.none(Port),
    udpPort: Opt[Port] = Opt.none(Port),
    extraFields: openArray[FieldPair] = []):
    EnrResult[T] =
  ## Initialize a `Record` with given sequence number, private key, optional
  ## ip address, tcp port, udp port, and optional custom k:v pairs.
  ##
  ## Can fail in case the record exceeds the `maxEnrSize`.
  doAssert(not hasPredefinedKey(extraFields), "Predefined key in custom pairs")

  var fields = newSeq[FieldPair]()

  fields.insertAddress(ip, tcpPort, udpPort)
  fields.insert extraFields
  makeEnrAux(seqNum, "v4", pk, fields)

func getField(r: Record, name: string, field: var Field): bool =
  # It might be more correct to do binary search,
  # as the fields are sorted, but it's unlikely to
  # make any difference in reality.
  for (k, v) in r.pairs:
    if k == name:
      field = v
      return true
  false

func requireKind(f: Field, kind: FieldKind): EnrResult[void] =
  if f.kind != kind:
    err("Wrong field kind")
  else:
    ok()

func get*(r: Record, key: string, T: type): EnrResult[T] =
  ## Get the value from the provided key.
  var f: Field
  if r.getField(key, f):
    when T is SomeInteger:
      ? requireKind(f, kNum)
      ok(T(f.num))
    elif T is seq[byte]:
      if requireKind(f, kBytes).isOk:
        ok(f.bytes)
      elif requireKind(f, kList).isOk:
        ok(f.listRaw)
      else:
        err("Invalid rlp type for seq[byte]")
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

func get*(r: Record, T: type PublicKey): Opt[T] =
  ## Get the `PublicKey` from provided `Record`. Return `none` when there is
  ## no `PublicKey` in the record.
  var pubkeyField: Field
  if r.getField("secp256k1", pubkeyField) and pubkeyField.kind == kBytes:
    let pk = PublicKey.fromRaw(pubkeyField.bytes)
    if pk.isOk:
      return Opt.some(pk[])
  Opt.none(T)

func update*(
    record: var Record,
    pk: PrivateKey,
    ip: Opt[IpAddress] = Opt.none(IpAddress),
    tcpPort: Opt[Port] = Opt.none(Port),
    udpPort: Opt[Port] = Opt.none(Port),
    extraFields: openArray[FieldPair] = []):
    EnrResult[void] =
  ## Update a `Record` with given ip address, tcp port, udp port and optional
  ## custom k:v pairs.
  ##
  ## If none of the k:v pairs are changed, the sequence number of the `Record`
  ## will still be incremented and a new signature will be applied.
  ##
  ## Providing an `Opt.none` for `ip`, `tcpPort` or `udpPort` will leave the
  ## corresponding field untouched.
  ##
  ## Can fail in case of wrong `PrivateKey`, if the size of the resulting record
  ## exceeds `maxEnrSize` or if maximum sequence number is reached. The `Record`
  ## will not be altered in these cases.
  # TODO: deprecate this call and have individual functions for updating?
  doAssert(not hasPredefinedKey(extraFields), "Predefined key in custom pairs")

  var r = record

  let pubkey = r.get(PublicKey)
  if pubkey.isNone() or pubkey.get() != pk.toPublicKey():
    return err("Public key does not correspond with given private key")

  r.pairs.insertAddress(ip, tcpPort, udpPort)
  r.pairs.insert extraFields

  if r.seqNum == high(type r.seqNum): # highly unlikely
    return err("Maximum sequence number reached")
  r.seqNum.inc()

  r.raw = ? makeEnrRaw(r.seqNum, pk, r.pairs)
  record = r

  ok()

func tryGet*(r: Record, key: string, T: type): Opt[T] =
  ## Get the value from the provided key.
  ## Return `none` if the key does not exist or if the value is invalid
  ## according to type `T`.
  get(r, key, T).optValue()

func fromRecord*(T: type TypedRecord, r: Record): T =
  TypedRecord(
    id: r.get("id", string).expect("Record must always have id field"),
    secp256k1: r.tryGet("secp256k1", array[33, byte]),
    ip: r.tryGet("ip", array[4, byte]),
    ip6: r.tryGet("ip6", array[16, byte]),
    tcp: r.tryGet("tcp", int),
    tcp6: r.tryGet("tcp6", int),
    udp: r.tryGet("udp", int),
    udp6: r.tryGet("udp6", int)
  )

func toTypedRecord*(r: Record): EnrResult[TypedRecord] {.deprecated: "Please use TypedRecord.fromRecord instead".} =
  ok(TypedRecord.fromRecord(r))

func contains*(r: Record, fp: (string, seq[byte])): bool =
  # TODO: use FieldPair for this, but that is a bit cumbersome. Perhaps the
  # `get` call can be improved to make this easier.
  let field = r.tryGet(fp[0], seq[byte])
  if field.isSome():
    if field.get() == fp[1]:
      return true
  false

func verifySignatureV4(
    publicKey: PublicKey, sigData: openArray[byte], content: openArray[byte]): EnrResult[void] =
  ## Verify the signature for the "v4" identity scheme
  let signature = ?SignatureNR.fromRaw(sigData)
  let hash = keccak256.digest(content)
  if verify(signature, SkMessage(hash.data), publicKey):
    ok()
  else:
    err("Signature verfication failed")

template rlpResult(body: untyped): auto =
  try:
    body
  except RlpError:
    return err("Invalid RLP list")

func buildRlpContent(bytes: openArray[byte]): EnrResult[seq[byte]] =
  ## Rebuild the encoded RLP content without the signature. This is used to
  ## verify the signature.
  var rlp = rlpFromBytes(bytes)
  let listLen = rlpResult rlp.listLen
  doAssert rlp.enterList()

  # skip signature
  rlpResult rlp.skipElem()

  let content = block:
    var writer = initRlpList(listLen - 1)
    for i in 1 ..< listLen:
      rlpResult:
        writer.appendRawBytes(rlp.rawData)
        rlp.skipElem()
    writer.finish()

  ok(content)

func fromBytesAux(T: type Record, s: openArray[byte]): EnrResult[T] =
  ## Creates ENR from rlp-encoded bytes and verifies the signature.
  if s.len > maxEnrSize:
    return err("Record exceeds maximum size")

  var rlp = rlpFromBytes(s)
  if not rlp.isList:
    return err("Record does not contain valid RLP list")

  let sz = rlpResult rlp.listLen
  if sz < minRlpListLen or sz mod 2 != 0:
    return err("Wrong RLP list length")

  # We already know we are working with a list
  doAssert rlp.enterList()

  let
    signatureRaw = rlpResult rlp.read(seq[byte])
    seqNum = rlpResult rlp.read(uint64)
    numPairs = (sz - 2) div 2

  var
    pairs = newSeqOfCap[FieldPair](numPairs)
    id: string = ""
    pkRaw = Opt.none(seq[byte])

  for i in 0 ..< numPairs:
    let k = rlpResult rlp.read(string)
    case k
    of "id":
      id = rlpResult rlp.read(string)
      pairs.add((k, Field(kind: kString, str: id)))
    of "secp256k1":
      pkRaw = Opt.some rlpResult rlp.read(seq[byte])
      pairs.add((k, Field(kind: kBytes, bytes: pkRaw.value())))
    of "tcp", "udp", "tcp6", "udp6":
      let v = rlpResult rlp.read(uint16)
      pairs.add((k, Field(kind: kNum, num: v)))
    else:
      # Don't know really what this is supposed to represent so drop it in
      # `kBytes` field pair when a single byte or blob.
      if rlp.isSingleByte() or rlp.isBlob():
        let bytes = rlpResult rlp.read(seq[byte])
        pairs.add((k, Field(kind: kBytes, bytes: bytes)))
      elif rlp.isList():
        # Not supporting decoding lists as value (especially unknown ones),
        # just drop the raw RLP value in there.
        pairs.add((k, Field(kind: kList, listRaw: @(rlpResult rlp.rawData()))))
        # Need to skip the element still.
        rlpResult rlp.skipElem()

  # Storing the PublicKey in the Record as `fromRaw` is relatively expensive.
  let pk: PublicKey =
    case id
      of "":
        return err("No id k:v pair in the ENR")
      of "v4":
        let content = ?buildRlpContent(s)
        if pkRaw.isNone():
          return err("No secp256k1 k:v pair in the ENR")
        let pk = ?PublicKey.fromRaw(pkRaw.value())
        ?verifySignatureV4(pk, signatureRaw, content)
        pk
      else:
        return err("Unknown Identity Scheme")

  ok(Record(
    seqNum: seqNum,
    pairs: pairs,
    raw: @s,
    publicKey: pk
  ))

func fromBytes*(T: type Record, s: openArray[byte]): EnrResult[T] =
  ## Creates ENR from rlp-encoded bytes and verifies the signature.
  Record.fromBytesAux(s)

func fromBytes*(r: var Record, s: openArray[byte]): bool {.deprecated: "Use the Result[Record] version instead".} =
  ## Loads ENR from rlp-encoded bytes and verifies the signature.
  r = Record.fromBytes(s).valueOr:
    return false
  true


func fromBase64*(T: type Record, s: string): EnrResult[T] =
  ## Creates ENR from base64-encoded rlp-encoded bytes and verifies the
  ## signature.
  let rlpRaw =
    try:
      Base64Url.decode(s)
    except Base64Error:
      return err("Base64 decoding error")

  Record.fromBytesAux(rlpRaw)

func fromBase64*(r: var Record, s: string): bool {.deprecated: "Use the Result[Record] version instead".} =
  ## Loads ENR from base64-encoded rlp-encoded bytes and verifies the
  ## signature.
  r = Record.fromBase64(s).valueOr:
    return false
  true

func fromURI*(T: type Record, s: string): EnrResult[T] =
  ## Creates ENR from its URI encoding: base64-encoded rlp-encoded bytes,
  ## prefixed with "enr:". Verifies the signature.
  const prefix = "enr:"
  if s.startsWith(prefix):
    Record.fromBase64(s[prefix.len .. ^1])
  else:
    err("Invalid URI prefix")

func toBase64*(r: Record): string =
  Base64Url.encode(r.raw)

func toURI*(r: Record): string = "enr:" & r.toBase64

func `$`(f: Field): string =
  case f.kind
  of kNum:
    $f.num
  of kBytes:
    "0x" & f.bytes.toHex
  of kString:
    "\"" & f.str & "\""
  of kList:
    "(Raw RLP list) " & "0x" & f.listRaw.toHex

func `$`*(fp: FieldPair): string =
  fp[0] & ":" & $fp[1]

func `$`*(r: Record): string =
  var res = "("
  res &= $r.seqNum
  for (k, v) in r.pairs:
    res &= ", "
    res &= k
    res &= ": "
    # For IP addresses we print something prettier than the default kinds
    # Note: Could disallow for invalid IPs in ENR also.
    if k == "ip":
      let ip = r.tryGet("ip", array[4, byte])
      if ip.isSome():
        res &= $ipv4(ip.get())
      else:
        res &= "(Invalid) " & $v
    elif k == "ip6":
      let ip = r.tryGet("ip6", array[16, byte])
      if ip.isSome():
        res &= $ipv6(ip.get())
      else:
        res &= "(Invalid) " & $v
    else:
      res &= $v
  res &= ')'

  res

func `==`*(a, b: Record): bool = a.raw == b.raw

func read*(
    rlp: var Rlp, T: type Record):
    T {.raises: [RlpError].} =
  if not rlp.hasData():
    raise newException(RlpError, "Empty RLP data")

  let res = T.fromBytes(rlp.rawData())
  if res.isErr:
    raise newException(RlpError, $res.error)

  rlp.skipElem()

  res.value

func append*(rlpWriter: var RlpWriter, value: Record) =
  rlpWriter.appendRawBytes(value.raw)

chronicles.formatIt(seq[FieldPair]): $it
