import
  times,
  json_serialization, nimcrypto/hash, eth_types

proc writeValue*(w: var JsonWriter, a: MDigest) {.inline.} =
  w.writeValue $a

proc readValue*(r: var JsonReader, a: var MDigest) {.inline.} =
  a = fromHex(type(a), r.readValue(string))

proc writeValue*(w: var JsonWriter, value: StUint) {.inline.} =
  w.writeValue $value

proc readValue*(r: var JsonReader, value: var StUint) {.inline.} =
  value = parse(r.readValue(string), type(value))

proc writeValue*(w: var JsonWriter, value: Stint) =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.error: "RLP serialization of signed integers is not allowed".}
  discard

proc writeValue*(w: var JsonWriter, t: Time) {.inline.} =
  w.writeValue t.toUnix()

proc readValue*(r: var JsonReader, t: var Time) {.inline.} =
  t = fromUnix r.readValue(int)

# TODO: remove this once case object are fully supported
# by the serialization library
proc writeValue*(w: var JsonWriter, value: HashOrNum) =
  w.beginRecord(HashOrNum)
  w.writeField("isHash", value.isHash)
  if value.isHash:
    w.writeField("hash", value.hash)
  else:
    w.writeField("number", value.number)
  w.endRecord()

