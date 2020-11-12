import
  times, net,
  json_serialization, nimcrypto/[hash, utils], eth_types

export
  json_serialization

{.push raises: [SerializationError, IOError, Defect].}

proc writeValue*(w: var JsonWriter, a: MDigest) =
  w.writeValue a.data.toHex(true)

proc readValue*(r: var JsonReader, a: var MDigest) {.inline.} =
  try:
    a = fromHex(type(a), r.readValue(string))
  except ValueError:
    raiseUnexpectedValue(r, "Hex string expected")

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

proc writeValue*(w: var JsonWriter, value: BlockHashOrNumber) =
  w.writeValue $value

proc readValue*(r: var JsonReader, value: var BlockHashOrNumber) =
  try:
    value = init(BlockHashOrNumber, r.readValue(string))
  except ValueError:
    r.raiseUnexpectedValue("A hex-encoded block hash or a decimal block number expected")

