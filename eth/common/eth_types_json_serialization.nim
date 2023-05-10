# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[times, net],
  json_serialization, nimcrypto/[hash, utils],
  ./eth_types

export
  json_serialization

{.push raises: [SerializationError, IOError].}

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

proc writeValue*(w: var JsonWriter, value: StInt) =
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

