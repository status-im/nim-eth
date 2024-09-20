# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[times, net],
  json_serialization, nimcrypto/[hash, utils],
  ./eth_types

export
  json_serialization

proc writeValue*(w: var JsonWriter, a: MDigest) {.raises: [IOError].} =
  w.writeValue a.data.toHex(true)

proc readValue*(
    r: var JsonReader, a: var MDigest
) {.inline, raises: [IOError, SerializationError].} =
  try:
    a = fromHex(type(a), r.readValue(string))
  except ValueError:
    raiseUnexpectedValue(r, "Hex string expected")

proc writeValue*(
    w: var JsonWriter, value: StUint) {.inline, raises: [IOError].} =
  w.writeValue $value

proc readValue*(
    r: var JsonReader, value: var StUint
) {.inline, raises: [IOError, SerializationError].} =
  value = parse(r.readValue(string), type(value))

proc writeValue*(w: var JsonWriter, value: StInt) {.raises: [IOError].} =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.error: "RLP serialization of signed integers is not allowed".}
  discard

proc writeValue*(w: var JsonWriter, t: Time) {.inline, raises: [IOError].} =
  w.writeValue t.toUnix()

proc readValue*(
    r: var JsonReader, t: var Time
) {.inline, raises: [IOError, SerializationError].} =
  t = fromUnix r.readValue(int)

proc writeValue*(
    w: var JsonWriter, value: BlockHashOrNumber) {.raises: [IOError].} =
  w.writeValue $value

proc readValue*(
    r: var JsonReader, value: var BlockHashOrNumber
) {.raises: [IOError, SerializationError].} =
  try:
    value = init(BlockHashOrNumber, r.readValue(string))
  except ValueError:
    r.raiseUnexpectedValue("A hex-encoded block hash or a decimal block number expected")
