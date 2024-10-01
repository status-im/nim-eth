# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/typetraits, json_serialization, ./eth_types

export json_serialization

export eth_types
  except BlockHeader, BlockNumber, BlockNonce, BloomFilter, Hash256, StorageKey

# This module contains "convenience formatting" for logging `eth_types` - this
# formatting does not conform to any particular Ethereum-based standard - in
# particular, it does not conform to the JSON-RPC conventions which instead
# can be found in `nim-web3`.

proc writeValue*(w: var JsonWriter, a: Address) {.raises: [IOError].} =
  w.writeValue $a

proc readValue*(
    r: var JsonReader, a: var Address
) {.inline, raises: [IOError, SerializationError].} =
  try:
    a = fromHex(type(a), r.readValue(string))
  except ValueError:
    raiseUnexpectedValue(r, "Hex string expected")

proc writeValue*(w: var JsonWriter, a: Hash32) {.raises: [IOError].} =
  w.writeValue $a

proc readValue*(
    r: var JsonReader, a: var Hash32
) {.inline, raises: [IOError, SerializationError].} =
  try:
    a = fromHex(type(a), r.readValue(string))
  except ValueError:
    raiseUnexpectedValue(r, "Hex string expected")

proc writeValue*(w: var JsonWriter, a: FixedBytes) {.raises: [IOError].} =
  w.writeValue $a

proc readValue*[N](
    r: var JsonReader, a: var FixedBytes[N]
) {.inline, raises: [IOError, SerializationError].} =
  try:
    a = fromHex(type(a), r.readValue(string))
  except ValueError:
    raiseUnexpectedValue(r, "Hex string expected")

proc writeValue*(w: var JsonWriter, value: StUint) {.inline, raises: [IOError].} =
  w.writeValue $value

proc readValue*(
    r: var JsonReader, value: var StUint
) {.inline, raises: [IOError, SerializationError].} =
  value = parse(r.readValue(string), type(value))

proc writeValue*(w: var JsonWriter, t: EthTime) {.inline, raises: [IOError].} =
  w.writeValue distinctBase(t)

proc readValue*(
    r: var JsonReader, t: var EthTime
) {.inline, raises: [IOError, SerializationError].} =
  t = EthTime r.readValue(uint64)

proc writeValue*(w: var JsonWriter, value: BlockHashOrNumber) {.raises: [IOError].} =
  w.writeValue $value

proc readValue*(
    r: var JsonReader, value: var BlockHashOrNumber
) {.raises: [IOError, SerializationError].} =
  try:
    value = init(BlockHashOrNumber, r.readValue(string))
  except ValueError:
    r.raiseUnexpectedValue(
      "A hex-encoded block hash or a decimal block number expected"
    )
