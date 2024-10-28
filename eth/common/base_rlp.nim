# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/typetraits, ./base, ../rlp, 
  ../rlp/options as rlp_options

export base, rlp, rlp_options


template read*[T](rlp: var Rlp, val: var T) =
  mixin read
  val = rlp.read(type val)

proc read*(rlp: var Rlp, T: type StUint): T {.raises: [RlpError].} =
  if rlp.isBlob:
    let bytes = rlp.toBytes
    if bytes.len > 0:
      # be sure the amount of bytes matches the size of the stint
      if bytes.len <= sizeof(result):
        result.initFromBytesBE(bytes)
      else:
        raise newException(
          RlpTypeMismatch,
          "Unsigned integer expected, but the source RLP has the wrong length",
        )
    else:
      result = 0.to(T)
  else:
    raise newException(
      RlpTypeMismatch, "Unsigned integer expected, but the source RLP is a list"
    )

  rlp.skipElem

func significantBytesBE(val: openArray[byte]): int =
  ## Returns the number of significant trailing bytes in a big endian
  ## representation of a number.
  for i in 0 ..< val.len:
    if val[i] != 0:
      return val.len - i
  return 1

proc append*(w: var RlpWriter, value: StUint) =
  if value > 128:
    let bytes = value.toByteArrayBE
    let nonZeroBytes = significantBytesBE(bytes)
    w.append bytes.toOpenArray(bytes.len - nonZeroBytes, bytes.len - 1)
  else:
    w.append(value.truncate(uint))

proc read*(rlp: var Rlp, T: type StInt): T =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.fatal: "RLP serialization of signed integers is not allowed".}
  discard

proc append*(w: var RlpWriter, value: StInt) =
  # The Ethereum Yellow Paper defines the RLP serialization only
  # for unsigned integers:
  {.fatal: "RLP serialization of signed integers is not allowed".}
  discard

proc append*(w: var RlpWriter, val: FixedBytes) =
  mixin append
  w.append(val.data())

proc read*[N: static int](
    rlp: var Rlp, T: type FixedBytes[N]
): T {.raises: [RlpError].} =
  T(rlp.read(type(result.data)))

proc append*(w: var RlpWriter, id: ChainId) =
  w.append(distinctBase id)

proc read*(rlp: var Rlp, T: type ChainId): T {.raises: [RlpError].} =
  T(rlp.read(distinctBase T))

proc append*(w: var RlpWriter, id: NetworkId) =
  w.append(distinctBase id)

proc read*(rlp: var Rlp, T: type NetworkId): T {.raises: [RlpError].} =
  T(rlp.read(distinctBase T))
