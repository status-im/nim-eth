# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import stew/[bitops2], ./priv/defs

func bytesNeeded*(num: SomeUnsignedInt): int =
  # Number of non-zero bytes in the big endian encoding
  sizeof(num) - (num.leadingZeros() shr 3)

func writeBigEndian*(
    outStream: var auto, number: SomeUnsignedInt, lastByteIdx: int, numberOfBytes: int
) =
  var n = number
  for i in countdown(lastByteIdx, lastByteIdx - numberOfBytes + 1):
    outStream[i] = byte(n and 0xff)
    n = n shr 8

func prefixLength*(dataLen: int): int {.inline.} =
  return
    # if dataLen is one byte(more than 127) or more than a byte len but lesser than threshold
    # length is added to the marker prefix itself - so 1 byte
    if dataLen < THRESHOLD_LEN:
      1
    # if datalen is more than threshold then the length is encoded afte the prefix and
    # the length of the encoded length is added to marker prefix
    else:
      int(uint64(dataLen).bytesNeeded) + 1
