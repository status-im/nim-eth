import stew/[bitops2]

func bytesNeeded*(num: SomeUnsignedInt): int =
  # Number of non-zero bytes in the big endian encoding
  sizeof(num) - (num.leadingZeros() shr 3)

func writeBigEndian*(outStream: var auto, number: SomeUnsignedInt,
                    lastByteIdx: int, numberOfBytes: int) =
  var n = number
  for i in countdown(lastByteIdx, lastByteIdx - numberOfBytes + 1):
    outStream[i] = byte(n and 0xff)
    n = n shr 8


