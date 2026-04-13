# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ./priv/defs, ./utils, ../keccak/keccak, stint

export keccak

func rlpIntEncodedLen*(i: uint64): int {.inline.} =
  if i == 0:
    1 # 0x80 (zero marker)
  elif i < uint64(BLOB_START_MARKER):
    1 # self-encoding single byte
  else:
    let n = i.bytesNeeded
    prefixLength(n) + n

func rlpIntEncodedLen*(i: SomeUnsignedInt): int {.inline.} =
  rlpIntEncodedLen(uint64(i))

func rlpBlobEncodedLen*(data: openArray[byte]): int {.inline.} =
  if data.len == 0:
    1 # 0x80 (empty blob)
  elif data.len == 1 and data[0] < BLOB_START_MARKER:
    1 # self-encoding
  else:
    prefixLength(data.len) + data.len

func rlpBlobEncodedLen*(dataLen: int): int {.inline.} =
  ## Encoded byte length of an RLP blob of `dataLen` bytes, for the case where
  ## the blob is either empty (0 bytes) or known not to be a single self-encoding
  ## byte (i.e. dataLen == 0, dataLen >= 2, or the single byte value >= 0x80).
  ## For the general single-byte case use ``rlpBlobEncodedLen(openArray[byte])``.
  if dataLen == 0: 1
  else: prefixLength(dataLen) + dataLen

func rlpListEncodedLen*(contentLen: int): int {.inline.} =
  prefixLength(contentLen) + contentLen

func uint256SignificantBytes*(v: UInt256): int =
  let bytes = v.toBytesBE
  for i in 0 ..< bytes.len:
    if bytes[i] != 0:
      return bytes.len - i
  1

func rlpUInt256EncodedLen*(v: UInt256): int =
  if v > 128:
    let sigBytes = v.uint256SignificantBytes()
    prefixLength(sigBytes) + sigBytes
  else:
    rlpIntEncodedLen(v.truncate(uint64))

func rlpHashByte*(ctx: var Keccak256, b: byte) {.inline.} =
  ctx.update([b])

func rlpHashLength*(ctx: var Keccak256, dataLen: int, baseMarker: byte) =
  if dataLen < THRESHOLD_LEN:
    ctx.rlpHashByte(baseMarker + byte(dataLen))
  else:
    let bytesNeeded = uint64(dataLen).bytesNeeded
    ctx.rlpHashByte(baseMarker + byte(THRESHOLD_LEN - 1) + byte(bytesNeeded))
    var buf: array[8, byte]
    buf.writeBigEndian(uint64(dataLen), bytesNeeded - 1, bytesNeeded)
    ctx.update(buf.toOpenArray(0, bytesNeeded - 1))

func rlpHashListHeader*(ctx: var Keccak256, contentLen: int) {.inline.} =
  ctx.rlpHashLength(contentLen, LIST_START_MARKER)

func rlpHashBlobHeader*(ctx: var Keccak256, dataLen: int) {.inline.} =
  ctx.rlpHashLength(dataLen, BLOB_START_MARKER)

func rlpHashInt*(ctx: var Keccak256, i: uint64) =
  if i == 0:
    ctx.rlpHashByte(BLOB_START_MARKER)
  elif i < uint64(BLOB_START_MARKER):
    ctx.rlpHashByte(byte(i))
  else:
    let n = i.bytesNeeded
    ctx.rlpHashLength(n, BLOB_START_MARKER)
    var buf: array[8, byte]
    buf.writeBigEndian(i, n - 1, n)
    ctx.update(buf.toOpenArray(0, n - 1))

func rlpHashInt*(ctx: var Keccak256, i: SomeUnsignedInt) {.inline.} =
  ctx.rlpHashInt(uint64(i))

func rlpHashBlob*(ctx: var Keccak256, data: openArray[byte]) =
  if data.len == 0:
    ctx.rlpHashByte(BLOB_START_MARKER)
  elif data.len == 1 and data[0] < BLOB_START_MARKER:
    ctx.rlpHashByte(data[0])
  else:
    ctx.rlpHashLength(data.len, BLOB_START_MARKER)
    ctx.update(data)

func rlpHashUInt256*(ctx: var Keccak256, v: UInt256) =
  if v > 128:
    let bytes = v.toBytesBE   # array[32, byte], stack-allocated
    var sigBytes = bytes.len
    for i in 0 ..< bytes.len:
      if bytes[i] != 0:
        sigBytes = bytes.len - i
        break
    let startIdx = bytes.len - sigBytes
    ctx.rlpHashLength(sigBytes, BLOB_START_MARKER)
    ctx.update(bytes.toOpenArray(startIdx, bytes.len - 1))
  else:
    ctx.rlpHashInt(v.truncate(uint64))

func rlpWriteLength*(
    output: var openArray[byte], pos: var int, dataLen: int, baseMarker: byte
) =
  if dataLen < THRESHOLD_LEN:
    output[pos] = baseMarker + byte(dataLen)
    pos += 1
  else:
    let bytesNeeded = uint64(dataLen).bytesNeeded
    output[pos] = baseMarker + byte(THRESHOLD_LEN - 1) + byte(bytesNeeded)
    pos += 1
    output.writeBigEndian(uint64(dataLen), pos + bytesNeeded - 1, bytesNeeded)
    pos += bytesNeeded

func rlpWriteListHeader*(
    output: var openArray[byte], pos: var int, contentLen: int
) {.inline.} =
  rlpWriteLength(output, pos, contentLen, LIST_START_MARKER)

func rlpWriteBlobHeader*(
    output: var openArray[byte], pos: var int, dataLen: int
) {.inline.} =
  rlpWriteLength(output, pos, dataLen, BLOB_START_MARKER)

func rlpWriteRawBytes*(
    output: var openArray[byte], pos: var int, data: openArray[byte]
) {.inline.} =
  if data.len > 0:
    copyMem(addr output[pos], unsafeAddr data[0], data.len)
    pos += data.len

func rlpWriteInt*(output: var openArray[byte], pos: var int, i: uint64) =
  if i == 0:
    output[pos] = BLOB_START_MARKER
    pos += 1
  elif i < uint64(BLOB_START_MARKER):
    output[pos] = byte(i)
    pos += 1
  else:
    let n = i.bytesNeeded
    rlpWriteLength(output, pos, n, BLOB_START_MARKER)
    output.writeBigEndian(i, pos + n - 1, n)
    pos += n

func rlpWriteInt*(output: var openArray[byte], pos: var int, i: SomeUnsignedInt) {.inline.} =
  rlpWriteInt(output, pos, uint64(i))

func rlpWriteBlob*(output: var openArray[byte], pos: var int, data: openArray[byte]) =
  if data.len == 0:
    output[pos] = BLOB_START_MARKER
    pos += 1
  elif data.len == 1 and data[0] < BLOB_START_MARKER:
    output[pos] = data[0]
    pos += 1
  else:
    rlpWriteLength(output, pos, data.len, BLOB_START_MARKER)
    rlpWriteRawBytes(output, pos, data)

func rlpWriteUInt256*(output: var openArray[byte], pos: var int, v: UInt256) =
  if v > 128:
    let bytes = v.toBytesBE   # array[32, byte], stack-allocated
    var sigBytes = bytes.len
    for i in 0 ..< bytes.len:
      if bytes[i] != 0:
        sigBytes = bytes.len - i
        break
    let startIdx = bytes.len - sigBytes
    rlpWriteLength(output, pos, sigBytes, BLOB_START_MARKER)
    rlpWriteRawBytes(output, pos, bytes.toOpenArray(startIdx, bytes.len - 1))
  else:
    rlpWriteInt(output, pos, v.truncate(uint64))
