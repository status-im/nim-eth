# eth
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import stew/endians2, ../keccak/keccak, ./priv/defs, utils, ../common/hashes, length_writer

const BufferSize = 136

type RlpHashWriter* = object
  keccak: keccak.Keccak256
  lengths*: ListLengths
  wrapLengths*: seq[int]
  listCount: int
  wrapCount: int
  buf: array[BufferSize, byte]
  bufLen: int

func update(writer: var RlpHashWriter, data: byte) =
  if writer.bufLen == BufferSize:
    writer.keccak.update(writer.buf)
    writer.bufLen = 0
  writer.buf[writer.bufLen] = data
  writer.bufLen += 1

func update(writer: var RlpHashWriter, data: openArray[byte]) =
  var pos = 0
  if writer.bufLen > 0 or data.len < BufferSize:
    pos = min(BufferSize - writer.bufLen, data.len)
    if pos > 0:
      copyMem(addr writer.buf[writer.bufLen], unsafeAddr data[0], pos)
      writer.bufLen += pos
    if writer.bufLen < BufferSize:
      return
    writer.keccak.update(writer.buf)
    writer.bufLen = 0

  let wholeBlocks = (data.len - pos) div BufferSize * BufferSize
  if wholeBlocks > 0:
    writer.keccak.update(data.toOpenArray(pos, pos + wholeBlocks - 1))
    pos += wholeBlocks

  writer.bufLen = data.len - pos
  if writer.bufLen > 0:
    copyMem(addr writer.buf[0], unsafeAddr data[pos], writer.bufLen)

template updateBigEndian(writer: var RlpHashWriter, i: SomeUnsignedInt, length: int) =
  if length > 0 and writer.bufLen + 8 <= BufferSize:
    let bytes = toBytesBE(uint64(i) shl (8 * (8 - length)))
    copyMem(addr writer.buf[writer.bufLen], unsafeAddr bytes[0], 8)
    writer.bufLen += length
  else:
    let bytes = toBytesBE(uint64(i))
    writer.update(bytes.toOpenArray(bytes.len - length, bytes.high))

func writeLength(writer: var RlpHashWriter, dataLen: int, baseMarker: byte) =
  if dataLen < THRESHOLD_LEN:
    writer.update(baseMarker + byte(dataLen))
  else:
    let lenBytes = uint64(dataLen).bytesNeeded
    writer.update(baseMarker + (THRESHOLD_LEN - 1) + byte(lenBytes))
    writer.updateBigEndian(uint64(dataLen), lenBytes)

func writeInt*(writer: var RlpHashWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    writer.update BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    writer.update byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeLength(bytesNeeded, BLOB_START_MARKER)
    writer.updateBigEndian(uint64(i), bytesNeeded)

template appendRawBytes*(writer: var RlpHashWriter, bytes: openArray[byte]) =
  writer.update(bytes)

proc writeBlob*(writer: var RlpHashWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    writer.update byte(bytes[0])
  else:
    writer.writeLength(bytes.len, BLOB_START_MARKER)
    writer.appendRawBytes(bytes)

template appendDetached*(writer: var RlpHashWriter, bytes: openArray[byte]) =
  writer.update(bytes)

  # INFO: normally we would update the list and wrap counters but this proc avoids that
  # for special cases like transaction types
  # self.decrementCounters(false)

template appendDetached*(writer: var RlpHashWriter, data: byte) =
  writer.update(data)

  # INFO: normally we would update the list and wrap counters but this proc avoids that
  # for special cases like transaction types
  # self.decrementCounters(false)

proc startList*(writer: var RlpHashWriter, listSize: int) =
  mixin writeCount

  if listSize == 0:
    writer.writeLength(0, LIST_START_MARKER)
  else:
    let listLen = writer.lengths[writer.listCount]

    writer.listCount += 1

    writer.writeLength(listLen, LIST_START_MARKER)

proc wrapEncoding*(writer: var RlpHashWriter, numOfEncodings: int) =
  let encodingLen = writer.wrapLengths[writer.wrapCount]

  writer.wrapCount += 1

  if encodingLen == 0:
    return # do nothing because nested encoding of a single byte <128 is the byte itself

  writer.writeLength(encodingLen, BLOB_START_MARKER)

func initHashWriter*(tracker: var RlpLengthTracker): RlpHashWriter =
  result.lengths = move(tracker.lengths)
  result.wrapLengths = move(tracker.wrapLengths)

func reInit*(self: var RlpHashWriter, tracker: var RlpLengthTracker) =
  self.lengths = move(tracker.lengths)
  self.wrapLengths = move(tracker.wrapLengths)

template finish*(self: var RlpHashWriter): Hash32 =
  self.keccak.update(self.buf.toOpenArray(0, self.bufLen - 1))
  self.bufLen = 0
  self.keccak.finish.to(Hash32)

func clear*(self: var RlpHashWriter) =
  # Prepare writer for reuse
  self.lengths.clear()
  self.wrapLengths.setLen(0)
  self.listCount = 0
  self.wrapCount = 0
  self.bufLen = 0
  self.keccak.clear()
