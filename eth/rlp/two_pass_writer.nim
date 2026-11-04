# eth
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import stew/endians2, ./priv/defs, utils, length_writer

type RlpTwoPassWriter* = object
  output*: seq[byte]
  lengths*: ListLengths
  wrapLengths*: seq[int]
  fillLevel: int
  listCount: int
  wrapCount: int

template update(self: var RlpTwoPassWriter, data: byte) =
  self.output[self.fillLevel] = data
  self.fillLevel += 1

template checkSpace(self: RlpTwoPassWriter, n: int) =
  if self.output.len - self.fillLevel < n:
    raiseAssert "RLP output overflow: the length and the write pass disagree"

template update(self: var RlpTwoPassWriter, data: openArray[byte]) =
  if data.len > 0:
    self.checkSpace(data.len)
    copyMem(addr self.output[self.fillLevel], unsafeAddr data[0], data.len)
    self.fillLevel += data.len

template updateBigEndian(self: var RlpTwoPassWriter, i: SomeUnsignedInt, length: int) =
  self.fillLevel += length
  self.output.writeBigEndian(i, self.fillLevel - 1, length)

func writeLength(writer: var RlpTwoPassWriter, dataLen: int, baseMarker: byte) =
  if dataLen < THRESHOLD_LEN:
    writer.update(baseMarker + byte(dataLen))
  else:
    let lenBytes = uint64(dataLen).bytesNeeded
    writer.update(baseMarker + (THRESHOLD_LEN - 1) + byte(lenBytes))
    writer.updateBigEndian(uint64(dataLen), lenBytes)

func writeInt*(writer: var RlpTwoPassWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    writer.update BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    writer.update byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeLength(bytesNeeded, BLOB_START_MARKER)
    writer.updateBigEndian(uint64(i), bytesNeeded)

template appendRawBytes*(writer: var RlpTwoPassWriter, bytes: openArray[byte]) =
  writer.update(bytes)

proc writeBlob*(writer: var RlpTwoPassWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    writer.update byte(bytes[0])
  else:
    writer.writeLength(bytes.len, BLOB_START_MARKER)
    writer.appendRawBytes(bytes)

template appendDetached*(writer: var RlpTwoPassWriter, bytes: openArray[byte]) =
  writer.update(bytes)

  # INFO: normally we would update the list and wrap counters but this proc avoids that
  # for special cases like transaction types
  # self.decrementCounters(false)

template appendDetached*(writer: var RlpTwoPassWriter, data: byte) =
  writer.update(data)

  # INFO: normally we would update the list and wrap counters but this proc avoids that
  # for special cases like transaction types
  # self.decrementCounters(false)

proc startList*(writer: var RlpTwoPassWriter, listSize: int) =
  mixin writeCount

  if listSize == 0:
    writer.writeLength(0, LIST_START_MARKER)
  else:
    let listLen = writer.lengths[writer.listCount]

    writer.listCount += 1

    writer.writeLength(listLen, LIST_START_MARKER)

proc wrapEncoding*(self: var RlpTwoPassWriter, numOfEncodings: int) =
  let encodingLen = self.wrapLengths[self.wrapCount]

  self.wrapCount += 1

  if encodingLen == 0:
    return # do nothing because nested encoding of a single byte <128 is the byte itself

  self.writeLength(encodingLen, BLOB_START_MARKER)

func initTwoPassWriter*(tracker: var RlpLengthTracker): RlpTwoPassWriter =
  # every byte is written by the second pass
  result.output = newSeqUninit[byte](tracker.totalLength)
  result.lengths = move(tracker.lengths)
  result.wrapLengths = move(tracker.wrapLengths)

func reInit*(self: var RlpTwoPassWriter, tracker: var RlpLengthTracker) =
  self.output.setLen(tracker.totalLength)
  self.lengths = move(tracker.lengths)
  self.wrapLengths = move(tracker.wrapLengths)

template finish*(self: RlpTwoPassWriter): seq[byte] =
  self.output

func clear*(self: var RlpTwoPassWriter) =
  # Prepare writer for reuse
  self.lengths.clear()
  self.wrapLengths.setLen(0)
  self.output.setLen(0)
  self.listCount = 0
  self.wrapCount = 0
  self.fillLevel = 0
