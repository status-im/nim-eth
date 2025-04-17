# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import stew/assign2, ./priv/defs, utils, length_writer

type RlpTwoPassWriter* = object
  output*: seq[byte]
  lengths*: seq[int]
  wrapLengths*: seq[int]
  fillLevel: int
  listCount: int
  wrapCount: int

template update(self: var RlpTwoPassWriter, data: byte) =
  self.output[self.fillLevel] = data
  self.fillLevel += 1

template update(self: var RlpTwoPassWriter, data: openArray[byte]) =
  assign(self.output.toOpenArray(self.fillLevel, self.fillLevel + data.len - 1), data)
  self.fillLevel += data.len

template updateBigEndian(self: var RlpTwoPassWriter, i: SomeUnsignedInt, length: int) =
  self.fillLevel += length
  self.output.writeBigEndian(i, self.fillLevel - 1, length)

func writeLength(writer: var RlpTwoPassWriter, dataLen: int, baseMarker: byte) =
  if dataLen < THRESHOLD_LEN:
    writer.update(baseMarker + byte(dataLen))
  else:
    writer.update(baseMarker + (THRESHOLD_LEN - 1) + byte(uint64(dataLen).bytesNeeded))
    writer.updateBigEndian(uint64(dataLen), uint64(dataLen).bytesNeeded)

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

proc startList*(writer: var RlpTwoPassWriter, listSize: int) =
  mixin writeCount

  if listSize == 0:
    writer.writeLength(0, LIST_START_MARKER)
  else:
    let
      listLen = writer.lengths[writer.listCount]
      prefixLen = prefixLength(listLen)

    writer.listCount += 1

    writer.writeLength(listLen, LIST_START_MARKER)

proc wrapEncoding*(self: var RlpTwoPassWriter, numOfEncodings: int) =
  let
    encodingLen = self.wrapLengths[self.wrapCount]
    prefixLen = prefixLength(encodingLen)

  if encodingLen == 0:
    return # do nothing because nested encoding of a single byte <128 is the byte itself

  self.wrapCount += 1

  self.writeLength(encodingLen, BLOB_START_MARKER)

func initTwoPassWriter*(tracker: var RlpLengthTracker): RlpTwoPassWriter =
  result.output = newSeq[byte](tracker.totalLength)
  result.lengths = move(tracker.lengths)
  result.wrapLengths = move(tracker.wrapLengths)

template finish*(self: RlpTwoPassWriter): seq[byte] =
  self.lengths.setLen(0)
  self.wrapLengths.setLen(0)
  self.output

func clear*(self: var RlpTwoPassWriter) =
  # Prepare writer for reuse
  self.lengths.setLen(0)
  self.wrapLengths.setLen(0)
  self.output.setLen(0)
