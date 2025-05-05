# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import nimcrypto/keccak, ./priv/defs, utils, ../common/hashes, length_writer

type RlpHashWriter* = object
  keccak: keccak.keccak256
  lengths*: seq[int]
  wrapLengths*: seq[int]
  listCount: int
  wrapCount: int
  bigEndianBuf: array[8, byte]

template update(writer: var RlpHashWriter, data: byte) =
  writer.keccak.update([data])

template update(writer: var RlpHashWriter, data: openArray[byte]) =
  writer.keccak.update(data)

template updateBigEndian(writer: var RlpHashWriter, i: SomeUnsignedInt, length: int) =
  writer.bigEndianBuf.writeBigEndian(i, length - 1, length)
  writer.update(writer.bigEndianBuf.toOpenArray(0, length - 1))

func writeLength(writer: var RlpHashWriter, dataLen: int, baseMarker: byte) =
  if dataLen < THRESHOLD_LEN:
    writer.update(baseMarker + byte(dataLen))
  else:
    writer.update(baseMarker + (THRESHOLD_LEN - 1) + byte(uint64(dataLen).bytesNeeded))
    writer.updateBigEndian(uint64(dataLen), uint64(dataLen).bytesNeeded)

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

proc startList*(writer: var RlpHashWriter, listSize: int) =
  mixin writeCount

  if listSize == 0:
    writer.writeLength(0, LIST_START_MARKER)
  else:
    let
      listLen = writer.lengths[writer.listCount]
      prefixLen = prefixLength(listLen)

    writer.listCount += 1

    writer.writeLength(listLen, LIST_START_MARKER)

proc wrapEncoding*(writer: var RlpHashWriter, numOfEncodings: int) =
  let
    encodingLen = writer.wrapLengths[writer.wrapCount]
    prefixLen = prefixLength(encodingLen)

  if encodingLen == 0:
    return # do nothing because nested encoding of a single byte <128 is the byte itself

  writer.wrapCount += 1

  writer.writeLength(encodingLen, BLOB_START_MARKER)

func initHashWriter*(tracker: var RlpLengthTracker): RlpHashWriter =
  result.lengths = move(tracker.lengths)
  result.wrapLengths = move(tracker.wrapLengths)

func reInit*(self: var RlpHashWriter, tracker: var RlpLengthTracker) =
  self.lengths = move(tracker.lengths)
  self.wrapLengths = move(tracker.wrapLengths)

template finish*(self: var RlpHashWriter): Hash32 =
  self.keccak.finish.to(Hash32)

func clear*(self: var RlpHashWriter) =
  # Prepare writer for reuse
  self.reset()
