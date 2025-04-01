# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/options,
  pkg/results,
  nimcrypto/keccak,
  stew/[arraybuf, shims/macros],
  ./priv/defs,
  utils,
  ../common/hashes,
  length_writer

type RlpHashWriter* = object
  keccak: keccak.keccak256
  lengths*: seq[int]
  listCount: int
  bigEndianBuf: array[8, byte]

template update(writer: var RlpHashWriter, data: byte) =
  writer.keccak.update([data])

template update(writer: var RlpHashWriter, data: openArray[byte]) =
  writer.keccak.update(data)

template updateBigEndian(writer: var RlpHashWriter, i: SomeUnsignedInt, length: int) =
  writer.bigEndianBuf.writeBigEndian(i, length - 1, length)
  writer.update(writer.bigEndianBuf.toOpenArray(0, length - 1))

func writeCount(writer: var RlpHashWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    writer.update(baseMarker + byte(count))
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    writer.update baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)

    writer.updateBigEndian(uint64(count), lenPrefixBytes)

func writeInt*(writer: var RlpHashWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    writer.update BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    writer.update byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeCount(bytesNeeded, BLOB_START_MARKER)

    writer.updateBigEndian(uint64(i), bytesNeeded)

template appendRawBytes*(self: var RlpHashWriter, bytes: openArray[byte]) =
  self.update(bytes)

proc writeBlob*(self: var RlpHashWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    self.update byte(bytes[0])
  else:
    self.writeCount(bytes.len, BLOB_START_MARKER)
    self.appendRawBytes(bytes)

proc startList*(self: var RlpHashWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
  else:
    let
      listLen = self.lengths[self.listCount]
      prefixLen =
        if listLen < int(THRESHOLD_LIST_LEN):
          1
        else:
          int(uint64(listLen).bytesNeeded) + 1

    self.listCount += 1

    if listLen < THRESHOLD_LIST_LEN:
      self.update(LIST_START_MARKER + byte(listLen))
    else:
      let listLenBytes = prefixLen - 1
      self.update(LEN_PREFIXED_LIST_MARKER + byte(listLenBytes))

      self.updateBigEndian(uint64(listLen), listLenBytes)

func initHashWriter*(tracker: var RlpLengthTracker): RlpHashWriter =
  result.lengths = move(tracker.lengths)

template finish*(self: var RlpHashWriter): Hash32 =
  self.lengths.setLen(0)
  self.keccak.finish.to(Hash32)

func clear*(w: var RlpHashWriter) =
  # Prepare writer for reuse
  w.lengths.setLen(0)
