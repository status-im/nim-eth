# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import stew/[arraybuf, assign2], ./priv/defs, utils

const MAX_PENDING_LISTS = 10

type RlpArrayBufWriter*[N: static int] = object
  pendingLists: ArrayBuf[MAX_PENDING_LISTS, tuple[remainingItems, startPos: int]]
  output: ArrayBuf[N, byte]

func writeCount(writer: var RlpArrayBufWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LEN:
    writer.output.add(baseMarker + byte(count))
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    writer.output.add baseMarker + (THRESHOLD_LEN - 1) + byte(lenPrefixBytes)

    writer.output.setLen(writer.output.len + lenPrefixBytes)
    writer.output.writeBigEndian(uint64(count), writer.output.len - 1, lenPrefixBytes)

proc maybeClosePendingLists(self: var RlpArrayBufWriter) =
  while self.pendingLists.len > 0:
    let lastListIdx = self.pendingLists.len - 1
    doAssert self.pendingLists[lastListIdx].remainingItems > 0

    self.pendingLists[lastListIdx].remainingItems -= 1
    # if one last item is remaining in the list
    if self.pendingLists[lastListIdx].remainingItems == 0:
      # A list have been just finished. It was started in `startList`.
      let listStartPos = self.pendingLists[lastListIdx].startPos
      self.pendingLists.setLen lastListIdx

      let
        listLen = self.output.len - listStartPos
        totalPrefixBytes =
          if listLen < int(THRESHOLD_LEN):
            1
          else:
            int(uint64(listLen).bytesNeeded) + 1

      #Shift the written data to make room for the prefix length
      self.output.setLen(self.output.len + totalPrefixBytes)

      moveMem(
        addr self.output[listStartPos + totalPrefixBytes],
        unsafeAddr self.output[listStartPos],
        listLen,
      )

      # Write out the prefix length
      if listLen < THRESHOLD_LEN:
        self.output[listStartPos] = LIST_START_MARKER + byte(listLen)
      else:
        let listLenBytes = totalPrefixBytes - 1
        self.output[listStartPos] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)

        self.output.writeBigEndian(
          uint64(listLen), listStartPos + listLenBytes, listLenBytes
        )
    else:
      # The currently open list is not finished yet. Nothing to do.
      return

func writeInt*(writer: var RlpArrayBufWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    writer.output.add BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    writer.output.add byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeCount(bytesNeeded, BLOB_START_MARKER)

    writer.output.setLen(writer.output.len + bytesNeeded)
    writer.output.writeBigEndian(i, writer.output.len - 1, bytesNeeded)
  writer.maybeClosePendingLists()

func appendRawBytes*(self: var RlpArrayBufWriter, bytes: openArray[byte]) =
  self.output.setLen(self.output.len + bytes.len)
  assign(
    self.output.buf.toOpenArray(self.output.len - bytes.len, self.output.len - 1), bytes
  )
  self.maybeClosePendingLists()

proc writeBlob*(self: var RlpArrayBufWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    self.output.add byte(bytes[0])
    self.maybeClosePendingLists()
  else:
    self.writeCount(bytes.len, BLOB_START_MARKER)
    self.appendRawBytes(bytes)

proc appendDetached*(writer: var RlpArrayBufWriter, bytes: openArray[byte]) =
  writer.output.setLen(writer.output.len + bytes.len)
  assign(
    writer.output.buf.toOpenArray(writer.output.len - bytes.len, writer.output.len - 1),
    bytes,
  )

  # INFO: normally we would update the list and wrap counters but this proc avoids that
  # for special cases like transaction types
  # writer.maybeClosePendingLists()

proc appendDetached*(writer: var RlpArrayBufWriter, data: byte) =
  writer.output.add(data)

  # INFO: normally we would update the list and wrap counters but this proc avoids that
  # for special cases like transaction types
  # writer.maybeClosePendingLists()

proc startList*(self: var RlpArrayBufWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
    self.maybeClosePendingLists()
  else:
    self.pendingLists.add((listSize, self.output.len))

template finish*[N](self: RlpArrayBufWriter[N]): ArrayBuf[N, byte] =
  doAssert self.pendingLists.len == 0,
    "Insufficient number of elements written to a started list"
  self.output

func clear*(w: var RlpArrayBufWriter) =
  # Prepare writer for reuse
  w.pendingLists.setLen(0)
  w.output.setLen(0)
