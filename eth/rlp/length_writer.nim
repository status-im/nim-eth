# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ./priv/defs, utils

type
  PendingListItem = tuple[idx, remainingItems, startLen: int]

  StaticRlpLengthTracker*[N: static int] = object
    pendingLists: array[N, PendingListItem]
    lengths*: seq[int]
    listTop: int
    listCount: int
    totalLength*: int

  DynamicRlpLengthTracker* = object
    pendingLists: seq[PendingListItem]
    lengths*: seq[int]
    listTop: int
    listCount: int
    totalLength*: int

  RlpLengthTracker* = StaticRlpLengthTracker | DynamicRlpLengthTracker

# these constants set the initial capacities of the pendingLists stack and lengths list
const LIST_LENGTH = 5
const STACK_LENGTH = 5

proc maybeClosePendingLists(self: var RlpLengthTracker) =
  while self.listTop > 0:
    self.pendingLists[self.listTop - 1].remainingItems -= 1

    if self.pendingLists[self.listTop - 1].remainingItems == 0:
      let
        listIdx = self.pendingLists[self.listTop - 1].idx
        startLen = self.pendingLists[self.listTop - 1].startLen
        listLen = self.totalLength - startLen
        prefixLen =
          if listLen < int(THRESHOLD_LIST_LEN):
            1
          else:
            int(uint64(listLen).bytesNeeded) + 1

      # save the list lengths and prefix lengths
      self.lengths[listIdx] = listLen

      # close the list by deleting
      self.listTop -= 1
      when self is DynamicRlpLengthTracker:
        self.pendingLists.setLen(self.listTop)

      self.totalLength += prefixLen
    else:
      return

func appendRawBytes*(self: var RlpLengthTracker, bytes: openArray[byte]) =
  self.totalLength += bytes.len
  self.maybeClosePendingLists()

proc startList*(self: var RlpLengthTracker, listSize: int) =
  if listSize == 0:
    self.totalLength += 1
    self.maybeClosePendingLists()
  else:
    # open a list
    when self is DynamicRlpLengthTracker:
      self.pendingLists.setLen(self.listTop + 1)
    self.pendingLists[self.listTop] = (self.lengths.len, listSize, self.totalLength)
    self.listTop += 1
    self.lengths.setLen(self.lengths.len + 1)

proc wrapEncoding*(self: var RlpLengthTracker, numOfEncodings: int) =
  self.startList(numOfEncodings)

func lengthCount(count: int): int {.inline.} =
  return
    if count < THRESHOLD_LIST_LEN:
      1
    else:
      uint64(count).bytesNeeded + 1

func writeBlob*(self: var RlpLengthTracker, data: openArray[byte]) =
  if data.len == 1 and byte(data[0]) < BLOB_START_MARKER:
    self.totalLength += 1
  else:
    self.totalLength += lengthCount(data.len) + data.len
  self.maybeClosePendingLists()

func writeInt*(self: var RlpLengthTracker, i: SomeUnsignedInt) =
  if i < typeof(i)(BLOB_START_MARKER):
    self.totalLength += 1
  else:
    self.totalLength += lengthCount(i.bytesNeeded) + i.bytesNeeded
  self.maybeClosePendingLists()

func initLengthTracker*(self: var RlpLengthTracker) =
  # we preset the lengths since we want to skip using add method for
  # these lists
  when self is DynamicRlpLengthTracker:
    self.pendingLists = newSeqOfCap[(int, int, int)](STACK_LENGTH)
  self.lengths = newSeqOfCap[int](LIST_LENGTH)

template finish*(self: RlpLengthTracker): int =
  self.totalLength

func clear*(w: var RlpLengthTracker) =
  # Prepare writer for reuse
  w.lengths.setLen(0)
  when w is DynamicRlpLengthTracker:
    w.pendingLists.setLen(0)
