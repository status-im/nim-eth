# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ./priv/defs, utils, pkg/results, stacked_counters

type
  PendingListItem = tuple[idx, startLen: int]
  PendingWrapItem = tuple[idx, listIdx, startLen: int]

  StaticRlpLengthTracker*[N: static int] = object
    pendingLists: StaticStackedCounters[N, PendingListItem]
    wrappedEncodings: DynamicStackedCounters[PendingWrapItem]
    lengths*: seq[int]
    wrapLengths*: seq[int]
    totalLength*: int

  DynamicRlpLengthTracker* = object
    pendingLists: DynamicStackedCounters[PendingListItem]
    wrappedEncodings: DynamicStackedCounters[PendingWrapItem]
    lengths*: seq[int]
    wrapLengths*: seq[int]
    totalLength*: int

  RlpLengthTracker* = StaticRlpLengthTracker | DynamicRlpLengthTracker

# these constants set the initial capacities of the pendingLists stack and lengths list
const LIST_LENGTH = 5
const STACK_LENGTH = 5

proc processWrapCounter(
    self: var RlpLengthTracker, item: Opt[PendingWrapItem], isSelfEncoding: bool
): bool =
  if item.isSome():
    let i = item.get()

    var
      encodingLen = self.totalLength - i.startLen
      prefixLen = prefixLength(encodingLen)

    if isSelfEncoding and prefixLen == 1:
      # nested/wrapped encoding of a single byte lesser than 128(BLOB_START_MARKER)
      # is not required the byte itself is its own encoding
      prefixLen = 0
      # NOTE: encoding len is 1 but is set to 0 to differentiate between 
      # single byte <128 versus single byte >=128 on the second pass
      encodingLen = 0

    # save the encoding length
    self.wrapLengths[i.idx] = encodingLen

    # update the total length
    self.totalLength += prefixLen
    return true
  else:
    return false

proc processListCounter(self: var RlpLengthTracker, item: Opt[PendingListItem]): bool =
  if item.isSome():
    let
      i = item.get()
      listLen = self.totalLength - i.startLen
      prefixLen = prefixLength(listLen)

    # save the list length
    self.lengths[i.idx] = listLen

    # update the total length
    self.totalLength += prefixLen

    return true
  else:
    return false

proc decrementCounters(self: var RlpLengthTracker, isSelfEncoding: bool) =
  var
    wrapStatus = true
    listStatus = true
    isSelfEncodingFlag = isSelfEncoding

  # we use a while loop here to close nested wrappings one after the other (if possible)
  while true:
    let
      topListItem = self.pendingLists.peek(PendingListItem).get((0, 0))
      topWrapItem = self.wrappedEncodings.peek(PendingWrapItem).get((0, 0, 0))
      wrapItem =
        # if a wrapped encoding was started just before a list started (AND the list is not yet closed) then do not decrement the counter
        if topListItem.idx < topWrapItem.listIdx and wrapStatus:
          self.wrappedEncodings.pop(PendingWrapItem)
        else:
          Opt.none(PendingWrapItem)

      wrapStatus = self.processWrapCounter(wrapItem, isSelfEncodingFlag)

    let
      listItem =
        if listStatus:
          self.pendingLists.pop(PendingListItem)
        else:
          Opt.none(PendingListItem)

      listStatus = self.processListCounter(listItem)

    isSelfEncodingFlag = false

    if not listStatus and not wrapStatus:
      return

func appendRawBytes*(self: var RlpLengthTracker, bytes: openArray[byte]) =
  self.totalLength += bytes.len
  self.decrementCounters(
    bytes.len == 1 and bytes[0] < BLOB_START_MARKER and bytes[0] > 0
  )

proc startList*(self: var RlpLengthTracker, listSize: int) =
  if listSize == 0:
    self.totalLength += 1
    # empty lists always are encoded as a single byte which >128
    self.decrementCounters(false)
  else:
    # open a list = push a list on the stack with count value as the list size
    self.pendingLists.push((self.lengths.len, self.totalLength), listSize)

    self.lengths.setLen(self.lengths.len + 1)

# next item encoded will not decrement list or wrap counters

proc wrapEncoding*(self: var RlpLengthTracker, numOfEncodings: int) =
  self.wrappedEncodings.push(
    (self.wrapLengths.len, self.lengths.len, self.totalLength), numOfEncodings
  )
  self.wrapLengths.setLen(self.wrapLengths.len + 1)

func writeBlob*(self: var RlpLengthTracker, data: openArray[byte]) =
  let isSelfEncoding = data.len == 1 and byte(data[0]) < BLOB_START_MARKER

  if isSelfEncoding:
    self.totalLength += data.len
  else:
    self.totalLength += prefixLength(data.len) + data.len

  self.decrementCounters(isSelfEncoding)

func writeInt*(self: var RlpLengthTracker, i: SomeUnsignedInt) =
  let isSelfEncoding = i < typeof(i)(BLOB_START_MARKER) and i > typeof(i)(0)

  if isSelfEncoding:
    self.totalLength += 1
  elif i == typeof(i)(0):
    self.totalLength += 1
  else:
    self.totalLength += prefixLength(i.bytesNeeded) + i.bytesNeeded

  self.decrementCounters(isSelfEncoding)

proc appendDetached*(self: var RlpLengthTracker, bytes: openArray[byte]) =
  self.totalLength += bytes.len

  # INFO: normally we would update the list and wrap counters but this method avoids that
  # for special cases like transaction types
  # self.decrementCounters(false)

proc appendDetached*(self: var RlpLengthTracker, data: byte) =
  self.totalLength += 1

  # INFO: normally we would update the list and wrap counters but this method avoids that
  # for special cases like transaction types
  # self.decrementCounters(false)

func initLengthTracker*(self: var RlpLengthTracker) =
  # we preset the lengths since we want to skip using add method for
  # these lists
  when self is DynamicRlpLengthTracker:
    self.pendingLists.init(STACK_LENGTH, PendingListItem)
  self.lengths = newSeqOfCap[int](LIST_LENGTH)

template finish*(self: RlpLengthTracker): int =
  self.totalLength

func clear*(w: var RlpLengthTracker) =
  # Prepare writer for reuse
  w.lengths.setLen(0)
  w.totalLength = 0
  when w is DynamicRlpLengthTracker:
    w.pendingLists.clear
