# eth
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import ./priv/defs, utils, stacked_counters

const InlineListLengths = 8
  ## Enough for the lists of a transaction or receipt - encoding one then
  ## needs no allocation for its list lengths

type
  PendingListItem = tuple[idx, startLen: int]
  PendingWrapItem = tuple[idx, listIdx, startLen: int]

  ListLengths* = object
    ## The lengths of the lists of an encoding, in the order they start
    count: int
    inline: array[InlineListLengths, int]
    spilled: seq[int]

  StaticRlpLengthTracker*[N: static int] = object
    pendingLists: StaticStackedCounters[N, PendingListItem]
    wrappedEncodings: DynamicStackedCounters[PendingWrapItem]
    lengths*: ListLengths
    wrapLengths*: seq[int]
    totalLength*: int

  DynamicRlpLengthTracker* = object
    pendingLists: DynamicStackedCounters[PendingListItem]
    wrappedEncodings: DynamicStackedCounters[PendingWrapItem]
    lengths*: ListLengths
    wrapLengths*: seq[int]
    totalLength*: int

  RlpLengthTracker* = StaticRlpLengthTracker | DynamicRlpLengthTracker

# this constant sets the initial capacity of the pendingLists stack
const STACK_LENGTH = 5

func len*(s: ListLengths): int =
  s.count

func spill(s: var ListLengths, listLen: int) {.noinline.} =
  if s.spilled.len == 0:
    s.spilled = newSeqOfCap[int](32)
  s.spilled.add listLen

func add*(s: var ListLengths, listLen: int) =
  if s.count < InlineListLengths:
    s.inline[s.count] = listLen
  else:
    s.spill(listLen)
  s.count += 1

func `[]`*(s: ListLengths, i: int): int =
  doAssert i < s.count, "list length index out of bounds"
  if i < InlineListLengths:
    s.inline[i]
  else:
    s.spilled[i - InlineListLengths]

func `[]=`*(s: var ListLengths, i: int, listLen: int) =
  doAssert i < s.count, "list length index out of bounds"
  if i < InlineListLengths:
    s.inline[i] = listLen
  else:
    s.spilled[i - InlineListLengths] = listLen

func clear*(s: var ListLengths) =
  s.count = 0
  s.spilled.setLen(0)

proc processWrapCounter(
    self: var RlpLengthTracker, i: PendingWrapItem, isSelfEncoding: bool
) =
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

proc processListCounter(self: var RlpLengthTracker, i: PendingListItem) =
  let
    listLen = self.totalLength - i.startLen
    prefixLen = prefixLength(listLen)

  # save the list length
  self.lengths[i.idx] = listLen

  # update the total length
  self.totalLength += prefixLen

proc decrementCounters(self: var RlpLengthTracker, isSelfEncoding: bool) =
  if self.wrappedEncodings.isEmpty():
    if self.pendingLists.decrementTop():
      return

    var item: PendingListItem
    while self.pendingLists.pop(item):
      self.processListCounter(item)
    return

  var isSelfEncodingFlag = isSelfEncoding

  # The item just written belongs to the innermost open list or wrapping - each
  # one that it completes is in turn an item of the one around it
  while true:
    # a wrapping is innermost when it was started after the top list
    if not self.wrappedEncodings.isEmpty() and (
        self.pendingLists.isEmpty() or
        self.pendingLists.topItem.idx < self.wrappedEncodings.topItem.listIdx):
      var item: PendingWrapItem
      if not self.wrappedEncodings.pop(item):
        return
      self.processWrapCounter(item, isSelfEncodingFlag)
    else:
      var item: PendingListItem
      if not self.pendingLists.pop(item):
        return
      self.processListCounter(item)

    isSelfEncodingFlag = false

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

    self.lengths.add(0)

# next item encoded will not decrement list or wrap counters

proc wrapEncoding*(self: var RlpLengthTracker, numOfEncodings: int) =
  self.wrappedEncodings.push(
    (self.wrapLengths.len, self.lengths.len, self.totalLength), numOfEncodings
  )
  self.wrapLengths.add(0)

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
    let lenBytes = i.bytesNeeded
    self.totalLength += prefixLength(lenBytes) + lenBytes

  self.decrementCounters(isSelfEncoding)

proc appendDetached*(self: var RlpLengthTracker, bytes: openArray[byte]) =
  self.totalLength += bytes.len

  # INFO: normally we would update the list and wrap counters but this proc avoids that
  # for special cases like transaction types
  # self.decrementCounters(false)

proc appendDetached*(self: var RlpLengthTracker, data: byte) =
  self.totalLength += 1

  # INFO: normally we would update the list and wrap counters but this proc avoids that
  # for special cases like transaction types
  # self.decrementCounters(false)

func initLengthTracker*(self: var RlpLengthTracker) =
  when self is DynamicRlpLengthTracker:
    self.pendingLists.init(STACK_LENGTH, PendingListItem)
  self.lengths.clear()

template finish*(self: RlpLengthTracker): int =
  self.totalLength

func clear*(w: var RlpLengthTracker) =
  # Prepare writer for reuse
  w.lengths.clear()
  w.totalLength = 0
  when w is DynamicRlpLengthTracker:
    w.pendingLists.clear
