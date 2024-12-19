import
  std/options,
  pkg/results,
  stew/[arraybuf, shims/macros],
  ./priv/defs,
  utils

type
  RlpLengthTracker* = object
    lengths*: seq[tuple[listLen, prefixLen: int]]
    pendingLists: seq[tuple[idx, remainingItems, startLen: int]]
    listCount: int
    totalLength*: int

const LIST_LENGTH = 50

proc maybeClosePendingLists(self: var RlpLengthTracker) =
  while self.pendingLists.len > 0:
    let lastIdx = self.pendingLists.len - 1
    self.pendingLists[lastIdx].remainingItems -= 1

    if self.pendingLists[lastIdx].remainingItems == 0:
      let 
        listIdx = self.pendingLists[lastIdx].idx
        startLen = self.pendingLists[lastIdx].startLen
        listLen = self.totalLength - startLen
        prefixLen = if listLen < int(THRESHOLD_LIST_LEN): 1
                      else: int(uint64(listLen).bytesNeeded) + 1

      # save the list lengths and prefix lengths
      self.lengths[listIdx] = (listLen, prefixLen)

      # close the list by deleting
      self.pendingLists.setLen(lastIdx)

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
    self.pendingLists.add((self.listCount, listSize, self.totalLength))
    self.listCount += 1
    if self.listCount == self.lengths.len:
      self.lengths.setLen(self.lengths.len + LIST_LENGTH)

func lengthCount(count: int): int {.inline.} =
  return if count < THRESHOLD_LIST_LEN: 1 
          else: uint64(count).bytesNeeded + 1

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

func initLengthTracker*(): RlpLengthTracker =
  # we preset the lengths since we want to skip using add method for
  # these lists
  result.lengths = newSeq[(int, int)](LIST_LENGTH)

template finish*(self: RlpLengthTracker): int =
  doAssert self.pendingLists.len == 0, 
    "Insufficient number of elements written to a started list"
  self.totalLength

func clear*(w: var RlpLengthTracker) =
  # Prepare writer for reuse
  w.pendingLists.setLen(0)
  w.lengths.setLen(0)
