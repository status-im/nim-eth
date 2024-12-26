import
  std/options,
  pkg/results,
  stew/[arraybuf, shims/macros],
  ./priv/defs,
  utils

type
  RlpLengthTracker*[N: static int] = object
    lengths*: seq[tuple[listLen, prefixLen: int]]
    pendingLists: array[N, tuple[idx, remainingItems, startLen: int]]
    listTop: int
    listCount: int
    totalLength*: int

const LIST_LENGTH = 50

proc maybeClosePendingLists(self: var RlpLengthTracker) =
  while self.listTop > 0:
    self.pendingLists[self.listTop - 1].remainingItems -= 1

    if self.pendingLists[self.listTop - 1].remainingItems == 0:
      let 
        listIdx = self.pendingLists[self.listTop - 1].idx
        startLen = self.pendingLists[self.listTop - 1].startLen
        listLen = self.totalLength - startLen
        prefixLen = if listLen < int(THRESHOLD_LIST_LEN): 1
                      else: int(uint64(listLen).bytesNeeded) + 1

      # save the list lengths and prefix lengths
      self.lengths[listIdx] = (listLen, prefixLen)

      # close the list by deleting
      self.listTop -= 1

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
    self.pendingLists[self.listTop] = (self.listCount, listSize, self.totalLength)
    self.listTop += 1
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

func initLengthTracker*(self: var RlpLengthTracker) =
  # we preset the lengths since we want to skip using add method for
  # these lists
  self.lengths = newSeq[(int, int)](LIST_LENGTH)

template finish*(self: RlpLengthTracker): int =
  self.totalLength

func clear*(w: var RlpLengthTracker) =
  # Prepare writer for reuse
  w.lengths.setLen(0)
