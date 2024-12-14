import
  std/options,
  pkg/results,
  stew/[arraybuf, assign2, bitops2, shims/macros],
  ./priv/defs,
  utils

type
  ListAndPrefixLengths = tuple[listLengths, prefixLengths: seq[int]]
  RlpLengthTracker* = object
    prefixLengths*: seq[int]
    listLengths*: seq[int]
    pendingLists: seq[tuple[idx, remainingItems, startLen: int]]
    listCount: int
    totalLength*: int

proc calculateListPrefix(listLen, prefixLen: int): seq[byte] =
  var prefix = newSeqOfCap[byte](1) # prefix min length is 1
  prefix.setLen(prefixLen)

  if listLen < THRESHOLD_LIST_LEN:
    prefix[0] = LIST_START_MARKER + byte(listLen)
  else:
    let listLenBytes = prefixLen - 1
    prefix[0] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)
    prefix.writeBigEndian(uint64(listLen), listLenBytes, listLenBytes)

  move(prefix)

proc maybeClosePendingLists(self: var RlpLengthTracker) =
  while self.pendingLists.len > 0:
    let lastIdx = self.pendingLists.len - 1
    self.pendingLists[lastIdx].remainingItems -= 1

    if self.pendingLists[lastIdx].remainingItems == 0:
      let listIdx = self.pendingLists[lastIdx].idx
      let startLen = self.pendingLists[lastIdx].startLen

      let listLen = self.totalLength - startLen

      let prefixLen = if listLen < int(THRESHOLD_LIST_LEN): 1
                        else: int(uint64(listLen).bytesNeeded) + 1

      # save the list lengths and prefix lengths
      self.listLengths[listIdx] = listLen
      self.prefixLengths[listIdx] = prefixLen

      #TODO: extend the lists if they cross length of 50 by 50.

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

  # TODO: Don't hardcode 50

  # we preset the lengths since we want to skip using add method for
  # these lists
  result.prefixLengths = newSeqOfCap[int](50)
  result.prefixLengths.setLen(50)
  result.listLengths = newSeqOfCap[int](50)
  result.listLengths.setLen(50)

template finish*(self: RlpLengthTracker): ListAndPrefixLengths =
  doAssert self.pendingLists.len == 0, "Insufficient number of elements written to a started list"
  (self.listLengths, self.prefixLengths)

func clear*(w: var RlpLengthTracker) =
  # Prepare writer for reuse
  w.pendingLists.setLen(0)
  w.prefixLengths.setLen(0)
  w.listLengths.setLen(0)
