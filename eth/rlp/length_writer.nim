import
  std/options,
  pkg/results,
  stew/[arraybuf, assign2, bitops2, shims/macros],
  ./priv/defs,
  utils

type
  TrackerKind* = enum
    RecordLen,
    RecordPrefix

  RlpLengthTracker* = object
    case kind*: TrackerKind
    of RecordLen: listPrefixLen*: seq[int]
    of RecordPrefix: listPrefixBytes*: seq[seq[byte]]
    pendingLists: seq[tuple[idx, remainingItems, length: int]]
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
      let startLen = self.pendingLists[lastIdx].length

      let listLen = self.totalLength - startLen

      let prefixLen = if listLen < int(THRESHOLD_LIST_LEN): 1
                        else: int(uint64(listLen).bytesNeeded) + 1

      # save the prefix
      if self.kind == TrackerKind.RecordPrefix:
        self.listPrefixBytes[listIdx] = calculateListPrefix(listLen, prefixLen)
      else: # take note of the prefix len
        self.listPrefixLen[listIdx] = prefixLen

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
    if self.kind == TrackerKind.RecordLen:
      self.listPrefixLen.add(0)
    else:
      self.listPrefixBytes.add(@[])

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

template finish*(self: RlpLengthTracker): seq[seq[byte]] =
  doAssert self.pendingLists.len == 0, "Insufficient number of elements written to a started list"
  self.listPrefixBytes

func clear*(w: var RlpLengthTracker) =
  # Prepare writer for reuse
  w.pendingLists.setLen(0)
  if w.kind == TrackerKind.RecordLen:
    w.listPrefixLen.setLen(0)
  else:
    w.listPrefixBytes.setLen(0)
