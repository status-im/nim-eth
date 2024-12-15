import
  std/options,
  pkg/results,
  stew/[arraybuf, assign2, shims/macros],
  ./priv/defs,
  utils

type
  RlpDefaultWriter* = object
    pendingLists: seq[tuple[remainingItems, startPos: int]]
    output: seq[byte]

func writeCount(writer: var RlpDefaultWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    writer.output.add(baseMarker + byte(count))
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    writer.output.add baseMarker + (THRESHOLD_LIST_LEN - 1) +
      byte(lenPrefixBytes)

    writer.output.setLen(writer.output.len + lenPrefixBytes)
    writer.output.writeBigEndian(uint64(count), writer.output.len - 1,
      lenPrefixBytes)

proc maybeClosePendingLists(self: var RlpDefaultWriter) =
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
        totalPrefixBytes = if listLen < int(THRESHOLD_LIST_LEN): 1
                            else: int(uint64(listLen).bytesNeeded) + 1

      #Shift the written data to make room for the prefix length
      self.output.setLen(self.output.len + totalPrefixBytes)

      moveMem(addr self.output[listStartPos + totalPrefixBytes],
            unsafeAddr self.output[listStartPos],
            listLen)

      # Write out the prefix length
      if listLen < THRESHOLD_LIST_LEN:
        self.output[listStartPos] = LIST_START_MARKER + byte(listLen)
      else:
        let listLenBytes = totalPrefixBytes - 1
        self.output[listStartPos] = LEN_PREFIXED_LIST_MARKER +
          byte(listLenBytes)

        self.output.writeBigEndian(uint64(listLen), 
          listStartPos + listLenBytes, listLenBytes)
    else:
      # The currently open list is not finished yet. Nothing to do.
      return

func writeInt*(writer: var RlpDefaultWriter, i: SomeUnsignedInt) =
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

func appendRawBytes*(self: var RlpDefaultWriter, bytes: openArray[byte]) =
  self.output.setLen(self.output.len + bytes.len)
  assign(self.output.toOpenArray(
    self.output.len - bytes.len, self.output.len - 1), bytes)
  self.maybeClosePendingLists()

proc writeBlob*(self: var RlpDefaultWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    self.output.add byte(bytes[0])
    self.maybeClosePendingLists()
  else:
    self.writeCount(bytes.len, BLOB_START_MARKER)
    self.appendRawBytes(bytes)

proc startList*(self: var RlpDefaultWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
    self.maybeClosePendingLists()
  else:
    self.pendingLists.add((listSize, self.output.len))

template finish*(self: RlpDefaultWriter): seq[byte] =
  doAssert self.pendingLists.len == 0, 
    "Insufficient number of elements written to a started list"
  self.output

func clear*(w: var RlpDefaultWriter) =
  # Prepare writer for reuse
  w.pendingLists.setLen(0)
  w.output.setLen(0)
