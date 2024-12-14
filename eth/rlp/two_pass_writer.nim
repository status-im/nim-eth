import
  std/options,
  pkg/results,
  stew/[arraybuf, assign2, shims/macros],
  ./priv/defs,
  utils

type
  RlpTwoPassWriter* = object
    pendingLists*: seq[tuple[remainingItems, startPos, prefixLen: int]]
    output*: seq[byte]
    prefixLengths*: seq[int]
    listLengths*: seq[int]
    fillLevel: int

func writeCount(writer: var RlpTwoPassWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    writer.output[writer.fillLevel] = (baseMarker + byte(count))
    writer.fillLevel += 1
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    writer.output[writer.fillLevel] = baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)
    writer.fillLevel += lenPrefixBytes + 1
    writer.output.writeBigEndian(uint64(count), writer.fillLevel - 1, lenPrefixBytes)

# nothing to do when serializing using tracker
template maybeClosePendingLists(self: var RlpTwoPassWriter) = discard

func writeInt*(writer: var RlpTwoPassWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    writer.output[writer.fillLevel] = BLOB_START_MARKER
    writer.fillLevel += 1
  elif i < typeof(i)(BLOB_START_MARKER):
    writer.output[writer.fillLevel] = byte(i)
    writer.fillLevel += 1
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeCount(bytesNeeded, BLOB_START_MARKER)

    writer.fillLevel += bytesNeeded
    writer.output.writeBigEndian(i, writer.fillLevel - 1, bytesNeeded)

func appendRawBytes*(self: var RlpTwoPassWriter, bytes: openArray[byte]) =
  self.fillLevel += bytes.len
  assign(self.output.toOpenArray(self.fillLevel - bytes.len, self.fillLevel - 1), bytes)

proc writeBlob*(self: var RlpTwoPassWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    self.output[self.fillLevel] = byte(bytes[0])
    self.fillLevel += 1
  else:
    self.writeCount(bytes.len, BLOB_START_MARKER)
    self.appendRawBytes(bytes)

proc startList*(self: var RlpTwoPassWriter, listSize: int) =
  mixin writeCount

  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
  else:
    let prefixLen = self.prefixLengths[0]
    let listLen = self.listLengths[0]
    self.prefixLengths.delete(0)
    self.listLengths.delete(0)

    if listLen < THRESHOLD_LIST_LEN:
      self.output[self.fillLevel] = LIST_START_MARKER + byte(listLen)
      self.fillLevel += 1
    else:
      let listLenBytes = prefixLen - 1
      self.output[self.fillLevel] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)
      self.fillLevel += prefixLen
      self.output.writeBigEndian(uint64(listLen), self.fillLevel - 1, listLenBytes)

func initTwoPassWriter*(length: int): RlpTwoPassWriter =
  result.fillLevel = 0
  result.output = newSeqOfCap[byte](length)
  result.output.setLen(length)

template finish*(self: RlpTwoPassWriter): seq[byte] =
  doAssert self.pendingLists.len == 0, "Insufficient number of elements written to a started list"
  self.prefixLengths.setLen(0)
  self.listLengths.setLen(0)
  self.output

func clear*(w: var RlpTwoPassWriter) =
  # Prepare writer for reuse
  w.pendingLists.setLen(0)
  w.output.setLen(0)
  w.prefixLengths.setLen(0)
  w.listLengths.setLen(0)
