import
  std/options,
  pkg/results,
  stew/[arraybuf, assign2, shims/macros],
  ./priv/defs,
  utils,
  length_writer

type
  RlpTwoPassWriter* = object
    output*: seq[byte]
    lengths*: seq[tuple[listLen, prefixLen: int]]
    fillLevel: int
    listCount: int

func writeCount(writer: var RlpTwoPassWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    writer.output[writer.fillLevel] = (baseMarker + byte(count))
    writer.fillLevel += 1
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    writer.output[writer.fillLevel] = baseMarker + (THRESHOLD_LIST_LEN - 1) +
      byte(lenPrefixBytes)
    writer.fillLevel += lenPrefixBytes + 1
    writer.output.writeBigEndian(uint64(count), 
      writer.fillLevel - 1, lenPrefixBytes)

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
  assign(self.output.toOpenArray(
    self.fillLevel - bytes.len, self.fillLevel - 1), bytes)

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
    let 
      prefixLen = self.lengths[self.listCount].prefixLen
      listLen = self.lengths[self.listCount].listLen

    self.listCount += 1

    if listLen < THRESHOLD_LIST_LEN:
      self.output[self.fillLevel] = LIST_START_MARKER + byte(listLen)
      self.fillLevel += 1
    else:
      let listLenBytes = prefixLen - 1
      self.output[self.fillLevel] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)
      self.fillLevel += prefixLen
      self.output.writeBigEndian(uint64(listLen), self.fillLevel - 1,
        listLenBytes)

func initTwoPassWriter*(tracker: var RlpLengthTracker): RlpTwoPassWriter =
  result.fillLevel = 0
  result.listCount = 0
  result.output = newSeq[byte](tracker.totalLength)
  result.lengths = move(tracker.lengths)

template finish*(self: RlpTwoPassWriter): seq[byte] =
  self.lengths.setLen(0)
  self.output

func clear*(w: var RlpTwoPassWriter) =
  # Prepare writer for reuse
  w.lengths.setLen(0)
  w.output.setLen(0)
