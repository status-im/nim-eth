import
  std/options,
  pkg/results,
  nimcrypto/keccak,
  stew/[arraybuf, bitops2, shims/macros],
  ./priv/defs,
  utils

type
  RlpHashWriter* = object
    keccak: keccak.keccak256
    listPrefixBytes*: seq[seq[byte]]

template update(writer: var RlpHashWriter, data: byte) =
  writer.keccak.update([data])

template update(writer: var RlpHashWriter, data: openArray[byte]) =
  writer.keccak.update(data)

func writeCount(writer: var RlpHashWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    writer.update(baseMarker + byte(count))
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    writer.update baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)

    var buf = newSeqOfCap[byte](lenPrefixBytes)
    buf.setLen(lenPrefixBytes)
    buf.writeBigEndian(uint64(count), buf.len - 1, lenPrefixBytes)
    writer.update(buf)

func writeInt*(writer: var RlpHashWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    writer.update BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    writer.update byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeCount(bytesNeeded, BLOB_START_MARKER)

    var buf = newSeqOfCap[byte](bytesNeeded)
    buf.setLen(bytesNeeded)
    buf.writeBigEndian(uint64(i), buf.len - 1, bytesNeeded)
    writer.update(buf)

template appendRawBytes*(self: var RlpHashWriter, bytes: openArray[byte]) =
  self.update(bytes)

proc writeBlob*(self: var RlpHashWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    self.update byte(bytes[0])
  else:
    self.writeCount(bytes.len, BLOB_START_MARKER)
    self.appendRawBytes(bytes)

proc startList*(self: var RlpHashWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
  else:
    let prefixBytes = self.listPrefixBytes[0]
    self.listPrefixBytes.delete(0)
    self.update(prefixBytes)

template finish*(self: var RlpHashWriter): MDigest[self.keccak.bits] =
  doAssert self.listPrefixBytes.len == 0, "Insufficient number of elements written to a started list"
  self.keccak.finish()

func clear*(w: var RlpHashWriter) =
  # Prepare writer for reuse
  w.listPrefixBytes.setLen(0)


