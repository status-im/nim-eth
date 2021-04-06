import
  std/macros,
  ./object_serialization, ./priv/defs

type
  RlpWriter* = object
    pendingLists: seq[tuple[remainingItems, outBytes: int]]
    output: seq[byte]

  IntLike* = concept x, y
    type T = type(x)

    # arithmetic ops
    x + y is T
    x * y is T
    x - y is T
    x div y is T
    x mod y is T

    # some int compatibility required for big endian encoding:
    x shr int is T
    x shl int is T
    x and 0xff is int
    x < 128 is bool

  Integer* = SomeInteger # or IntLike

const
  wrapObjsInList* = true

proc bytesNeeded(num: Integer): int =
  type IntType = type(num)
  var n = num
  while n != IntType(0):
    inc result
    n = n shr 8

proc writeBigEndian(outStream: var seq[byte], number: Integer,
                    lastByteIdx: int, numberOfBytes: int) =
  mixin `and`, `shr`

  var n = number
  for i in countdown(lastByteIdx, lastByteIdx - int(numberOfBytes) + 1):
    outStream[i] = byte(n and 0xff)
    n = n shr 8

proc writeBigEndian(outStream: var seq[byte], number: Integer,
                    numberOfBytes: int) {.inline.} =
  outStream.setLen(outStream.len + numberOfBytes)
  outStream.writeBigEndian(number, outStream.len - 1, numberOfBytes)

proc writeCount(bytes: var seq[byte], count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    bytes.add(baseMarker + byte(count))
  else:
    let
      origLen = bytes.len
      lenPrefixBytes = count.bytesNeeded

    bytes.setLen(origLen + int(lenPrefixBytes) + 1)
    bytes[origLen] = baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)
    bytes.writeBigEndian(count, bytes.len - 1, lenPrefixBytes)

proc initRlpWriter*: RlpWriter =
  newSeq(result.pendingLists, 0)
  newSeq(result.output, 0)

proc decRet(n: var int, delta: int): int =
  n -= delta
  return n

proc maybeClosePendingLists(self: var RlpWriter) =
  while self.pendingLists.len > 0:
    let lastListIdx = self.pendingLists.len - 1
    doAssert self.pendingLists[lastListIdx].remainingItems >= 1
    if decRet(self.pendingLists[lastListIdx].remainingItems, 1) == 0:
      # A list have been just finished. It was started in `startList`.
      let listStartPos = self.pendingLists[lastListIdx].outBytes
      self.pendingLists.setLen lastListIdx

      # How many bytes were written since the start?
      let listLen = self.output.len - listStartPos

      # Compute the number of bytes required to write down the list length
      let totalPrefixBytes = if listLen < int(THRESHOLD_LIST_LEN): 1
                             else: int(listLen.bytesNeeded) + 1

      # Shift the written data to make room for the prefix length
      self.output.setLen(self.output.len + totalPrefixBytes)

      moveMem(addr self.output[listStartPos + totalPrefixBytes],
              unsafeAddr self.output[listStartPos],
              listLen)

      # Write out the prefix length
      if listLen < THRESHOLD_LIST_LEN:
        self.output[listStartPos] = LIST_START_MARKER + byte(listLen)
      else:
        let listLenBytes = totalPrefixBytes - 1
        self.output[listStartPos] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)
        self.output.writeBigEndian(listLen, listStartPos + listLenBytes, listLenBytes)
    else:
      # The currently open list is not finished yet. Nothing to do.
      return

proc appendRawList(self: var RlpWriter, bytes: openArray[byte]) =
  self.output.writeCount(bytes.len, LIST_START_MARKER)
  self.output.add(bytes)
  self.maybeClosePendingLists()

proc appendRawBytes*(self: var RlpWriter, bytes: openArray[byte]) =
  self.output.add(bytes)
  self.maybeClosePendingLists()

proc startList*(self: var RlpWriter, listSize: int) =
  if listSize == 0:
    self.appendRawList([])
  else:
    self.pendingLists.add((listSize, self.output.len))

proc appendBlob(self: var RlpWriter, data: openArray[byte], startMarker: byte) =
  if data.len == 1 and byte(data[0]) < BLOB_START_MARKER:
    self.output.add byte(data[0])
  else:
    self.output.writeCount(data.len, startMarker)
    self.output.add data

  self.maybeClosePendingLists()

proc appendImpl(self: var RlpWriter, data: string) =
  appendBlob(self, data.toOpenArrayByte(0, data.high), BLOB_START_MARKER)

proc appendBlob(self: var RlpWriter, data: openarray[byte]) =
  appendBlob(self, data, BLOB_START_MARKER)

proc appendBlob(self: var RlpWriter, data: openarray[char]) =
  appendBlob(self, data.toOpenArrayByte(0, data.high), BLOB_START_MARKER)

proc appendInt(self: var RlpWriter, i: Integer) =
  # this is created as a separate proc as an extra precaution against
  # any overloading resolution problems when matching the IntLike concept.
  type IntType = type(i)

  if i == IntType(0):
    self.output.add BLOB_START_MARKER
  elif i < BLOB_START_MARKER.Integer:
    self.output.add byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    self.output.writeCount(bytesNeeded, BLOB_START_MARKER)
    self.output.writeBigEndian(i, bytesNeeded)

  self.maybeClosePendingLists()

proc appendFloat(self: var RlpWriter, data: float64) =
  # This is not covered in the RLP spec, but Geth uses Go's
  # `math.Float64bits`, which is defined here:
  # https://github.com/gopherjs/gopherjs/blob/master/compiler/natives/src/math/math.go
  let uintWords = cast[ptr UncheckedArray[uint32]](unsafeAddr data)
  let uint64bits = (uint64(uintWords[1]) shl 32) or uint64(uintWords[0])
  self.appendInt(uint64bits)

template appendImpl(self: var RlpWriter, i: Integer) =
  appendInt(self, i)

template appendImpl(self: var RlpWriter, e: enum) =
  appendImpl(self, int(e))

template appendImpl(self: var RlpWriter, b: bool) =
  appendImpl(self, int(b))

proc appendImpl[T](self: var RlpWriter, listOrBlob: openarray[T]) =
  mixin append

  # TODO: This append proc should be overloaded by `openarray[byte]` after
  # nim bug #7416 is fixed.
  when T is (byte or char):
    self.appendBlob(listOrBlob)
  else:
    self.startList listOrBlob.len
    for i in 0 ..< listOrBlob.len:
      self.append listOrBlob[i]

proc appendRecordType*(self: var RlpWriter, obj: object|tuple, wrapInList = wrapObjsInList) =
  mixin enumerateRlpFields, append

  if wrapInList:
    self.startList(static obj.type.rlpFieldsCount)

  template op(field) =
    when hasCustomPragma(field, rlpCustomSerialization):
      append(self, obj, field)
    else:
      append(self, field)

  enumerateRlpFields(obj, op)

proc appendImpl(self: var RlpWriter, data: object) {.inline.} =
    self.appendRecordType(data)

proc appendImpl(self: var RlpWriter, data: tuple) {.inline.} =
  self.appendRecordType(data)

# We define a single `append` template with a pretty low specifity
# score in order to facilitate easier overloading with user types:
template append*[T](w: var RlpWriter; data: T) =
  when data is float64:
    # XXX: This works around an overloading bug.
    # Apparently, integer literals will be converted to `float64`
    # values with higher precedence than the generic match to Integer
    appendFloat(w, data)
  else:
    appendImpl(w, data)

proc initRlpList*(listSize: int): RlpWriter =
  result = initRlpWriter()
  startList(result, listSize)

# TODO: This should return a lent value
template finish*(self: RlpWriter): seq[byte] =
  doAssert self.pendingLists.len == 0, "Insufficient number of elements written to a started list"
  self.output

proc encode*[T](v: T): seq[byte] =
  mixin append
  var writer = initRlpWriter()
  writer.append(v)
  return writer.finish

proc encodeInt*(i: Integer): seq[byte] =
  var writer = initRlpWriter()
  writer.appendInt(i)
  return writer.finish

macro encodeList*(args: varargs[untyped]): seq[byte] =
  var
    listLen = args.len
    writer = genSym(nskVar, "rlpWriter")
    body = newStmtList()
    append = bindSym("append", brForceOpen)

  for arg in args:
    body.add quote do:
      `append`(`writer`, `arg`)

  result = quote do:
    var `writer` = initRlpList(`listLen`)
    `body`
    finish(`writer`)

when false:
  # XXX: Currently fails with a malformed AST error on the args.len expression
  template encodeList*(args: varargs[untyped]): seq[byte] =
    mixin append
    var writer = initRlpList(args.len)
    for arg in args:
      writer.append(arg)
    writer.finish
