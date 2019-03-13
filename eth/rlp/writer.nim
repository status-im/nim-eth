import
  macros, types,
  ranges/[memranges, ptr_arith],
  object_serialization, priv/defs

export
  memranges

type
  RlpWriter* = object
    pendingLists: seq[tuple[remainingItems, outBytes: int]]
    output: Bytes

  PrematureFinalizationError* = object of Exception

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

proc writeBigEndian(outStream: var Bytes, number: Integer,
                    lastByteIdx: int, numberOfBytes: int) =
  mixin `and`, `shr`

  var n = number
  for i in countdown(lastByteIdx, lastByteIdx - int(numberOfBytes) + 1):
    outStream[i] = byte(n and 0xff)
    n = n shr 8

proc writeBigEndian(outStream: var Bytes, number: Integer,
                    numberOfBytes: int) {.inline.} =
  outStream.setLen(outStream.len + numberOfBytes)
  outStream.writeBigEndian(number, outStream.len - 1, numberOfBytes)

proc writeCount(bytes: var Bytes, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    bytes.add(baseMarker + byte(count))
  else:
    let
      origLen = bytes.len
      lenPrefixBytes = count.bytesNeeded

    bytes.setLen(origLen + int(lenPrefixBytes) + 1)
    bytes[origLen] = baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)
    bytes.writeBigEndian(count, bytes.len - 1, lenPrefixBytes)

proc add(outStream: var Bytes, newChunk: BytesRange) =
  let prevLen = outStream.len
  outStream.setLen(prevLen + newChunk.len)
  # XXX: Use copyMem here
  for i in 0 ..< newChunk.len:
    outStream[prevLen + i] = newChunk[i]

{.this: self.}
{.experimental.}

using
  self: var RlpWriter

proc initRlpWriter*: RlpWriter =
  newSeq(result.pendingLists, 0)
  newSeq(result.output, 0)

proc decRet(n: var int, delta: int): int =
  n -= delta
  return n

proc maybeClosePendingLists(self) =
  while pendingLists.len > 0:
    let lastListIdx = pendingLists.len - 1
    doAssert pendingLists[lastListIdx].remainingItems >= 1
    if decRet(pendingLists[lastListIdx].remainingItems, 1) == 0:
      # A list have been just finished. It was started in `startList`.
      let listStartPos = pendingLists[lastListIdx].outBytes
      pendingLists.setLen lastListIdx

      # How many bytes were written since the start?
      let listLen = output.len - listStartPos

      # Compute the number of bytes required to write down the list length
      let totalPrefixBytes = if listLen < int(THRESHOLD_LIST_LEN): 1
                             else: int(listLen.bytesNeeded) + 1

      # Shift the written data to make room for the prefix length
      output.setLen(output.len + totalPrefixBytes)
      let outputBaseAddr = output.baseAddr

      moveMem(outputBaseAddr.shift(listStartPos + totalPrefixBytes),
              outputBaseAddr.shift(listStartPos),
              listLen)

      # Write out the prefix length
      if listLen < THRESHOLD_LIST_LEN:
        output[listStartPos] = LIST_START_MARKER + byte(listLen)
      else:
        let listLenBytes = totalPrefixBytes - 1
        output[listStartPos] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)
        output.writeBigEndian(listLen, listStartPos + listLenBytes, listLenBytes)
    else:
      # The currently open list is not finished yet. Nothing to do.
      return

proc appendRawList(self; bytes: BytesRange) =
  output.writeCount(bytes.len, LIST_START_MARKER)
  output.add(bytes)
  maybeClosePendingLists()

proc appendRawBytes*(self; bytes: BytesRange) =
  output.add(bytes)
  maybeClosePendingLists()

proc startList*(self; listSize: int) =
  if listSize == 0:
    appendRawList(BytesRange())
  else:
    pendingLists.add((listSize, output.len))

template appendBlob(self; data, startMarker) =
  mixin baseAddr

  if data.len == 1 and byte(data[0]) < BLOB_START_MARKER:
    self.output.add byte(data[0])
  else:
    self.output.writeCount(data.len, startMarker)

    let startPos = output.len
    self.output.setLen(startPos + data.len)
    copyMem(shift(baseAddr(self.output), startPos),
            baseAddr(data),
            data.len)

  maybeClosePendingLists()

proc appendImpl(self; data: string) =
  appendBlob(self, data, BLOB_START_MARKER)

proc appendBlob(self; data: openarray[byte]) =
  appendBlob(self, data, BLOB_START_MARKER)

proc appendBlob(self; data: openarray[char]) =
  appendBlob(self, data, BLOB_START_MARKER)

proc appendBytesRange(self; data: BytesRange) =
  appendBlob(self, data, BLOB_START_MARKER)

proc appendImpl(self; data: MemRange) =
  appendBlob(self, data, BLOB_START_MARKER)

proc appendInt(self; i: Integer) =
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

proc appendFloat(self; data: float64) =
  # This is not covered in the RLP spec, but Geth uses Go's
  # `math.Float64bits`, which is defined here:
  # https://github.com/gopherjs/gopherjs/blob/master/compiler/natives/src/math/math.go
  let uintWords = cast[ptr UncheckedArray[uint32]](unsafeAddr data)
  let uint64bits = (uint64(uintWords[1]) shl 32) or uint64(uintWords[0])
  self.appendInt(uint64bits)

template appendImpl(self; i: Integer) =
  appendInt(self, i)

template appendImpl(self; e: enum) =
  appendImpl(self, int(e))

template appendImpl(self; b: bool) =
  appendImpl(self, int(b))

proc appendImpl[T](self; listOrBlob: openarray[T]) =
  mixin append

  # TODO: This append proc should be overloaded by `openarray[byte]` after
  # nim bug #7416 is fixed.
  when T is (byte or char):
    self.appendBlob(listOrBlob)
  else:
    self.startList listOrBlob.len
    for i in 0 ..< listOrBlob.len:
      self.append listOrBlob[i]

proc appendRecordType*(self; obj: object|tuple, wrapInList = wrapObjsInList) =
  mixin enumerateRlpFields, append

  if wrapInList:
    self.startList(static obj.type.rlpFieldsCount)

  template op(field) =
    when hasCustomPragma(field, rlpCustomSerialization):
      append(self, obj, field)
    else:
      append(self, field)

  enumerateRlpFields(obj, op)

proc appendImpl(self; data: object) {.inline.} =
  # TODO: This append proc should be overloaded by `BytesRange` after
  # nim bug #7416 is fixed.
  when data is BytesRange:
    self.appendBytesRange(data)
  else:
    self.appendRecordType(data)

proc appendImpl(self; data: tuple) {.inline.} =
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
proc finish*(self): Bytes =
  if pendingLists.len > 0:
    raise newException(PrematureFinalizationError,
      "Insufficient number of elements written to a started list")
  result = output

proc encode*[T](v: T): Bytes =
  mixin append
  var writer = initRlpWriter()
  writer.append(v)
  return writer.finish

proc encodeInt*(i: Integer): Bytes =
  var writer = initRlpWriter()
  writer.appendInt(i)
  return writer.finish

macro encodeList*(args: varargs[untyped]): Bytes =
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
  template encodeList*(args: varargs[untyped]): BytesRange =
    mixin append
    var writer = initRlpList(args.len)
    for arg in args:
      writer.append(arg)
    writer.finish

