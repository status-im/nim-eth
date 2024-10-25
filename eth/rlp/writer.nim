import
  std/options,
  results,
  stew/[arraybuf, assign2, bitops2, shims/macros],
 ./priv/defs

export arraybuf

type
  RlpWriter* = object
    pendingLists: seq[tuple[remainingItems, outBytes: int]]
    output: seq[byte]

  RlpIntBuf* = ArrayBuf[9, byte]
    ## Small buffer for holding a single RLP-encoded integer

const
  wrapObjsInList* = true

func bytesNeeded(num: SomeUnsignedInt): int =
  # Number of non-zero bytes in the big endian encoding
  sizeof(num) - (num.leadingZeros() shr 3)

func writeBigEndian(outStream: var auto, number: SomeUnsignedInt,
                    lastByteIdx: int, numberOfBytes: int) =
  var n = number
  for i in countdown(lastByteIdx, lastByteIdx - numberOfBytes + 1):
    outStream[i] = byte(n and 0xff)
    n = n shr 8

func writeBigEndian(outStream: var auto, number: SomeUnsignedInt,
                    numberOfBytes: int) {.inline.} =
  outStream.setLen(outStream.len + numberOfBytes)
  outStream.writeBigEndian(number, outStream.len - 1, numberOfBytes)

func writeCount(bytes: var auto, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    bytes.add(baseMarker + byte(count))
  else:
    let
      origLen = bytes.len
      lenPrefixBytes = uint64(count).bytesNeeded

    bytes.setLen(origLen + lenPrefixBytes + 1)
    bytes[origLen] = baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)
    bytes.writeBigEndian(uint64(count), bytes.len - 1, lenPrefixBytes)

func writeInt(outStream: var auto, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    outStream.add BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    outStream.add byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    outStream.writeCount(bytesNeeded, BLOB_START_MARKER)
    outStream.writeBigEndian(i, bytesNeeded)

proc initRlpWriter*: RlpWriter =
  # Avoid allocations during initial write of small items - since the writer is
  # expected to be short-lived, it doesn't hurt to allocate this buffer
  result.output = newSeqOfCap[byte](2000)

proc decRet(n: var int, delta: int): int =
  n -= delta
  n

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
                             else: int(uint64(listLen).bytesNeeded) + 1

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
        self.output.writeBigEndian(uint64(listLen), listStartPos + listLenBytes, listLenBytes)
    else:
      # The currently open list is not finished yet. Nothing to do.
      return

proc appendRawBytes*(self: var RlpWriter, bytes: openArray[byte]) =
  self.output.setLen(self.output.len + bytes.len)
  assign(self.output.toOpenArray(
    self.output.len - bytes.len, self.output.len - 1), bytes)
  self.maybeClosePendingLists()

proc startList*(self: var RlpWriter, listSize: int) =
  if listSize == 0:
    self.output.writeCount(0, LIST_START_MARKER)
    self.appendRawBytes([])
  else:
    self.pendingLists.add((listSize, self.output.len))

proc appendBlob(self: var RlpWriter, data: openArray[byte], startMarker: byte) =
  if data.len == 1 and byte(data[0]) < BLOB_START_MARKER:
    self.output.add byte(data[0])
    self.maybeClosePendingLists()
  else:
    self.output.writeCount(data.len, startMarker)
    self.appendRawBytes(data)

proc appendImpl(self: var RlpWriter, data: string) =
  appendBlob(self, data.toOpenArrayByte(0, data.high), BLOB_START_MARKER)

proc appendBlob(self: var RlpWriter, data: openArray[byte]) =
  appendBlob(self, data, BLOB_START_MARKER)

proc appendBlob(self: var RlpWriter, data: openArray[char]) =
  appendBlob(self, data.toOpenArrayByte(0, data.high), BLOB_START_MARKER)

proc appendInt(self: var RlpWriter, i: SomeUnsignedInt) =
  # this is created as a separate proc as an extra precaution against
  # any overloading resolution problems when matching the IntLike concept.
  self.output.writeInt(i)

  self.maybeClosePendingLists()

template appendImpl(self: var RlpWriter, i: SomeUnsignedInt) =
  appendInt(self, i)

template appendImpl(self: var RlpWriter, e: enum) =
  appendImpl(self, int(e))

template appendImpl(self: var RlpWriter, b: bool) =
  appendImpl(self, int(b))

proc appendImpl[T](self: var RlpWriter, listOrBlob: openArray[T]) =
  mixin append

  # TODO: This append proc should be overloaded by `openArray[byte]` after
  # nim bug #7416 is fixed.
  when T is (byte or char):
    self.appendBlob(listOrBlob)
  else:
    self.startList listOrBlob.len
    for i in 0 ..< listOrBlob.len:
      self.append listOrBlob[i]

proc countOptionalFields(T: type): int {.compileTime.} =
  mixin enumerateRlpFields

  var dummy: T

  # closure signature matches the one in object_serialization.nim
  template op(RT, fN, f) =
    when f is Option or f is Opt:
      inc result
    else: # this will count only optional fields at the end
      result = 0

  enumerateRlpFields(dummy, op)

proc genPrevFields(obj: NimNode, fd: openArray[FieldDescription], hi, lo: int): NimNode =
  result = newStmtList()
  for i in countdown(hi, lo):
    let fieldName = fd[i].name
    let msg = fieldName.strVal & " expected"
    result.add quote do:
      doAssert(`obj`.`fieldName`.isSome, `msg`)

macro genOptionalFieldsValidation(obj: untyped, T: type, num: static[int]): untyped =
  let
    Tresolved = getType(T)[1]
    fd = recordFields(Tresolved.getImpl)
    loidx = fd.len-num

  result = newStmtList()
  for i in countdown(fd.high, loidx):
    let fieldName = fd[i].name
    let prevFields = genPrevFields(obj, fd, i-1, loidx-1)
    result.add quote do:
      if `obj`.`fieldName`.isSome:
        `prevFields`

  # generate something like
  when false:
    if obj.fee.isNone:
      doAssert(obj.withdrawalsRoot.isNone, "withdrawalsRoot needs fee")
      doAssert(obj.blobGasUsed.isNone, "blobGasUsed needs fee")
      doAssert(obj.excessBlobGas.isNone, "excessBlobGas needs fee")
    if obj.withdrawalsRoot.isNone:
      doAssert(obj.blobGasUsed.isNone, "blobGasUsed needs withdrawalsRoot")
      doAssert(obj.excessBlobGas.isNone, "excessBlobGas needs withdrawalsRoot")
    doAssert obj.blobGasUsed.isSome == obj.excessBlobGas.isSome,
      "blobGasUsed and excessBlobGas must both be present or absent"

proc countFieldsRuntime(obj: object|tuple): int =
  mixin enumerateRlpFields

  var numOptionals: int = 0

  template op(RT, fN, f) {.used.} =
    when f is Option or f is Opt:
      if f.isSome: # if optional and non empty
        inc numOptionals
    else: # if  mandatory field
      inc result
      numOptionals = 0 # count only optionals at the end (after mandatory)

  enumerateRlpFields(obj, op)
  result += numOptionals

proc appendRecordType*(self: var RlpWriter, obj: object|tuple, wrapInList = wrapObjsInList) =
  mixin enumerateRlpFields, append

  type ObjType = type obj

  const
    cof = countOptionalFields(ObjType)

  when cof > 0:
    # ignoring first optional fields
    genOptionalFieldsValidation(obj, ObjType, cof - 1)

  if wrapInList:
    when cof > 0:
      self.startList(obj.countFieldsRuntime)
    else:
      self.startList(ObjType.rlpFieldsCount)

  template op(RecordType, fieldName, field) {.used.} =
    when hasCustomPragmaFixed(RecordType, fieldName, rlpCustomSerialization):
      append(self, obj, field)
    elif (field is Option or field is Opt) and cof > 0:
      # this works for optional fields at the end of an object/tuple
      # if the optional field is followed by a mandatory field,
      # custom serialization for a field or for the parent object
      # will be better
      if field.isSome:
        append(self, field.unsafeGet)
    else:
      append(self, field)

  enumerateRlpFields(obj, op)

proc appendImpl(self: var RlpWriter, data: object) {.inline.} =
  self.appendRecordType(data)

proc appendImpl(self: var RlpWriter, data: tuple) {.inline.} =
  self.appendRecordType(data)

# We define a single `append` template with a pretty low specificity
# score in order to facilitate easier overloading with user types:
template append*[T](w: var RlpWriter; data: T) =
  when data is (enum|bool):
    # TODO detect negative enum values at compile time?
    appendImpl(w, uint64(data))
  else:
    appendImpl(w, data)

template append*(w: var RlpWriter; data: SomeSignedInt) =
  {.error: "Signed integer encoding is not defined for rlp".}

proc initRlpList*(listSize: int): RlpWriter =
  result = initRlpWriter()
  startList(result, listSize)

# TODO: This should return a lent value
template finish*(self: RlpWriter): seq[byte] =
  doAssert self.pendingLists.len == 0, "Insufficient number of elements written to a started list"
  self.output

func clear*(w: var RlpWriter) =
  # Prepare writer for reuse
  w.pendingLists.setLen(0)
  w.output.setLen(0)

proc encode*[T](v: T): seq[byte] =
  mixin append

  var writer = initRlpWriter()
  writer.append(v)
  move(writer.finish)

func encodeInt*(i: SomeUnsignedInt): RlpIntBuf =
  var buf: RlpIntBuf
  buf.writeInt(i)
  buf

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
    move(finish(`writer`))
