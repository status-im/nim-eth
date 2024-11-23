# eth
# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/options,
  pkg/results,
  stew/[arraybuf, assign2, bitops2, shims/macros],
 ./priv/defs

export arraybuf

type
  RlpWriter* = object
    pendingLists: seq[tuple[remainingItems, startPos: int]]
    output: seq[byte]
    outStreamLen: int
    listPrefixBytes: seq[int]
    fillLevel: int
    dryRun: bool

  RlpIntBuf* = ArrayBuf[9, byte]
    ## Small buffer for holding a single RLP-encoded integer

const
  wrapObjsInList* = true

func bytesNeeded(num: SomeUnsignedInt): int =
  # Number of non-zero bytes in the big endian encoding
  sizeof(num) - (num.leadingZeros() shr 3)

func writeBigEndian(writer: var RlpWriter, number: SomeUnsignedInt,
                    numberOfBytes: int) {.inline.} =
  if writer.dryRun:
    writer.outStreamLen += numberOfBytes
  else:
    var n = number
    for i in countdown(writer.fillLevel + numberOfBytes - 1, writer.fillLevel - 1):
      writer.output[i] = byte(n and 0xff)
      n = n shr 8

    writer.fillLevel += numberOfBytes

func writeCount(writer: var RlpWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    if writer.dryRun:
      writer.outStreamLen += 1
    else:
      writer.output[writer.fillLevel] = (baseMarker + byte(count))
      writer.fillLevel += 1
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    if writer.dryRun:
      writer.outStreamLen += lenPrefixBytes + 1
    else:
      writer.output[writer.fillLevel] = baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)
      writer.writeBigEndian(uint64(count), lenPrefixBytes)

func writeInt(writer: var RlpWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    if writer.dryRun:
      writer.outStreamLen += 1
    else:
      writer.output[writer.fillLevel] = BLOB_START_MARKER
      writer.fillLevel += 1
  elif i < typeof(i)(BLOB_START_MARKER):
    if writer.dryRun:
      writer.outStreamLen += 1
    else:
      writer.output[writer.fillLevel] = byte(i)
      writer.fillLevel += 1
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeCount(bytesNeeded, BLOB_START_MARKER)
    writer.writeBigEndian(i, bytesNeeded)

proc initRlpWriter*: RlpWriter =
<<<<<<< Updated upstream
  # Avoid allocations during initial write of small items - since the writer is
  # expected to be short-lived, it doesn't hurt to allocate this buffer
  result.output = newSeqOfCap[byte](2)
=======
  result.output = newSeqOfCap[byte](2000)
>>>>>>> Stashed changes

proc maybeClosePendingLists(self: var RlpWriter) =
  while self.pendingLists.len > 0:
    let lastListIdx = self.pendingLists.len - 1
    doAssert self.pendingLists[lastListIdx].remainingItems > 0

    self.pendingLists[lastListIdx].remainingItems -= 1
    # if one last item is remaining in the list
    if self.pendingLists[lastListIdx].remainingItems == 0:
      # A list have been just finished. It was started in `startList`.
      let listStartPos = self.pendingLists[lastListIdx].startPos
      self.pendingLists.setLen lastListIdx

      # How many bytes were written since the start?
      let listLen = self.fillLevel - listStartPos

      # Compute the number of bytes required to write down the list length
      let totalPrefixBytes = if listLen < int(THRESHOLD_LIST_LEN): 1
                             else: int(uint64(listLen).bytesNeeded) + 1

      if self.dryRun:
        self.outStreamLen += totalPrefixBytes
        self.listPrefixBytes.add(totalPrefixBytes)
      else:
        # Write out the prefix length
        if listLen < THRESHOLD_LIST_LEN:
          self.output[listStartPos] = LIST_START_MARKER + byte(listLen)
        else:
          let listLenBytes = totalPrefixBytes - 1
          self.output[listStartPos] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)

          self.writeBigEndian(uint64(listLen), listLenBytes)
          self.fillLevel -= listLenBytes
    else:
      # The currently open list is not finished yet. Nothing to do.
      return

proc appendRawBytes*(self: var RlpWriter, bytes: openArray[byte]) =
  if self.dryRun:
    self.outStreamLen += bytes.len
  else:
    assign(self.output.toOpenArray(
      self.fillLevel, self.fillLevel + bytes.len - 1), bytes)

    # increment the fill level
    self.fillLevel += bytes.len
  self.maybeClosePendingLists()

proc startList*(self: var RlpWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
    self.appendRawBytes([])
  else:
    # add a list to the stack with the starting position as the current fill level
    self.pendingLists.add((listSize, self.fillLevel))

    # if not in dry run mode shift the fill level by prefixBytes (calculated during dry run) 
    if not self.dryRun:
      self.fillLevel += self.listPrefixBytes[self.pendingLists.len - 1]

proc appendBlob(self: var RlpWriter, data: openArray[byte]) =
  if data.len == 1 and byte(data[0]) < BLOB_START_MARKER:
    if self.dryRun:
      self.outStreamLen += 1
    else:
      self.output[self.fillLevel] = byte(data[0])
      self.fillLevel += 1
    self.maybeClosePendingLists()
  else:
    self.writeCount(data.len, BLOB_START_MARKER)
    self.appendRawBytes(data)

proc appendInt(self: var RlpWriter, i: SomeUnsignedInt) =
  # this is created as a separate proc as an extra precaution against
  # any overloading resolution problems when matching the IntLike concept.
  self.writeInt(i)

  self.maybeClosePendingLists()


template appendImpl(self: var RlpWriter, data: openArray[byte]) =
  self.appendBlob(data)

template appendImpl(self: var RlpWriter, data: openArray[char]) =
  self.appendBlob(data.toOpenArrayByte(0, data.high))

template appendImpl(self: var RlpWriter, data: string) =
  self.appendBlob(data.toOpenArrayByte(0, data.high))

template appendImpl(self: var RlpWriter, i: SomeUnsignedInt) =
  self.appendInt(i)

template appendImpl(self: var RlpWriter, e: enum) =
  # TODO: check for negative enums 
  self.appendInt(uint64(e))

template appendImpl(self: var RlpWriter, b: bool) =
  self.appendInt(uint64(b))

proc appendImpl[T](self: var RlpWriter, list: openArray[T]) =
  mixin append

  self.startList list.len
  for i in 0 ..< list.len:
    self.append list[i]

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

template appendImpl(self: var RlpWriter, data: object) =
  self.appendRecordType(data)

template appendImpl(self: var RlpWriter, data: tuple) =
  self.appendRecordType(data)

# We define a single `append` template with a pretty low specificity
# score in order to facilitate easier overloading with user types:
template append*[T](w: var RlpWriter; data: T) =
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

  var writer: RlpWriter
  writer.dryRun = true
  writer.append(v)
  doAssert writer.pendingLists.len == 0, $writer.pendingLists.len & "Insufficient number of elements written to a started list"
  writer.dryRun = false
  writer.output = newSeqOfCap[byte](writer.outStreamLen)
  writer.output.setLen(writer.outStreamLen)
  writer.append(v)
  move(writer.finish)

func encodeInt*(i: SomeUnsignedInt): RlpIntBuf =
  var buf: RlpIntBuf

  if i == typeof(i)(0):
    buf.add BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    buf.add byte(i)
  else:
    let bytesNeeded = i.bytesNeeded

    var n = i
    buf.add(BLOB_START_MARKER + byte(bytesNeeded))
    for j in countdown(1, bytesNeeded + 1):
      buf.add(byte(n and 0xff))
      n = n shr 8

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
