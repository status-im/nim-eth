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
  ./priv/defs,
  times,
  strutils


export arraybuf

type
  RlpDefaultWriter* = object
    pendingLists: seq[tuple[remainingItems, startPos: int]]
    output: seq[byte]

  RlpLengthTracker* = object
    pendingLists: seq[tuple[idx, remainingItems, length: int]]
    listCount: int
    listPrefixBytes: seq[int]
    totalLength: int
 
  RlpTwoPassWriter* = object
    pendingLists: seq[tuple[remainingItems, startPos, prefixLen: int]]
    output: seq[byte]
    listPrefixBytes: seq[int]

  RlpWriter* = RlpDefaultWriter | RlpTwoPassWriter | RlpLengthTracker

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

func writeCount(writer: var RlpWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    writer.output.add(baseMarker + byte(count))
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    writer.output.add baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)
    
    writer.output.setLen(writer.output.len + lenPrefixBytes)
    writer.output.writeBigEndian(uint64(count), writer.output.len - 1, lenPrefixBytes)

func writeInt(writer: var RlpWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    writer.output.add BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    writer.output.add byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeCount(bytesNeeded, BLOB_START_MARKER)

    writer.output.setLen(writer.output.len + bytesNeeded)
    writer.output.writeBigEndian(i, writer.output.len - 1, bytesNeeded)

proc initRlpWriter*: RlpDefaultWriter =
  # Avoid allocations during initial write of small items - since the writer is
  # expected to be short-lived, it doesn't hurt to allocate this buffer
  result

# nothing to do when serializing using tracker
proc maybeClosePendingLists(self: var RlpTwoPassWriter) =
  while self.pendingLists.len > 0:
    let lastListIdx = self.pendingLists.len - 1
    doAssert self.pendingLists[lastListIdx].remainingItems > 0

    self.pendingLists[lastListIdx].remainingItems -= 1
    # if one last item is remaining in the list
    if self.pendingLists[lastListIdx].remainingItems == 0:
      # A list have been just finished. It was started in `startList`.
      let listStartPos = self.pendingLists[lastListIdx].startPos
      let prefixLen = self.pendingLists[lastListIdx].prefixLen

      self.pendingLists.setLen lastListIdx

      let listLen = self.output.len - listStartPos - prefixLen

      # Write out the prefix length
      if listLen < THRESHOLD_LIST_LEN:
        self.output[listStartPos] = LIST_START_MARKER + byte(listLen)
      else:
        let listLenBytes = prefixLen - 1
        self.output[listStartPos] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)
        self.output.writeBigEndian(uint64(listLen), listStartPos + listLenBytes, listLenBytes)
    else:
      # The currently open list is not finished yet. Nothing to do.
      return


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

      let listLen = self.output.len - listStartPos

      let totalPrefixBytes = if listLen < int(THRESHOLD_LIST_LEN): 1
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
        self.output[listStartPos] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)
        self.output.writeBigEndian(uint64(listLen), listStartPos + listLenBytes, listLenBytes)
    else:
      # The currently open list is not finished yet. Nothing to do.
      return

template appendRawBytes*(self: var RlpWriter, bytes: openArray[byte]) =
  self.output.setLen(self.output.len + bytes.len)
  assign(self.output.toOpenArray(self.output.len - bytes.len, self.output.len - 1), bytes)

proc startList*(self: var RlpTwoPassWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
    self.maybeClosePendingLists()
  else:
    let prefixLen = self.listPrefixBytes[0]
    self.listPrefixBytes.delete(0)
    self.pendingLists.add((listSize, self.output.len, prefixLen))
    self.output.setLen(self.output.len + prefixLen)

proc writeRawBytes(self: var RlpWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    self.output.add byte(bytes[0])
  else:
    self.writeCount(bytes.len, BLOB_START_MARKER)
    self.appendRawBytes(bytes)

proc startList*(self: var RlpDefaultWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
    self.maybeClosePendingLists()
  else:
    self.pendingLists.add((listSize, self.output.len))

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

proc recordLenInCurList(self: var RlpLengthTracker, length: int) =
  if self.pendingLists.len <= 0:
    self.totalLength += length
    return

  let lastIdx = self.pendingLists.len - 1
  self.pendingLists[lastIdx].remainingItems -= 1
  self.pendingLists[lastIdx].length += length


  if self.pendingLists[lastIdx].remainingItems == 0:
    let listIdx = self.pendingLists[lastIdx].idx
    let listLen = self.pendingLists[lastIdx].length
    let prefixLen = if listLen < int(THRESHOLD_LIST_LEN): 1
                      else: int(uint64(listLen).bytesNeeded) + 1

    # save the prefix
    #self.listPrefixBytes[listIdx].prefix = calculateListPrefix(listLen, prefixLen)
    # take note of the prefix len
    self.listPrefixBytes[listIdx] = prefixLen
    # close the list by deleting
    self.pendingLists.setLen(lastIdx)
  
    let finalListLen = listLen + prefixLen
    # add the current lists length to its parent list
    self.recordLenInCurList(finalListLen)

proc startList*(self: var RlpLengthTracker, listSize: int) =
  if listSize == 0:
    self.recordLenInCurList(1)
  else:
    # open a list
    self.pendingLists.add((self.listCount, listSize, 0))
    self.listCount += 1
    self.listPrefixBytes.add(0)

func lengthCount(count: int): int {.inline.} =
  if count < THRESHOLD_LIST_LEN:
    return 1
  else:
    return uint64(count).bytesNeeded + 1

func appendBlob(self: var RlpLengthTracker, data: openArray[byte]) =
  if data.len == 1 and byte(data[0]) < BLOB_START_MARKER:
    self.recordLenInCurList(1)
  else:
    self.recordLenInCurList(lengthCount(data.len) + data.len)

func appendInt(self: var RlpLengthTracker, i: SomeUnsignedInt) =
  if i < typeof(i)(BLOB_START_MARKER):
    self.recordLenInCurList(1)
  else:
    self.recordLenInCurList(lengthCount(i.bytesNeeded) + i.bytesNeeded)

func appendBlob(self: var RlpWriter, data: openArray[byte]) =
  self.writeRawBytes(data)
  self.maybeClosePendingLists()

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

proc initRlpList*(listSize: int): RlpDefaultWriter =
  result = initRlpWriter()
  startList(result, listSize)

template finish*(self: RlpDefaultWriter): seq[byte] =
  doAssert self.pendingLists.len == 0, "Insufficient number of elements written to a started list"
  self.output

template finish*(self: RlpTwoPassWriter): seq[byte] =
  doAssert self.pendingLists.len == 0, "Insufficient number of elements written to a started list"
  doAssert self.listPrefixBytes.len == 0, "Insufficient number of list prefixes accounted for"
  self.output

func clear*(w: var RlpWriter) =
  # Prepare writer for reuse
  w.pendingLists.setLen(0)
  when typeof(w) is RlpDefaultWriter:
    w.output.setLen(0)
  elif typeof(w) is RlpTwoPassWriter:
    w.output.setLen(0)
    w.listPrefixBytes.setLen(0)

proc encode*[T](v: T): seq[byte] =
  mixin append

  var tracker: RlpLengthTracker
  var writer: RlpTwoPassWriter
  
  tracker.append(v)

  writer.output = newSeqOfCap[byte](tracker.totalLength)
  writer.listPrefixBytes = tracker.listPrefixBytes
  writer.append(v)

  move(writer.finish)

func encodeInt*(i: SomeUnsignedInt): RlpIntBuf =
  var buf: RlpIntBuf

  if i == typeof(i)(0):
    buf.add BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    buf.add byte(i)
  else:
    let bytesNeeded = uint64(i).bytesNeeded

    buf.add(BLOB_START_MARKER + byte(bytesNeeded))
    buf.setLen(buf.len + bytesNeeded) 
    buf.writeBigEndian(i, buf.len - 1, bytesNeeded)

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
