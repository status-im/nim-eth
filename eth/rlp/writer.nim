# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[options, typetraits],
  pkg/results,
  stew/[arraybuf, shims/macros],
  ./priv/defs,
  hash_writer,
  length_writer,
  two_pass_writer,
  default_writer,
  utils,
  stint,
  ../common/hashes

export arraybuf, default_writer, length_writer, two_pass_writer, hash_writer

type
  RlpWriter* = RlpDefaultWriter | RlpTwoPassWriter | RlpLengthTracker | RlpHashWriter

  RlpIntBuf* = ArrayBuf[9, byte]
    ## Small buffer for holding a single RLP-encoded integer

const
  wrapObjsInList* = true

proc initRlpWriter*: RlpDefaultWriter =
  # Avoid allocations during initial write of small items - since the writer is
  # expected to be short-lived, it doesn't hurt to allocate this buffer
  result

template appendBlob(self: var RlpWriter, data: openArray[byte]) =
  self.writeBlob(data)

proc appendInt(self: var RlpWriter, i: SomeUnsignedInt) =
  # this is created as a separate proc as an extra precaution against
  # any overloading resolution problems when matching the IntLike concept.
  self.writeInt(i)

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

template innerType[T](x: Option[T] | Opt[T]): typedesc = T

proc countNestedListsDepth(T: type): int {.compileTime.} =
  mixin enumerateRlpFields

  var dummy {.used.}: T

  template op(RT, fN, f) {.used.}=
    result += countNestedListsDepth(type f)

  when T is Option or T is Opt:
    result += countNestedListsDepth(innerType(dummy))
  elif T is UInt256:
    discard
  elif T is object or T is tuple:
    inc result
    enumerateRlpFields(dummy, op)
  elif T is seq or T is array:
    inc result
    result += countNestedListsDepth(elementType(dummy))

proc countNestedListsDepth[E](T: type openArray[E]): int =
  countNestedListsDepth(seq[E])

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

proc encode*[T](v: T): seq[byte] =
  mixin append

  const nestedListsDepth = countNestedListsDepth(T)

  when nestedListsDepth > 0:
    var tracker = StaticRlpLengthTracker[nestedListsDepth]()
  elif nestedListsDepth == 0:
    var tracker = DynamicRlpLengthTracker()

  tracker.initLengthTracker()

  tracker.append(v)

  var writer = initTwoPassWriter(tracker)
  writer.append(v)

  move(writer.finish)

proc encodeHash*[T](v: T): Hash32 =
  mixin append

  const nestedListsDepth = countNestedListsDepth(T)

  when nestedListsDepth > 0:
    var tracker = StaticRlpLengthTracker[nestedListsDepth]()
  elif nestedListsDepth == 0:
    var tracker = DynamicRlpLengthTracker()

  tracker.initLengthTracker()

  tracker.append(v)

  var writer = initHashWriter(tracker)
  writer.append(v)

  writer.finish()

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


proc getEncodedLength*[T](v: T): int =
  mixin append

  const nestedListsDepth = countNestedListsDepth(T)
  when nestedListsDepth > 0:
    var tracker = StaticRlpLengthTracker[nestedListsDepth]()
  elif nestedListsDepth == 0:
    var tracker = DynamicRlpLengthTracker()

  tracker.initLengthTracker()
  tracker.append(v)
  return tracker.finish()
