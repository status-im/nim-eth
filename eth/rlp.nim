## This module implements RLP encoding and decoding as
## defined in Appendix B of the Ethereum Yellow Paper:
## https://ethereum.github.io/yellowpaper/paper.pdf

import
  std/[strutils, options],
  stew/[byteutils, shims/macros, results],
  ./rlp/[writer, object_serialization],
  ./rlp/priv/defs

from stew/objects import checkedEnumAssign

export
  writer, object_serialization

type
  Rlp* = object
    bytes: seq[byte]
    position*: int

  RlpNodeType* = enum
    rlpBlob
    rlpList

  RlpNode* = object
    case kind*: RlpNodeType
    of rlpBlob:
      bytes*: seq[byte]
    of rlpList:
      elems*: seq[RlpNode]

  RlpError* = object of CatchableError
  MalformedRlpError* = object of RlpError
  UnsupportedRlpError* = object of RlpError
  RlpTypeMismatch* = object of RlpError

proc rlpFromBytes*(data: seq[byte]): Rlp =
  Rlp(bytes: data, position: 0)

proc rlpFromBytes*(data: openArray[byte]): Rlp =
  rlpFromBytes(@data)

const zeroBytesRlp* = Rlp()

proc rlpFromHex*(input: string): Rlp =
  rlpFromBytes(hexToSeqByte(input))

proc hasData*(self: Rlp): bool =
  self.position < self.bytes.len

proc currentElemEnd*(self: Rlp): int {.gcsafe.}

template rawData*(self: Rlp): openArray[byte] =
  self.bytes.toOpenArray(self.position, self.currentElemEnd - 1)

template remainingBytes*(self: Rlp): openArray[byte] =
  self.bytes.toOpenArray(self.position, self.bytes.len - 1)

proc isBlob*(self: Rlp): bool =
  self.hasData() and self.bytes[self.position] < LIST_START_MARKER

proc isEmpty*(self: Rlp): bool =
  ### Contains a blob or a list of zero length
  self.hasData() and (self.bytes[self.position] == BLOB_START_MARKER or
                 self.bytes[self.position] == LIST_START_MARKER)

proc isList*(self: Rlp): bool =
  self.hasData() and self.bytes[self.position] >= LIST_START_MARKER

template eosError =
  raise newException(MalformedRlpError, "Read past the end of the RLP stream")

template requireData {.dirty.} =
  if not self.hasData():
    raise newException(MalformedRlpError, "Illegal operation over an empty RLP stream")

proc getType*(self: Rlp): RlpNodeType =
  requireData()
  return if self.isBlob(): rlpBlob else: rlpList

proc lengthBytesCount(self: Rlp): int =
  var marker = self.bytes[self.position]
  if self.isBlob() and marker > LEN_PREFIXED_BLOB_MARKER:
    return int(marker - LEN_PREFIXED_BLOB_MARKER)
  if self.isList() and marker > LEN_PREFIXED_LIST_MARKER:
    return int(marker - LEN_PREFIXED_LIST_MARKER)
  return 0

proc isSingleByte*(self: Rlp): bool =
  self.hasData() and self.bytes[self.position] < BLOB_START_MARKER

proc getByteValue*(self: Rlp): byte =
  doAssert self.isSingleByte()
  return self.bytes[self.position]

proc payloadOffset(self: Rlp): int =
  if self.isSingleByte(): 0 else: 1 + self.lengthBytesCount()

template readAheadCheck(numberOfBytes: int) =
  # important to add nothing to the left side of the equation as `numberOfBytes`
  # can in theory be at max size of its type already
  if numberOfBytes > self.bytes.len - self.position - self.payloadOffset():
    eosError()

template nonCanonicalNumberError =
  raise newException(MalformedRlpError, "Small number encoded in a non-canonical way")

proc payloadBytesCount(self: Rlp): int =
  if not self.hasData():
    return 0

  var marker = self.bytes[self.position]
  if marker < BLOB_START_MARKER:
    return 1
  if marker <= LEN_PREFIXED_BLOB_MARKER:
    result = int(marker - BLOB_START_MARKER)
    readAheadCheck(result)
    if result == 1:
      if self.bytes[self.position + 1] < BLOB_START_MARKER:
        nonCanonicalNumberError()
    return

  template readInt(startMarker, lenPrefixMarker) =
    var
      lengthBytes = int(marker - lenPrefixMarker)
      remainingBytes = self.bytes.len - self.position

    if remainingBytes <= lengthBytes:
      eosError()

    if remainingBytes > 1 and self.bytes[self.position + 1] == 0:
      raise newException(MalformedRlpError, "Number encoded with a leading zero")

    # check if the size is not bigger than the max that result can hold
    if lengthBytes > sizeof(result) or
      (lengthBytes == sizeof(result) and self.bytes[self.position + 1].int > 127):
      raise newException(UnsupportedRlpError, "Message too large to fit in memory")

    for i in 1 .. lengthBytes:
      result = (result shl 8) or int(self.bytes[self.position + i])

    # must be greater than the short-list size list
    if result < THRESHOLD_LIST_LEN:
      nonCanonicalNumberError()

  if marker < LIST_START_MARKER:
    readInt(BLOB_START_MARKER, LEN_PREFIXED_BLOB_MARKER)
  elif marker <= LEN_PREFIXED_LIST_MARKER:
    result = int(marker - LIST_START_MARKER)
  else:
    readInt(LIST_START_MARKER, LEN_PREFIXED_LIST_MARKER)

  readAheadCheck(result)

proc blobLen*(self: Rlp): int =
  if self.isBlob(): self.payloadBytesCount() else: 0

proc isInt*(self: Rlp): bool =
  if not self.hasData():
    return false
  var marker = self.bytes[self.position]
  if marker < BLOB_START_MARKER:
    return marker != 0
  if marker == BLOB_START_MARKER:
    return true
  if marker <= LEN_PREFIXED_BLOB_MARKER:
    return self.bytes[self.position + 1] != 0
  if marker < LIST_START_MARKER:
    let offset = self.position + int(marker + 1 - LEN_PREFIXED_BLOB_MARKER)
    if offset >= self.bytes.len: eosError()
    return self.bytes[offset] != 0
  return false

template maxBytes*(o: type[Ordinal | uint64 | uint]): int = sizeof(o)

proc toInt*(self: Rlp, IntType: type): IntType =
  # XXX: work-around a Nim issue with type parameters
  type OutputType = IntType
  mixin maxBytes, to

  # XXX: self insertions are not working in generic procs
  # https://github.com/nim-lang/Nim/issues/5053
  if not self.hasData():
    raise newException(RlpTypeMismatch, "Attempt to read an Int value past the RLP end")

  if self.isList():
    raise newException(RlpTypeMismatch, "Int expected, but found a List")

  let
    payloadStart = self.payloadOffset()
    payloadSize = self.payloadBytesCount()

  if payloadSize > maxBytes(IntType):
    raise newException(RlpTypeMismatch, "The RLP contains a larger than expected Int value")

  for i in payloadStart ..< (payloadStart + payloadSize):
    result = (result shl 8) or OutputType(self.bytes[self.position + i])

proc toString*(self: Rlp): string =
  if not self.isBlob():
    raise newException(RlpTypeMismatch, "String expected, but the source RLP is not a blob")

  let
    payloadOffset = self.payloadOffset()
    payloadLen = self.payloadBytesCount()

  result = newString(payloadLen)
  for i in 0 ..< payloadLen:
    # XXX: switch to copyMem here
    result[i] = char(self.bytes[self.position + payloadOffset + i])

proc toBytes*(self: Rlp): seq[byte] =
  if not self.isBlob():
    raise newException(RlpTypeMismatch,
                       "Bytes expected, but the source RLP in not a blob")

  let payloadLen = self.payloadBytesCount()

  if payloadLen > 0:
    let
      payloadOffset = self.payloadOffset()
      ibegin = self.position + payloadOffset
      iend = ibegin + payloadLen - 1

    result = self.bytes[ibegin..iend]

proc currentElemEnd*(self: Rlp): int =
  doAssert self.hasData()
  result = self.position

  if self.isSingleByte():
    result += 1
  elif self.isBlob() or self.isList():
    result += self.payloadOffset() + self.payloadBytesCount()

proc enterList*(self: var Rlp): bool =
  if not self.isList():
    return false

  self.position += self.payloadOffset()
  return true

proc tryEnterList*(self: var Rlp) =
  if not self.enterList():
    raise newException(RlpTypeMismatch, "List expected, but source RLP is not a list")

proc skipElem*(rlp: var Rlp) =
  rlp.position = rlp.currentElemEnd

iterator items*(self: var Rlp): var Rlp =
  doAssert self.isList()

  var
    payloadOffset = self.payloadOffset()
    payloadEnd = self.position + payloadOffset + self.payloadBytesCount()

  if payloadEnd > self.bytes.len:
    raise newException(MalformedRlpError, "List length extends past the end of the stream")

  self.position += payloadOffset

  while self.position < payloadEnd:
    let elemEnd = self.currentElemEnd()
    yield self
    self.position = elemEnd

proc listElem*(self: Rlp, i: int): Rlp =
  doAssert self.isList()
  let
    payloadOffset = self.payloadOffset()

  # This will only check if there is some data, not if it is correct according
  # to list length. Could also run here payloadBytesCount() instead.
  if self.position + payloadOffset + 1 > self.bytes.len: eosError()

  let payload = self.bytes[self.position + payloadOffset..^1]
  result = rlpFromBytes payload
  var pos = 0
  while pos < i and result.hasData:
    result.position = result.currentElemEnd()
    inc pos

proc listLen*(self: Rlp): int =
  if not self.isList():
    return 0

  var rlp = self
  for elem in rlp:
    inc result

proc readImpl(rlp: var Rlp, T: type string): string =
  result = rlp.toString
  rlp.skipElem

proc readImpl(rlp: var Rlp, T: type Integer): Integer =
  result = rlp.toInt(T)
  rlp.skipElem

proc readImpl(rlp: var Rlp, T: type[enum]): T =
  let value = rlp.toInt(int)

  var res: T
  if not checkedEnumAssign(res, value):
    raise newException(RlpTypeMismatch,
      "Enum value expected, but the source RLP is not in valid range.")
  rlp.skipElem

  res

proc readImpl(rlp: var Rlp, T: type bool): T =
  result = rlp.toInt(int) != 0
  rlp.skipElem

proc readImpl(rlp: var Rlp, T: type float64): T =
  # This is not covered in the RLP spec, but Geth uses Go's
  # `math.Float64bits`, which is defined here:
  # https://github.com/gopherjs/gopherjs/blob/master/compiler/natives/src/math/math.go
  let uint64bits = rlp.toInt(uint64)
  var uint32parts = [uint32(uint64bits), uint32(uint64bits shr 32)]
  return cast[ptr float64](unsafeAddr uint32parts)[]

proc readImpl[R, E](rlp: var Rlp, T: type array[R, E]): T =
  mixin read

  when E is (byte or char):
    if not rlp.isBlob:
      raise newException(RlpTypeMismatch, "Bytes array expected, but the source RLP is not a blob.")

    var bytes = rlp.toBytes
    if result.len != bytes.len:
      raise newException(RlpTypeMismatch, "Fixed-size array expected, but the source RLP contains a blob of different length")

    copyMem(addr result[0], unsafeAddr bytes[0], bytes.len)

    rlp.skipElem

  else:
    if not rlp.isList:
      raise newException(RlpTypeMismatch, "List expected, but the source RLP is not a list.")

    if result.len != rlp.listLen:
      raise newException(RlpTypeMismatch, "Fixed-size array expected, but the source RLP contains a list of different length")

    var i = 0
    for elem in rlp:
      result[i] = rlp.read(E)
      inc i

proc readImpl[E](rlp: var Rlp, T: type seq[E]): T =
  mixin read

  when E is (byte or char):
    result = rlp.toBytes
    rlp.skipElem
  else:
    if not rlp.isList:
      raise newException(RlpTypeMismatch, "Sequence expected, but the source RLP is not a list.")

    result = newSeqOfCap[E](rlp.listLen)

    for elem in rlp:
      result.add rlp.read(E)

proc readImpl[E](rlp: var Rlp, T: type openArray[E]): seq[E] =
  result = readImpl(rlp, seq[E])

proc readImpl(rlp: var Rlp, T: type[object|tuple],
              wrappedInList = wrapObjsInList): T =
  mixin enumerateRlpFields, read

  var payloadEnd = rlp.bytes.len
  if wrappedInList:
    if not rlp.isList:
      raise newException(RlpTypeMismatch,
                        "List expected, but the source RLP is not a list.")
    var
      payloadOffset = rlp.payloadOffset()

    # there's an exception-raising side effect in there *sigh*
    payloadEnd = rlp.position + payloadOffset + rlp.payloadBytesCount()

    rlp.position += payloadOffset

  template getUnderlyingType[T](_: Option[T]): untyped = T
  template getUnderlyingType[T](_: Opt[T]): untyped = T

  template op(RecordType, fieldName, field) =
    type FieldType {.used.} = type field
    when hasCustomPragmaFixed(RecordType, fieldName, rlpCustomSerialization):
      field = rlp.read(result, FieldType)
    elif field is Option:
      # this works for optional fields at the end of an object/tuple
      # if the optional field is followed by a mandatory field,
      # custom serialization for a field or for the parent object
      # will be better
      type UT = getUnderlyingType(field)
      if rlp.position < payloadEnd:
        field = some(rlp.read(UT))
      else:
        field = none(UT)
    elif field is Opt:
      # this works for optional fields at the end of an object/tuple
      # if the optional field is followed by a mandatory field,
      # custom serialization for a field or for the parent object
      # will be better
      type UT = getUnderlyingType(field)
      if rlp.position < payloadEnd:
        field = Opt.some(rlp.read(UT))
      else:
        field = Opt.none(UT)
    else:
      field = rlp.read(FieldType)

  enumerateRlpFields(result, op)

proc toNodes*(self: var Rlp): RlpNode =
  requireData()

  if self.isList():
    result.kind = rlpList
    newSeq result.elems, 0
    for e in self:
      result.elems.add e.toNodes
  else:
    doAssert self.isBlob()
    result.kind = rlpBlob
    result.bytes = self.toBytes()
    self.position = self.currentElemEnd()

# We define a single `read` template with a pretty low specificity
# score in order to facilitate easier overloading with user types:
template read*(rlp: var Rlp, T: type): auto =
  readImpl(rlp, T)

proc `>>`*[T](rlp: var Rlp, location: var T) =
  mixin read
  location = rlp.read(T)

template readRecordType*(rlp: var Rlp, T: type, wrappedInList: bool): auto =
  readImpl(rlp, T, wrappedInList)

proc decode*(bytes: openArray[byte]): RlpNode =
  var rlp = rlpFromBytes(bytes)
  rlp.toNodes

template decode*(bytes: openArray[byte], T: type): untyped =
  mixin read
  var rlp = rlpFromBytes(bytes)
  rlp.read(T)

template decode*(bytes: seq[byte], T: type): untyped =
  mixin read
  var rlp = rlpFromBytes(bytes)
  rlp.read(T)

proc append*(writer: var RlpWriter; rlp: Rlp) =
  appendRawBytes(writer, rlp.rawData)

proc isPrintable(s: string): bool =
  for c in s:
    if ord(c) < 32 or ord(c) >= 128:
      return false

  return true

proc inspectAux(self: var Rlp, depth: int, hexOutput: bool, output: var string) =
  if not self.hasData():
    return

  template indent =
    for i in 0..<depth:
      output.add "  "

  indent()

  if self.isSingleByte:
    output.add "byte "
    output.add $self.bytes[self.position]
  elif self.isBlob:
    let str = self.toString
    if str.isPrintable:
      output.add '"'
      output.add str
      output.add '"'
    else:
      output.add "blob(" & $str.len & ") ["
      for c in str:
        if hexOutput:
          output.add toHex(int(c), 2)
        else:
          output.add $ord(c)
          output.add ","

      if hexOutput:
        output.add ']'
      else:
        output[^1] = ']'
  else:
    output.add "{\n"
    for subitem in self:
      inspectAux(subitem, depth + 1, hexOutput, output)
      output.add "\n"
    indent()
    output.add "}"

proc inspect*(self: Rlp, indent = 0, hexOutput = true): string =
  var rlpCopy = self
  result = newStringOfCap(self.bytes.len)
  inspectAux(rlpCopy, indent, hexOutput, result)
