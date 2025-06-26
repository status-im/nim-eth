# nim-eth
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## This module implements RLP encoding and decoding as
## defined in Appendix B of the Ethereum Yellow Paper:
## https://ethereum.github.io/yellowpaper/paper.pdf

import
  std/strutils,
  stew/[byteutils, shims/macros],
  results,
  ./rlp/[writer, object_serialization],
  ./rlp/priv/defs

from stew/objects import checkedEnumAssign

export writer, object_serialization

type
  Rlp* = object
    bytes: seq[byte]
    position*: int

  RlpNodeType* = enum
    rlpBlob
    rlpList

  RlpError* = object of CatchableError
  MalformedRlpError* = object of RlpError
  UnsupportedRlpError* = object of RlpError
  RlpTypeMismatch* = object of RlpError

  RlpItem = tuple[payload: Slice[int], typ: RlpNodeType]

func raiseOutOfBounds() {.noreturn, noinline.} =
  raise (ref MalformedRlpError)(msg: "out-of-bounds payload access")

func raiseExpectedBlob() {.noreturn, noinline.} =
  raise (ref RlpTypeMismatch)(msg: "expected blob")

func raiseExpectedList() {.noreturn, noinline.} =
  raise (ref RlpTypeMismatch)(msg: "expected list")

func raiseNonCanonical() {.noreturn, noinline.} =
  raise (ref MalformedRlpError)(msg: "non-canonical encoding")

func raiseIntOutOfBounds() {.noreturn, noinline.} =
  raise (ref UnsupportedRlpError)(msg: "integer out of bounds")

template view(input: openArray[byte], position: int): openArray[byte] =
  if position >= input.len:
    raiseOutOfBounds()

  toOpenArray(input, position, input.high())

template view(input: openArray[byte], slice: Slice[int]): openArray[byte] =
  if slice.b >= input.len:
    raiseOutOfBounds()

  toOpenArray(input, slice.a, slice.b)

template getPtr(x: untyped): auto =
  when (NimMajor, NimMinor) <= (1, 6):
    unsafeAddr(x)
  else:
    addr(x)

func toString(self: Rlp, item: RlpItem): string =
  result = "" # TODO https://github.com/nim-lang/Nim/issues/23645
  if item.typ != rlpBlob:
    raiseExpectedBlob()

  if 0 < item.payload.len:
    result = newString(item.payload.len)
    copyMem(addr result[0], self.bytes.view(item.payload)[0].getPtr, result.len)

func decodeInteger(input: openArray[byte]): uint64 =
  # For a positive integer, it is converted to the the shortest byte array whose
  # big-endian interpretation is the integer, and then encoded as a string
  # according to the rules below.
  if input.len > sizeof(uint64):
    raiseIntOutOfBounds()

  if input.len == 0:
    0
  else:
    if input[0] == 0:
      raiseNonCanonical()

    var v: uint64
    for b in input:
      v = (v shl 8) or uint64(b)
    v

# https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
func rlpItem(input: openArray[byte], start = 0): RlpItem =
  # Extract coordinates for the RLP item starting at `start`, ensuring that
  # it (but not necessarily its payload) is correctly encoded
  if start >= len(input):
    raiseOutOfBounds()

  let
    length = len(input) - start # >= 1
    prefix = input[start]

  if prefix <= 0x7f:
    # For a single byte whose value is in the [0x00, 0x7f] (decimal [0, 127])
    # range, that byte is its own RLP encoding.
    (start .. start, rlpBlob)
  elif prefix <= 0xb7:
    # Otherwise, if a string is 0-55 bytes long, the RLP encoding consists of a
    # single byte with value 0x80 (dec. 128) plus the length of the string
    # followed by the string. The range of the first byte is thus [0x80, 0xb7]
    # (dec. [128, 183]).
    let strLen = int(prefix - 0x80)
    if strLen >= length:
      raiseOutOfBounds()
    if strLen == 1 and input[start + 1] <= 0x7f:
      raiseNonCanonical()

    (start + 1 .. start + strLen, rlpBlob)
  elif prefix <= 0xbf:
    # If a string is more than 55 bytes long, the RLP encoding consists of a
    # single byte with value 0xb7 (dec. 183) plus the length in bytes of the
    # length of the string in binary form, followed by the length of the string,
    # followed by the string. For example, a 1024 byte long string would be
    # encoded as \xb9\x04\x00 (dec. 185, 4, 0) followed by the string.
    # Here, 0xb9 (183 + 2 = 185) as the first byte, followed by the 2 bytes
    # 0x0400 (dec. 1024) that denote the length of the actual string. The range
    # of the first byte is thus [0xb8, 0xbf] (dec. [184, 191]).

    let
      lenOfStrLen = int(prefix - 0xb7)
      strLen = decodeInteger(input.view(start + 1 .. start + lenOfStrLen))

    if strLen < THRESHOLD_LEN:
      raiseNonCanonical()

    if strLen >= uint64(length - lenOfStrLen):
      raiseOutOfBounds()

    (start + 1 + lenOfStrLen .. start + lenOfStrLen + int(strLen), rlpBlob)
  elif prefix <= 0xf7:
    # If the total payload of a list (i.e. the combined length of all its items
    # being RLP encoded) is 0-55 bytes long, the RLP encoding consists of a
    # single byte with value 0xc0 plus the length of the payload followed by the
    # concatenation of the RLP encodings of the items. The range of the first
    # byte is thus [0xc0, 0xf7] (dec. [192, 247]).
    let listLen = int(prefix - 0xc0)
    if listLen >= length:
      raiseOutOfBounds()

    (start + 1 .. start + listLen, rlpList)
  else:
    # If the total payload of a list is more than 55 bytes long, the RLP
    # encoding consists of a single byte with value 0xf7 plus the length in
    # bytes of the length of the payload in binary form, followed by the length
    # of the payload, followed by the concatenation of the RLP encodings of the
    # items. The range of the first byte is thus [0xf8, 0xff] (dec. [248, 255]).
    let
      lenOfListLen = int(prefix - 0xf7)
      listLen = decodeInteger(input.view(start + 1 .. start + lenOfListLen))

    if listLen < THRESHOLD_LEN:
      raiseNonCanonical()

    if listLen >= uint64(length - lenOfListLen):
      raiseOutOfBounds()

    (start + 1 + lenOfListLen .. start + lenOfListLen + int(listLen), rlpList)

func item(self: Rlp, position: int): RlpItem =
  rlpItem(self.bytes, position)

func item(self: Rlp): RlpItem =
  self.item(self.position)

func rlpFromBytes*(data: openArray[byte]): Rlp =
  Rlp(bytes: @data, position: 0)

func rlpFromBytes*(data: sink seq[byte]): Rlp =
  Rlp(bytes: move(data), position: 0)

const zeroBytesRlp* = Rlp()

func rlpFromHex*(input: string): Rlp =
  Rlp(bytes: hexToSeqByte(input), position: 0)

func hasData(self: Rlp, position: int): bool =
  position < self.bytes.len

func hasData*(self: Rlp): bool =
  self.hasData(self.position)

func isBlob(self: Rlp, position: int): bool =
  self.hasData(position) and self.bytes[position] < LIST_START_MARKER

func isBlob*(self: Rlp): bool =
  self.isBlob(self.position)

func isEmpty*(self: Rlp): bool =
  ### Contains a blob or a list of zero length
  self.hasData() and (
    self.bytes[self.position] == BLOB_START_MARKER or
    self.bytes[self.position] == LIST_START_MARKER
  )

func isList(self: Rlp, position: int): bool =
  self.hasData(position) and self.bytes[position] >= LIST_START_MARKER

func isList*(self: Rlp): bool =
  self.isList(self.position)

func isSingleByte(self: Rlp, position: int): bool =
  self.hasData(position) and self.bytes[position] < BLOB_START_MARKER

func isSingleByte*(self: Rlp): bool =
  self.isSingleByte(self.position)

func getByteValue*(self: Rlp): byte =
  doAssert self.isSingleByte()
  self.bytes[self.position]

func readRawByte*(self: var Rlp): byte =
  ### Read a raw byte that is not RLP encoded
  ### This is sometimes used to communicate union type information
  doAssert self.hasData
  let res = self.bytes[self.position]
  inc self.position
  res

func blobLen*(self: Rlp): int =
  if self.isBlob():
    self.item().payload.len()
  else:
    0

func isInt*(self: Rlp): bool =
  if not self.hasData():
    return false
  let item = self.item()
  item.typ == rlpBlob and (
    item.payload.len() == 0 or
    self.bytes[item.payload.a] != 0)

template maxBytes*(o: type[Ordinal | uint64 | uint]): int =
  sizeof(o)

func toInt(self: Rlp, item: RlpItem, IntType: type): IntType =
  mixin maxBytes, to
  if item.typ != rlpBlob:
    raiseExpectedBlob()

  if item.payload.len > maxBytes(IntType):
    raiseIntOutOfBounds()

  for b in self.bytes.view(item.payload):
    result = (result shl 8) or IntType(b)

func toInt*(self: Rlp, IntType: type): IntType =
  self.toInt(self.item(), IntType)

func toString*(self: Rlp): string =
  # TODO https://github.com/nim-lang/Nim/issues/23645
  # the returnd string is cleared properly on exception here - the double
  # result assignment can be removed once that bug is fixed
  result = ""
  result = self.toString(self.item())

func toBytes(self: Rlp, item: RlpItem): seq[byte] =
  if item.typ != rlpBlob:
    raiseExpectedBlob()

  @(self.bytes.view(item.payload))

func toBytes*(self: Rlp): seq[byte] =
  self.toBytes(self.item())

func currentElemEnd(self: Rlp, position: int): int =
  let item = self.item(position).payload
  item.b + 1

func currentElemEnd*(self: Rlp): int =
  self.currentElemEnd(self.position)

func enterList*(self: var Rlp): bool =
  try: # TODO Refactor to remove exception here..
    let item = self.item()
    if item.typ != rlpList:
      return false

    self.position = item.payload.a
    return true
  except RlpError:
    return false

func tryEnterList*(self: var Rlp) =
  if not self.enterList():
    raiseExpectedList()

func positionAfter(rlp: var Rlp, item: RlpItem) =
  rlp.position = item.payload.b + 1

func positionAt(rlp: var Rlp, item: RlpItem) =
  rlp.position = item.payload.a

func skipElem*(rlp: var Rlp) =
  doAssert rlp.hasData()
  rlp.positionAfter(rlp.item())

template iterateIt(self: Rlp, position: int, body: untyped) =
  let item = self.item(position)
  doAssert item.typ == rlpList
  var it {.inject.} = item.payload.a
  let last = item.payload.b
  while it <= last:
    let subItem = rlpItem(self.bytes.view(it .. last)).payload
    body
    it += subItem.b + 1

iterator items(self: var Rlp, item: RlpItem): var Rlp =
  # Iterate over items while updating "current" element view, mutating self
  doAssert item.typ == rlpList

  self.position = item.payload.a
  let last = item.payload.b
  while self.position <= last:
    let
      subItem = rlpItem(self.bytes.view(self.position .. last)).payload
      next = self.position + subItem.b + 1
    yield self
    self.position = next # self.position might have changed during yield

iterator items*(self: var Rlp): var Rlp =
  # Iterate over items while updating "current" element view, mutating self
  let item = self.item()
  for item in self.items(item):
    yield item

func listElem*(self: Rlp, i: int): Rlp =
  let item = self.item()
  doAssert item.typ == rlpList

  var
    i = i
    start = item.payload.a
    payload = rlpItem(self.bytes.view(start .. item.payload.b)).payload

  while i > 0:
    start += payload.b + 1
    payload = rlpItem(self.bytes.view(start .. item.payload.b)).payload
    dec i

  rlpFromBytes self.bytes.view(start .. start + payload.b)

func listLen*(self: Rlp): int =
  if not self.isList():
    return 0

  self.iterateIt(self.position):
    inc result

func readImpl(rlp: var Rlp, T: type string): string =
  let item = rlp.item()
  result = rlp.toString(item)
  rlp.positionAfter(item)

func readImpl(rlp: var Rlp, T: type SomeUnsignedInt): T =
  let item = rlp.item()
  result = rlp.toInt(item, T)
  rlp.positionAfter(item)

func readImpl(rlp: var Rlp, T: type[enum]): T =
  let
    item = rlp.item()
    value = rlp.toInt(item, uint64)

  var res: T
  if not checkedEnumAssign(res, value):
    raise newException(
      RlpTypeMismatch, "Enum value expected, but the source RLP is not in valid range."
    )
  rlp.positionAfter(item)

  res

func readImpl(rlp: var Rlp, T: type bool): T =
  rlp.readImpl(uint64) != 0

func readImpl[R, E](rlp: var Rlp, T: type array[R, E]): T =
  mixin read

  let item = rlp.item()
  when E is (byte or char):
    if item.typ != rlpBlob:
      raiseExpectedBlob()

    if item.payload.len != result.len:
      raise newException(
        RlpTypeMismatch,
        "Fixed-size array expected, but the source RLP contains a blob of different length",
      )

    copyMem(addr result[0], unsafeAddr rlp.bytes[item.payload.a], result.len)
  else:
    if result.len != rlp.listLen:
      raise newException(
        RlpTypeMismatch,
        "Fixed-size array expected, but the source RLP contains a list of different length",
      )

    var i = 0
    for elem in rlp.items(item):
      result[i] = rlp.read(E)
      inc i

  rlp.positionAfter(item)

func readImpl[E](rlp: var Rlp, T: type seq[E]): T =
  mixin read
  let item = rlp.item()
  when E is byte:
    result = rlp.toBytes(item)
  else:
    if item.typ != rlpList:
      raiseExpectedList()

    result = newSeqOfCap[E](rlp.listLen)

    for elem in rlp.items():
      result.add rlp.read(E)

  rlp.positionAfter(item)

func readImpl[E](rlp: var Rlp, T: type openArray[E]): seq[E] =
  readImpl(rlp, seq[E])

func readImpl(
    rlp: var Rlp, T: type[object | tuple], wrappedInList = wrapObjsInList
): T =
  mixin enumerateRlpFields, read

  let payloadEnd =
    if wrappedInList:
      let item = rlp.item()
      if item.typ != rlpList:
        raiseExpectedList()

      rlp.positionAt(item)
      item.payload.b + 1
    else:
      rlp.bytes.len()

  template getUnderlyingType[T](_: Opt[T]): untyped =
    T

  template op(RecordType, fieldName, field) {.used.} =
    type FieldType {.used.} = type field
    when hasCustomPragmaFixed(RecordType, fieldName, rlpCustomSerialization):
      field = rlp.read(result, FieldType)
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

proc validate(self: Rlp, position: int) =
  var item = self.item(position)
  while true:
    if item.typ == rlpList:
      self.iterateIt(item.payload.a):
        self.validate(it)

    if item.payload.b >= self.bytes.high():
      break

    item = self.item(item.payload.b + 1)

func validate*(self: Rlp) =
  self.validate(self.position)

# We define a single `read` template with a pretty low specificity
# score in order to facilitate easier overloading with user types:
template read*(rlp: var Rlp, T: type): auto =
  when T is SomeSignedInt:
    {.error "Signed integer encoding is not defined for rlp".}
  else:
    readImpl(rlp, T)

func `>>`*[T](rlp: var Rlp, location: var T) =
  mixin read
  location = rlp.read(T)

template readRecordType*(rlp: var Rlp, T: type, wrappedInList: bool): auto =
  readImpl(rlp, T, wrappedInList)

template decode*(bytes: openArray[byte], T: type): untyped =
  mixin read
  var rlp = rlpFromBytes(bytes)
  rlp.read(T)

template decode*(bytes: seq[byte], T: type): untyped =
  mixin read
  var rlp = rlpFromBytes(bytes)
  rlp.read(T)

template rawData*(self: Rlp): openArray[byte] =
  self.bytes.toOpenArray(self.position, self.currentElemEnd - 1)

func append*(writer: var RlpWriter, rlp: Rlp) =
  appendRawBytes(writer, rlp.rawData)

func isPrintable(s: string): bool =
  for c in s:
    if ord(c) < 32 or ord(c) >= 128:
      return false

  return true

func renderBlob(self: var Rlp, hexOutput: bool, output: var string) =
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

func inspectAux(self: var Rlp, depth: int, hexOutput: bool, output: var string) =
  if not self.hasData():
    return

  template indent() =
    for i in 0 ..< depth:
      output.add "  "

  indent()

  if self.isSingleByte:
    output.add "byte "
    output.add $self.bytes[self.position]
  elif self.isBlob:
    self.renderBlob(hexOutput, output)
  else:
    output.add "{\n"
    for subitem in self.items:
      inspectAux(subitem, depth + 1, hexOutput, output)
      output.add "\n"
    indent()
    output.add "}"

func inspect*(self: Rlp, indent = 0, hexOutput = true): string =
  var rlpCopy = self
  result = newStringOfCap(self.bytes.len)
  inspectAux(rlpCopy, indent, hexOutput, result)
