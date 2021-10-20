# nim-eth - Limited SSZ implementation
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, options, typetraits, strformat],
  stew/shims/macros, stew/[byteutils, bitops2, objects],
  nimcrypto/hash, serialization/[object_serialization, errors],
  ./bitseqs

export bitseqs

const
  offsetSize* = 4
  bytesPerChunk* = 32

type
  UintN* = SomeUnsignedInt
  BasicType* = bool|UintN

  Limit* = int64

  List*[T; maxLen: static Limit] = distinct seq[T]
  BitList*[maxLen: static Limit] = distinct BitSeq
  Digest* = MDigest[32 * 8]

  # Note for readers:
  # We use `array` for `Vector` and
  #        `BitArray` for `BitVector`

  SszError* = object of SerializationError

  MalformedSszError* = object of SszError

  SszSizeMismatchError* = object of SszError
    deserializedType*: cstring
    actualSszSize*: int
    elementSize*: int

# A few index types from here onwards:
# * dataIdx - leaf index starting from 0 to maximum length of collection
# * chunkIdx - leaf data index after chunking starting from 0
# * vIdx - virtual index in merkle tree - the root is found at index 1, its
#          two children at 2, 3 then 4, 5, 6, 7 etc

func nextPow2Int64(x: int64): int64 =
  # TODO the nextPow2 in bitops2 works with uint64 - there's a bug in the nim
  #      compiler preventing it to be used - it seems that a conversion to
  #      uint64 cannot be done with the static maxLen :(
  var v = x - 1

  # round down, make sure all bits are 1 below the threshold, then add 1
  v = v or v shr 1
  v = v or v shr 2
  v = v or v shr 4
  when bitsof(x) > 8:
    v = v or v shr 8
  when bitsof(x) > 16:
    v = v or v shr 16
  when bitsof(x) > 32:
    v = v or v shr 32

  v + 1

template dataPerChunk(T: type): int =
  # How many data items fit in a chunk
  when T is BasicType:
    bytesPerChunk div sizeof(T)
  else:
    1

template chunkIdx*(T: type, dataIdx: int64): int64 =
  # Given a data index, which chunk does it belong to?
  dataIdx div dataPerChunk(T)

template maxChunkIdx*(T: type, maxLen: Limit): int64 =
  # Given a number of data items, how many chunks are needed?
  # TODO compiler bug:
  # beacon_chain/ssz/types.nim(75, 53) Error: cannot generate code for: maxLen
  # nextPow2(chunkIdx(T, maxLen + dataPerChunk(T) - 1).uint64).int64
  nextPow2Int64(chunkIdx(T, maxLen.int64 + dataPerChunk(T) - 1))

template asSeq*(x: List): auto = distinctBase(x)

template init*[T](L: type List, x: seq[T], N: static Limit): auto =
  List[T, N](x)

template init*[T, N](L: type List[T, N], x: seq[T]): auto =
  List[T, N](x)

template `$`*(x: List): auto = $(distinctBase x)
template len*(x: List): auto = len(distinctBase x)
template low*(x: List): auto = low(distinctBase x)
template high*(x: List): auto = high(distinctBase x)
template `[]`*(x: List, idx: auto): untyped = distinctBase(x)[idx]
template `[]=`*(x: var List, idx: auto, val: auto) = distinctBase(x)[idx] = val
template `==`*(a, b: List): bool = distinctBase(a) == distinctBase(b)

template `&`*(a, b: List): auto = (type(a)(distinctBase(a) & distinctBase(b)))

template items* (x: List): untyped = items(distinctBase x)
template pairs* (x: List): untyped = pairs(distinctBase x)
template mitems*(x: var List): untyped = mitems(distinctBase x)
template mpairs*(x: var List): untyped = mpairs(distinctBase x)

template contains* (x: List, val: auto): untyped = contains(distinctBase x, val)

proc add*(x: var List, val: auto): bool =
  if x.len < x.maxLen:
    add(distinctBase x, val)
    true
  else:
    false

proc setLen*(x: var List, newLen: int): bool =
  if newLen <= x.maxLen:
    setLen(distinctBase x, newLen)
    true
  else:
    false

template init*(L: type BitList, x: seq[byte], N: static Limit): auto =
  BitList[N](data: x)

template init*[N](L: type BitList[N], x: seq[byte]): auto =
  L(data: x)

template init*(T: type BitList, len: int): auto = T init(BitSeq, len)
template len*(x: BitList): auto = len(BitSeq(x))
template bytes*(x: BitList): auto = seq[byte](x)
template `[]`*(x: BitList, idx: auto): auto = BitSeq(x)[idx]
template `[]=`*(x: var BitList, idx: auto, val: bool) = BitSeq(x)[idx] = val
template `==`*(a, b: BitList): bool = BitSeq(a) == BitSeq(b)
template setBit*(x: var BitList, idx: Natural) = setBit(BitSeq(x), idx)
template clearBit*(x: var BitList, idx: Natural) = clearBit(BitSeq(x), idx)
template overlaps*(a, b: BitList): bool = overlaps(BitSeq(a), BitSeq(b))
template incl*(a: var BitList, b: BitList) = incl(BitSeq(a), BitSeq(b))
template isSubsetOf*(a, b: BitList): bool = isSubsetOf(BitSeq(a), BitSeq(b))
template isZeros*(x: BitList): bool = isZeros(BitSeq(x))
template countOnes*(x: BitList): int = countOnes(BitSeq(x))
template countZeros*(x: BitList): int = countZeros(BitSeq(x))
template countOverlap*(x, y: BitList): int = countOverlap(BitSeq(x), BitSeq(y))
template `$`*(a: BitList): string = $(BitSeq(a))

iterator items*(x: BitList): bool =
  for i in 0 ..< x.len:
    yield x[i]

macro unsupported*(T: typed): untyped =
  # TODO: {.fatal.} breaks compilation even in `compiles()` context,
  # so we use this macro instead. It's also much better at figuring
  # out the actual type that was used in the instantiation.
  # File both problems as issues.
  error "SSZ serialization of the type " & humaneTypeName(T) & " is not supported"

template ElemType*(T: type array): untyped =
  type(default(T)[low(T)])

template ElemType*(T: type seq): untyped =
  type(default(T)[0])

template ElemType*(T0: type List): untyped =
  T0.T

func isFixedSize*(T0: type): bool {.compileTime.} =
  mixin toSszType, enumAllSerializedFields

  type T = type toSszType(declval T0)

  when T is BasicType:
    return true
  elif T is array:
    return isFixedSize(ElemType(T))
  elif T is object|tuple:
    enumAllSerializedFields(T):
      when not isFixedSize(FieldType):
        return false
    return true

func fixedPortionSize*(T0: type): int {.compileTime.} =
  mixin enumAllSerializedFields, toSszType

  type T = type toSszType(declval T0)

  when T is BasicType: sizeof(T)
  elif T is array:
    type E = ElemType(T)
    when isFixedSize(E): int(len(T)) * fixedPortionSize(E)
    else: int(len(T)) * offsetSize
  elif T is object|tuple:
    enumAllSerializedFields(T):
      when isFixedSize(FieldType):
        result += fixedPortionSize(FieldType)
      else:
        result += offsetSize
  else:
    unsupported T0

# TODO This should have been an iterator, but the VM can't compile the
# code due to "too many registers required".
proc fieldInfos*(RecordType: type): seq[tuple[name: string,
                                              offset: int,
                                              fixedSize: int,
                                              branchKey: string]] =
  mixin enumAllSerializedFields

  var
    offsetInBranch = {"": 0}.toTable
    nestedUnder = initTable[string, string]()

  enumAllSerializedFields(RecordType):
    const
      isFixed = isFixedSize(FieldType)
      fixedSize = when isFixed: fixedPortionSize(FieldType)
                  else: 0
      branchKey = when  fieldCaseDiscriminator.len == 0: ""
                  else: fieldCaseDiscriminator & ":" & $fieldCaseBranches
      fieldSize = when isFixed: fixedSize
                  else: offsetSize

    nestedUnder[fieldName] = branchKey

    var fieldOffset: int
    offsetInBranch.withValue(branchKey, val):
      fieldOffset = val[]
      val[] += fieldSize
    do:
      try:
        let parentBranch = nestedUnder.getOrDefault(fieldCaseDiscriminator, "")
        fieldOffset = offsetInBranch[parentBranch]
        offsetInBranch[branchKey] = fieldOffset + fieldSize
      except KeyError as e:
        raiseAssert e.msg

    result.add((fieldName, fieldOffset, fixedSize, branchKey))

func getFieldBoundingOffsetsImpl(RecordType: type, fieldName: static string):
    tuple[fieldOffset, nextFieldOffset: int, isFirstOffset: bool]
    {.compileTime.} =
  result = (-1, -1, false)
  var fieldBranchKey: string
  var isFirstOffset = true

  for f in fieldInfos(RecordType):
    if fieldName == f.name:
      result[0] = f.offset
      if f.fixedSize > 0:
        result[1] = result[0] + f.fixedSize
        return
      else:
        fieldBranchKey = f.branchKey
      result.isFirstOffset = isFirstOffset

    elif result[0] != -1 and
         f.fixedSize == 0 and
         f.branchKey == fieldBranchKey:
      # We have found the next variable sized field
      result[1] = f.offset
      return

    if f.fixedSize == 0:
      isFirstOffset = false

func getFieldBoundingOffsets*(RecordType: type, fieldName: static string):
    tuple[fieldOffset, nextFieldOffset: int, isFirstOffset: bool]
    {.compileTime.} =
  ## Returns the start and end offsets of a field.
  ##
  ## For fixed-size fields, the start offset points to the first
  ## byte of the field and the end offset points to 1 byte past the
  ## end of the field.
  ##
  ## For variable-size fields, the returned offsets point to the
  ## statically known positions of the 32-bit offset values written
  ## within the SSZ object. You must read the 32-bit values stored
  ## at the these locations in order to obtain the actual offsets.
  ##
  ## For variable-size fields, the end offset may be -1 when the
  ## designated field is the last variable sized field within the
  ## object. Then the SSZ object boundary known at run-time marks
  ## the end of the variable-size field.
  type T = RecordType
  anonConst getFieldBoundingOffsetsImpl(T, fieldName)

template enumerateSubFields*(holder, fieldVar, body: untyped) =
  when holder is array:
    for fieldVar in holder: body
  else:
    enumInstanceSerializedFields(holder, _{.used.}, fieldVar): body

method formatMsg*(
  err: ref SszSizeMismatchError,
  filename: string): string {.gcsafe, raises: [Defect].} =
  try:
    &"SSZ size mismatch, element {err.elementSize}, actual {err.actualSszSize}, type {err.deserializedType}, file {filename}"
  except CatchableError:
    "SSZ size mismatch"
