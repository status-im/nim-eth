import
  stew/[arraybuf, assign2, bitops2, shims/macros]

const
  BLOB_START_MARKER* = byte(0x80)
  LIST_START_MARKER* = byte(0xc0)
  THRESHOLD_LEN* = 56
  LEN_PREFIXED_BLOB_MARKER* = byte(BLOB_START_MARKER + THRESHOLD_LEN - 1)
  LEN_PREFIXED_LIST_MARKER* = byte(LIST_START_MARKER + THRESHOLD_LEN - 1)

func bytesNeeded*(num: SomeUnsignedInt): int =
  sizeof(num) - (num.leadingZeros() shr 3)
func writeBigEndian*(
    outStream: var auto, number: SomeUnsignedInt, lastByteIdx: int, numberOfBytes: int
) =
  var n = number
  for i in countdown(lastByteIdx, lastByteIdx - numberOfBytes + 1):
    outStream[i] = byte(n and 0xff)
    n = n shr 8
func prefixLength*(dataLen: int): int {.inline.} =
  return
    if dataLen < THRESHOLD_LEN:
      1
    else:
      int(uint64(dataLen).bytesNeeded) + 1

type RlpDefaultWriter* = object
  pendingLists: seq[tuple[remainingItems, startPos: int]]
  output: seq[byte]
func writeCount(writer: var RlpDefaultWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LEN:
    writer.output.add(baseMarker + byte(count))
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded
    writer.output.add baseMarker + (THRESHOLD_LEN - 1) + byte(lenPrefixBytes)
    writer.output.setLen(writer.output.len + lenPrefixBytes)
    writer.output.writeBigEndian(uint64(count), writer.output.len - 1, lenPrefixBytes)
proc maybeClosePendingLists(self: var RlpDefaultWriter) =
  while self.pendingLists.len > 0:
    let lastListIdx = self.pendingLists.len - 1
    doAssert self.pendingLists[lastListIdx].remainingItems > 0
    self.pendingLists[lastListIdx].remainingItems -= 1
    if self.pendingLists[lastListIdx].remainingItems == 0:
      let listStartPos = self.pendingLists[lastListIdx].startPos
      self.pendingLists.setLen lastListIdx
      let
        listLen = self.output.len - listStartPos
        totalPrefixBytes =
          if listLen < int(THRESHOLD_LEN):
            1
          else:
            int(uint64(listLen).bytesNeeded) + 1
      self.output.setLen(self.output.len + totalPrefixBytes)
      moveMem(
        addr self.output[listStartPos + totalPrefixBytes],
        unsafeAddr self.output[listStartPos],
        listLen,
      )
      if listLen < THRESHOLD_LEN:
        self.output[listStartPos] = LIST_START_MARKER + byte(listLen)
      else:
        let listLenBytes = totalPrefixBytes - 1
        self.output[listStartPos] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)
        self.output.writeBigEndian(
          uint64(listLen), listStartPos + listLenBytes, listLenBytes
        )
    else:
      return
func writeInt*(writer: var RlpDefaultWriter, i: SomeUnsignedInt) =
  if i == typeof(i)(0):
    writer.output.add BLOB_START_MARKER
  elif i < typeof(i)(BLOB_START_MARKER):
    writer.output.add byte(i)
  else:
    let bytesNeeded = i.bytesNeeded
    writer.writeCount(bytesNeeded, BLOB_START_MARKER)
    writer.output.setLen(writer.output.len + bytesNeeded)
    writer.output.writeBigEndian(i, writer.output.len - 1, bytesNeeded)
  writer.maybeClosePendingLists()
func appendRawBytes*(self: var RlpDefaultWriter, bytes: openArray[byte]) =
  self.output.setLen(self.output.len + bytes.len)
  assign(
    self.output.toOpenArray(self.output.len - bytes.len, self.output.len - 1), bytes
  )
  self.maybeClosePendingLists()
proc writeBlob*(self: var RlpDefaultWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    self.output.add byte(bytes[0])
    self.maybeClosePendingLists()
  else:
    self.writeCount(bytes.len, BLOB_START_MARKER)
    self.appendRawBytes(bytes)
proc startList*(self: var RlpDefaultWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
    self.maybeClosePendingLists()
  else:
    self.pendingLists.add((listSize, self.output.len))
template finish*(self: RlpDefaultWriter): seq[byte] =
  doAssert self.pendingLists.len == 0,
    "Insufficient number of elements written to a started list"
  self.output

export arraybuf
type
  RlpWriter* = RlpDefaultWriter
proc initRlpWriter*(): RlpDefaultWriter =
  result
template appendBlob(self: var RlpWriter, data: openArray[byte]) =
  self.writeBlob(data)
proc appendInt(self: var RlpWriter, i: SomeUnsignedInt) =
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
  self.appendInt(uint64(e))
template appendImpl(self: var RlpWriter, b: bool) =
  self.appendInt(uint64(b))
proc appendImpl[T](self: var RlpWriter, list: openArray[T]) =
  mixin append
  self.startList list.len
  for i in 0 ..< list.len:
    self.append list[i]
template append*[T](w: var RlpWriter, data: T) =
  appendImpl(w, data)
proc initRlpList*(listSize: int): RlpDefaultWriter =
  result = initRlpWriter()
  startList(result, listSize)
macro encodeList*(args: varargs[untyped]): seq[byte] =
  var
    listLen = args.len
    writer = genSym(nskVar, "rlpWriter")
    body = newStmtList()
    append = bindSym("append", brForceOpen)
  for arg in args:
    body.add quote do:
      `append`(`writer`, `arg`)
  result = quote:
    var `writer` = initRlpList(`listLen`)
    `body`
    move(finish(`writer`))

# Rlp reader (was rlp.nim)
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
func raiseNonCanonical() {.noreturn, noinline.} =
  raise (ref MalformedRlpError)(msg: "non-canonical encoding")
func raiseIntOutOfBounds() {.noreturn, noinline.} =
  raise (ref UnsupportedRlpError)(msg: "integer out of bounds")
template view(input: openArray[byte], slice: Slice[int]): openArray[byte] =
  if slice.b >= input.len:
    raiseOutOfBounds()
  toOpenArray(input, slice.a, slice.b)
func decodeInteger(input: openArray[byte]): uint64 =
  if input.len > sizeof(uint64):
    raiseIntOutOfBounds()
  else:
    if input[0] == 0:
      raiseNonCanonical()
    var v: uint64
    for b in input:
      v = (v shl 8) or uint64(b)
    v
func rlpItem(input: openArray[byte], start = 0): RlpItem =
  if start >= len(input):
    raiseOutOfBounds()
  let
    length = len(input) - start # >= 1
    prefix = input[start]
  if prefix <= 0x7f:
    (start .. start, rlpBlob)
  elif prefix <= 0xb7:
    let strLen = int(prefix - 0x80)
    (start + 1 .. start + strLen, rlpBlob)
  elif prefix <= 0xbf:
    let
      lenOfStrLen = int(prefix - 0xb7)
      strLen = decodeInteger(input.view(start + 1 .. start + lenOfStrLen))
    (start + 1 + lenOfStrLen .. start + lenOfStrLen + int(strLen), rlpBlob)
  elif prefix <= 0xf7:
    let listLen = int(prefix - 0xc0)
    if listLen >= length:
      raiseOutOfBounds()
    (start + 1 .. start + listLen, rlpList)
  else:
    let
      lenOfListLen = int(prefix - 0xf7)
      listLen = decodeInteger(input.view(start + 1 .. start + lenOfListLen))
    (start + 1 + lenOfListLen .. start + lenOfListLen + int(listLen), rlpList)
func item(self: Rlp, position: int): RlpItem =
  rlpItem(self.bytes, position)
func item(self: Rlp): RlpItem =
  self.item(self.position)
func rlpFromBytes*(data: openArray[byte]): Rlp =
  Rlp(bytes: @data, position: 0)
func rlpFromBytes*(data: sink seq[byte]): Rlp =
  Rlp(bytes: move(data), position: 0)
func hasData(self: Rlp, position: int): bool =
  position < self.bytes.len
func hasData*(self: Rlp): bool =
  self.hasData(self.position)
func isEmpty*(self: Rlp): bool =
  self.hasData() and (
    self.bytes[self.position] == BLOB_START_MARKER or
    self.bytes[self.position] == LIST_START_MARKER
  )
func isList(self: Rlp, position: int): bool =
  self.hasData(position) and self.bytes[position] >= LIST_START_MARKER
func isList*(self: Rlp): bool =
  self.isList(self.position)
func toBytes(self: Rlp, item: RlpItem): seq[byte] =
  if item.typ != rlpBlob:
    raiseExpectedBlob()
  @(self.bytes.view(item.payload))
func toBytes*(self: Rlp): seq[byte] =
  self.toBytes(self.item())
func currentElemEnd(self: Rlp, position: int): int =
  let item = self.item(position).payload
func currentElemEnd*(self: Rlp): int =
  self.currentElemEnd(self.position)
func enterList*(self: var Rlp): bool =
  try:
    return true
  except RlpError:
    return false
func positionAfter(rlp: var Rlp, item: RlpItem) =
  rlp.position = item.payload.b + 1
func skipElem*(rlp: var Rlp) =
  rlp.positionAfter(rlp.item())
template iterateIt(self: Rlp, position: int, body: untyped) =
  let item = self.item(position)
  var it {.inject.} = item.payload.a
  let last = item.payload.b
  while it <= last:
    let subItem = rlpItem(self.bytes.view(it .. last)).payload
    body
    it += subItem.b + 1
iterator items(self: var Rlp, item: RlpItem): var Rlp =
  doAssert item.typ == rlpList
  self.position = item.payload.a
  let last = item.payload.b
  while self.position <= last:
    let
      subItem = rlpItem(self.bytes.view(self.position .. last)).payload
      next = self.position + subItem.b + 1
    yield self
    self.position = next
iterator items*(self: var Rlp): var Rlp =
  let item = self.item()
  for item in self.items(item):
    yield item
func listElem*(self: Rlp, i: int): Rlp =
  let item = self.item()
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
template rawData*(self: Rlp): openArray[byte] =
  self.bytes.toOpenArray(self.position, self.currentElemEnd - 1)
func append*(writer: var RlpWriter, rlp: Rlp) =
  appendRawBytes(writer, rlp.rawData)
