type
  NibblesSeq* = object
    bytes: seq[byte]
    ibegin, iend: int

proc initNibbleRange*(bytes: openArray[byte]): NibblesSeq =
  result.bytes = @bytes
  result.ibegin = 0
  result.iend = bytes.len * 2

proc `{}`(r: NibblesSeq, pos: int): byte {.inline.} =
  ## This is a helper for a more raw access to the nibbles.
  ## It works with absolute positions.
  if pos > r.iend: raise newException(RangeError, "index out of range")
  return if (pos and 1) != 0: (r.bytes[pos div 2] and 0xf)
         else: (r.bytes[pos div 2] shr 4)

template `[]`*(r: NibblesSeq, i: int): byte = r{r.ibegin + i}

proc len*(r: NibblesSeq): int =
  r.iend - r.ibegin

proc `==`*(lhs, rhs: NibblesSeq): bool =
  if lhs.len == rhs.len:
    for i in 0 ..< lhs.len:
      if lhs[i] != rhs[i]:
        return false
    return true
  else:
    return false

proc `$`*(r: NibblesSeq): string =
  result = newStringOfCap(100)
  for i in r.ibegin ..< r.iend:
    let n = int r{i}
    let c = if n > 9: char(ord('a') + n - 10)
            else: char(ord('0') + n)
    result.add c

proc slice*(r: NibblesSeq, ibegin: int, iend = -1): NibblesSeq =
  result.bytes = r.bytes
  result.ibegin = r.ibegin + ibegin
  let e = if iend < 0: r.iend + iend + 1
          else: r.ibegin + iend
  doAssert ibegin >= 0 and e <= result.bytes.len * 2
  result.iend = e

template writeFirstByte(nibbleCountExpr) {.dirty.} =
  let nibbleCount = nibbleCountExpr
  var oddnessFlag = (nibbleCount and 1) != 0
  newSeq(result, (nibbleCount div 2) + 1)
  result[0] = byte((int(isLeaf) * 2 + int(oddnessFlag)) shl 4)
  var writeHead = 0

template writeNibbles(r) {.dirty.} =
  for i in r.ibegin ..< r.iend:
    let nextNibble = r{i}
    if oddnessFlag:
      result[writeHead] = result[writeHead] or nextNibble
    else:
      inc writeHead
      result[writeHead] = nextNibble shl 4
    oddnessFlag = not oddnessFlag

proc hexPrefixEncode*(r: NibblesSeq, isLeaf = false): seq[byte] =
  writeFirstByte(r.len)
  writeNibbles(r)

proc hexPrefixEncode*(r1, r2: NibblesSeq, isLeaf = false): seq[byte] =
  writeFirstByte(r1.len + r2.len)
  writeNibbles(r1)
  writeNibbles(r2)

proc hexPrefixEncodeByte*(val: byte, isLeaf = false): byte =
  doAssert val < 16
  result = (((byte(isLeaf) * 2) + 1) shl 4) or val

proc sharedPrefixLen*(lhs, rhs: NibblesSeq): int =
  result = 0
  while result < lhs.len and result < rhs.len:
    if lhs[result] != rhs[result]: break
    inc result

proc startsWith*(lhs, rhs: NibblesSeq): bool =
  sharedPrefixLen(lhs, rhs) == rhs.len

proc hexPrefixDecode*(r: openArray[byte]): tuple[isLeaf: bool, nibbles: NibblesSeq] =
  result.nibbles = initNibbleRange(r)
  if r.len > 0:
    result.isLeaf = (r[0] and 0x20) != 0
    let hasOddLen = (r[0] and 0x10) != 0
    result.nibbles.ibegin = 2 - int(hasOddLen)
  else:
    result.isLeaf = false

template putNibble(bytes, x: untyped) =
  if odd:
    bytes[pos] = (bytes[pos] and 0xF0) or x
    inc pos
  else:
    bytes[pos] = x shl 4

template putNibbles(bytes, src: untyped) =
  for i in 0 ..< src.len:
    bytes.putNibble(src[i])
    odd = not odd

template calcNeededBytes(len: int): int =
  (len shr 1) + (len and 1)

proc `&`*(a, b: NibblesSeq): NibblesSeq =
  let
    len = a.len + b.len
    bytesNeeded = calcNeededBytes(len)

  var
    bytes = newSeq[byte](bytesNeeded)
    odd   = false
    pos   = 0

  bytes.putNibbles(a)
  bytes.putNibbles(b)

  result = initNibbleRange(bytes)
  result.iend = len

proc cloneAndReserveNibble*(a: NibblesSeq): NibblesSeq =
  let
    len = a.len + 1
    bytesNeeded = calcNeededBytes(len)

  var
    bytes = newSeq[byte](bytesNeeded)
    odd   = false
    pos   = 0

  bytes.putNibbles(a)
  result = initNibbleRange(bytes)
  result.iend = len

proc replaceLastNibble*(a: var NibblesSeq, b: byte) =
  var
    odd = (a.len and 1) == 0
    pos = (a.len shr 1) - odd.int

  putNibble(a.bytes, b)

proc getBytes*(a: NibblesSeq): seq[byte] =
  a.bytes
