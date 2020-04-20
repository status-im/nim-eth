import
  stew/bitops2

type
  TrieBitSeq* = object
    ## Bit sequence as used in ethereum tries
    data: seq[byte]
    start: int
    mLen: int ## Length in bits

template `@`(s, idx: untyped): untyped =
  (when idx is BackwardsIndex: s.len - int(idx) else: int(idx))

proc bits*(a: seq[byte], start, len: int): TrieBitSeq =
  doAssert start <= len
  doAssert len <= 8 * a.len
  TrieBitSeq(data: a, start: start, mLen: len)

template bits*(a: seq[byte]): TrieBitSeq =
  bits(a, 0, a.len * 8)

template bits*(a: seq[byte], len: int): TrieBitSeq =
  bits(a, 0, len)

template bits*(a: openArray[byte], start, len: int): TrieBitSeq =
  bits(@a, start, len)

template bits*(a: openArray[byte]): TrieBitSeq =
  bits(@a, 0, a.len * 8)

template bits*(a: openArray[byte], len: int): TrieBitSeq =
  bits(@a, 0, len)

template bits*(x: TrieBitSeq): TrieBitSeq = x

proc len*(r: TrieBitSeq): int = r.mLen

iterator enumerateBits(x: TrieBitSeq): (int, bool) =
  var p = x.start
  var i = 0
  let e = x.len
  while i != e:
    yield (i, getBitBE(x.data, p))
    inc p
    inc i

iterator items*(x: TrieBitSeq): bool =
  for _, v in enumerateBits(x): yield v

iterator pairs*(x: TrieBitSeq): (int, bool) =
  for i, v in enumerateBits(x): yield (i, v)

proc `[]`*(x: TrieBitSeq, idx: int): bool =
  doAssert idx < x.len
  let p = x.start + idx
  result = getBitBE(x.data, p)

proc sliceNormalized(x: TrieBitSeq, ibegin, iend: int): TrieBitSeq =
  doAssert ibegin >= 0 and
           ibegin < x.len and
           iend < x.len and
           iend + 1 >= ibegin # the +1 here allows the result to be
                              # an empty range

  result.data  = x.data
  result.start = x.start + ibegin
  result.mLen  = iend - ibegin + 1

proc `[]`*(r: TrieBitSeq, s: HSlice): TrieBitSeq =
  sliceNormalized(r, r @ s.a, r @ s.b)

proc `==`*(a, b: TrieBitSeq): bool =
  if a.len != b.len: return false
  for i in 0 ..< a.len:
    if a[i] != b[i]: return false
  true

proc `[]=`*(r: var TrieBitSeq, idx: Natural, val: bool) =
  doAssert idx < r.len
  let absIdx = r.start + idx
  changeBitBE(r.data, absIdx, val)

proc pushFront*(x: var TrieBitSeq, val: bool) =
  doAssert x.start > 0
  dec x.start
  x[0] = val
  inc x.mLen

template neededBytes(nBits: int): int =
  (nBits shr 3) + ord((nBits and 0b111) != 0)

static:
  doAssert neededBytes(2) == 1
  doAssert neededBytes(8) == 1
  doAssert neededBytes(9) == 2

proc `&`*(a, b: TrieBitSeq): TrieBitSeq =
  let totalLen = a.len + b.len

  var bytes = newSeq[byte](totalLen.neededBytes)
  result = bits(bytes, 0, totalLen)

  for i in 0 ..< a.len: result.data.changeBitBE(i, a[i])
  for i in 0 ..< b.len: result.data.changeBitBE(i + a.len, b[i])

proc `$`*(r: TrieBitSeq): string =
  result = newStringOfCap(r.len)
  for bit in r:
    result.add(if bit: '1' else: '0')

proc fromBits*(T: type, r: TrieBitSeq, offset, num: Natural): T =
  doAssert(num <= sizeof(T) * 8)
  # XXX: Nim has a bug that a typedesc parameter cannot be used
  # in a type coercion, so we must define an alias here:
  type TT = T
  for i in 0 ..< num:
    result = (result shl 1) or TT(r[offset + i])

proc parse*(T: type TrieBitSeq, s: string): TrieBitSeq =
  var bytes = newSeq[byte](s.len.neededBytes)
  for i, c in s:
    case c
    of '0': discard
    of '1': setBitBE(bytes, i)
    else: doAssert false
  result = bits(bytes, 0, s.len)

proc toBytes*(r: TrieBitSeq): seq[byte] =
  r.data[(r.start div 8)..<((r.mLen - r.start + 7) div 8)]
