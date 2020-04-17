import
  random, sets, eth/trie/trie_utils as ethUtils,
  eth/rlp/types as rlpTypes, stew/ranges/bitranges,
  nimcrypto/[utils, sysrand]

type
  RandGen*[T] = object
    minVal, maxVal: T

  KVPair* = ref object
    key*: string
    value*: string

proc randGen*[T](minVal, maxVal: T): RandGen[T] =
  doAssert(minVal <= maxVal)
  result.minVal = minVal
  result.maxVal = maxVal

proc randGen*[T](minMax: T): RandGen[T] =
  randGen(minMax, minMax)

proc getVal*[T](x: RandGen[T]): T =
  if x.minVal == x.maxVal: return x.minVal
  rand(x.minVal..x.maxVal)

proc randString*(len: int): string =
  result = newString(len)
  for i in 0..<len:
    result[i] = rand(255).char

proc randBytes*(len: int): Bytes =
  result = newSeq[byte](len)
  discard randomBytes(result[0].addr, len)

proc toBytesRange*(str: string): BytesRange =
  var s: seq[byte]
  if str[0] == '0' and str[1] == 'x':
    s = fromHex(str.substr(2))
  else:
    s = newSeq[byte](str.len)
    for i in 0 ..< str.len:
      s[i] = byte(str[i])
  result = s.toRange

proc randPrimitives*[T](val: int): T =
  when T is string:
    randString(val)
  elif T is int:
    result = val
  elif T is BytesRange:
    result = randString(val).toRange
  elif T is Bytes:
    result = randBytes(val)

proc randList*(T: typedesc, strGen, listGen: RandGen, unique: bool = true): seq[T] =
  let listLen = listGen.getVal()
  result = newSeqOfCap[T](listLen)
  if unique:
    var set = initHashSet[T]()
    for len in 0..<listLen:
      while true:
        let x = randPrimitives[T](strGen.getVal())
        if x notin set:
          result.add x
          set.incl x
          break
  else:
    for len in 0..<listLen:
      let x = randPrimitives[T](strGen.getVal())
      result.add x

proc randKVPair*(keySize = 32): seq[KVPair] =
  const listLen = 100
  let keys = randList(string, randGen(keySize, keySize), randGen(listLen, listLen))
  let vals = randList(string, randGen(1, 100), randGen(listLen, listLen))

  result = newSeq[KVPair](listLen)
  for i in 0..<listLen:
    result[i] = KVPair(key: keys[i], value: vals[i])

proc toBytes*(str: string): Bytes =
  result = newSeq[byte](str.len)
  for i in 0..<str.len:
    result[i] = byte(str[i])

proc genBitVec*(len: int): BitRange =
  let k = ((len + 7) and (not 7)) shr 3
  var s = newSeq[byte](k)
  result = bits(s, len)
  for i in 0..<len:
    result[i] = rand(2) == 1
