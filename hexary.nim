import
  std/[tables, hashes, sets],
  nimcrypto/keccak,
  ./writer,
  ./hashes as common_hashes
export common_hashes
import stew/[arraybuf, arrayops, bitops2, endians2, staticfor]
export arraybuf

type
  TrieError* = object of CatchableError
  PersistenceFailure* = object of TrieError
  CorruptedTrieDatabase* = object of Defect
const
  emptyRlp* = @[128.byte]
  emptyRlpHash* = hash32"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
template traceGet(k, v) = discard
template tracePut(k, v) = discard
template traceDel(k) = discard

type
  MemDBRec = object
    refCount: int
    value: seq[byte]
  MemoryLayer = ref object of RootObj
    records: Table[seq[byte], MemDBRec]
    deleted: HashSet[seq[byte]]
  TrieDatabaseRef* = ref object
    obj: RootRef
    getProc: proc (db: RootRef, key: openArray[byte]): seq[byte] {.gcsafe, raises: [].}
    mostInnerTransaction: DbTransaction
  DbTransaction = ref object
    db: TrieDatabaseRef
    parentTransaction: DbTransaction
    modifications: MemoryLayer
proc put*(db: TrieDatabaseRef, key, val: openArray[byte]) {.gcsafe.}
proc get*(db: TrieDatabaseRef, key: openArray[byte]): seq[byte] {.gcsafe.}
proc del*(db: TrieDatabaseRef, key: openArray[byte]) {.gcsafe.}
proc get(db: MemoryLayer, key: openArray[byte]): seq[byte] =
  result = db.records.getOrDefault(@key).value
  traceGet key, result
proc del(db: MemoryLayer, key: openArray[byte]) =
  traceDel key
  if key != emptyRlpHash.data:
    let key = @key
    db.records.withValue(key, v):
      dec v.refCount
      if v.refCount <= 0:
        db.records.del(key)
        db.deleted.incl(key)
proc put(db: MemoryLayer, key, val: openArray[byte]) =
  tracePut key, val
  let key = @key
  db.deleted.excl(key)
  if key.len != 32:
    db.records[key] = MemDBRec(refCount: 1, value: @val)
  else:
    db.records.withValue(key, v) do:
      inc v.refCount
      if v.value != val: v.value = @val
    do:
      db.records[key] = MemDBRec(refCount: 1, value: @val)
proc newMemoryLayer: MemoryLayer =
  result.new
  result.records = initTable[seq[byte], MemDBRec]()
  result.deleted = initHashSet[seq[byte]]()
proc beginTransaction(db: TrieDatabaseRef): DbTransaction =
  new result
  result.db = db
  result.modifications = newMemoryLayer()
  result.parentTransaction = db.mostInnerTransaction
  db.mostInnerTransaction = result
proc newMemoryDB*: TrieDatabaseRef =
  new result
  discard result.beginTransaction
  put(result, emptyRlpHash.data, emptyRlp)
proc put*(db: TrieDatabaseRef, key, val: openArray[byte]) =
  var t = db.mostInnerTransaction
  if t != nil:
    t.modifications.put(key, val)
proc get*(db: TrieDatabaseRef, key: openArray[byte]): seq[byte] =
  let key = @key
  var t = db.mostInnerTransaction
  while t != nil:
    result = t.modifications.records.getOrDefault(key).value
    if result.len > 0 or key in t.modifications.deleted:
      return
    t = t.parentTransaction
  if db.getProc != nil:
    result = db.getProc(db.obj, key)
proc del*(db: TrieDatabaseRef, key: openArray[byte]) =
  var t = db.mostInnerTransaction
  if t != nil:
    t.modifications.del(key)

{.push gcsafe, inline.}
type
  NibblesBuf* = object
    limbs: array[4, uint64]
    iend: uint8
  HexPrefixBuf* = ArrayBuf[33, byte]
func nibble*(T: type NibblesBuf, nibble: byte): T =
  result.limbs[0] = uint64(nibble) shl (64 - 4)
  result.iend = 1
template limb(i: int | uint8): uint8 =
  uint8(i) shr 4
template shift(i: int | uint8): uint8 =
  60 - ((uint8(i) mod 16) shl 2)
func `[]`*(r: NibblesBuf, i: int): byte =
  let
    ilimb = i.limb
    ishift = i.shift
  byte((r.limbs[ilimb] shr ishift) and 0x0f)
func fromBytes*(T: type NibblesBuf, bytes: openArray[byte]): T =
  if bytes.len >= 32:
    result.iend = 64
    staticFor i, 0 ..< result.limbs.len:
      const pos = i * 8
      result.limbs[i] = uint64.fromBytesBE(bytes.toOpenArray(pos, pos + 7))
  else:
    let blen = uint8(bytes.len)
    result.iend = blen * 2
    block done:
      staticFor i, 0 ..< result.limbs.len:
        const pos = i * 8
        if pos + 7 < blen:
          result.limbs[i] = uint64.fromBytesBE(bytes.toOpenArray(pos, pos + 7))
        else:
          if pos < blen:
            var tmp = 0'u64
            var shift = 56'u8
            for j in uint8(pos) ..< blen:
              tmp = tmp or uint64(bytes[j]) shl shift
              shift -= 8
            result.limbs[i] = tmp
          break done
func len*(r: NibblesBuf): int =
  int(r.iend)
func `==`*(lhs, rhs: NibblesBuf): bool =
  if lhs.iend != rhs.iend:
    return false
  staticFor i, 0 ..< lhs.limbs.len:
    if uint8(i * 16) >= lhs.iend:
      return true
    if lhs.limbs[i] != rhs.limbs[i]:
      return false
  true
func sharedPrefixLen*(lhs, rhs: NibblesBuf): int =
  let len = min(lhs.iend, rhs.iend)
  staticFor i, 0 ..< lhs.limbs.len:
    const pos = i * 16
    if (pos + 16) >= len or lhs.limbs[i] != rhs.limbs[i]:
      return
        if pos < len:
          let mask =
            if len - pos >= 16:
              0'u64
            else:
              (not 0'u64) shr ((len - pos) * 4)
          pos + leadingZeros((lhs.limbs[i] xor rhs.limbs[i]) or mask) shr 2
        else:
          pos
  64
func slice*(r: NibblesBuf, ibegin: int, iend = -1): NibblesBuf =
  let e =
    if iend < 0:
      min(64, r.len + iend + 1)
    else:
      min(64, iend)
  result.iend = uint8(e - ibegin)
  var ilimb = ibegin.limb
  block done:
    let shift = (ibegin mod 16) shl 2
    if shift == 0:
      staticFor i, 0 ..< result.limbs.len:
        if uint8(i * 16) >= result.iend:
          break done
        result.limbs[i] = r.limbs[ilimb]
        ilimb += 1
    else:
      staticFor i, 0 ..< result.limbs.len:
        if uint8(i * 16) >= result.iend:
          break done
        let cur = r.limbs[ilimb] shl shift
        ilimb += 1
        result.limbs[i] =
          if (ilimb * 16) < uint8 r.iend:
            let next = r.limbs[ilimb] shr (64 - shift)
            cur or next
          else:
            cur
  if result.iend mod 16 > 0:
    let
      elimb = result.iend.limb
      eshift = result.iend.shift + 4
template copyshr(aend: uint8) =
  block adone:
    staticFor i, 0 ..< result.limbs.len:
      if uint8(i * 16) >= aend:
        break adone
  block bdone:
    let shift = (aend mod 16) shl 2
    var alimb = aend.limb
    if shift == 0:
      staticFor i, 0 ..< result.limbs.len:
        if uint8(i * 16) >= b.iend:
          break bdone
func `&`*(a, b: NibblesBuf): NibblesBuf =
  let aend = a.iend
func toHexPrefix*(r: NibblesBuf, isLeaf = false): HexPrefixBuf =
  result.n = 33
  let
    limbs = (r.iend + 15).limb
    isOdd = (r.iend and 1) > 0
  result[0] = (byte(isLeaf) * 2 + byte(isOdd)) shl 4
  if isOdd:
    staticFor i, 0 ..< r.limbs.len:
        let next =
          when i == r.limbs.high:
            0'u64
          else:
            r.limbs[i + 1]
        let limb = r.limbs[i] shl 4 or next shr 60
        const pos = i * 8 + 1
  else:
    staticFor i, 0 ..< r.limbs.len:
        let limb = r.limbs[i]
        const pos = i * 8 + 1
        assign(result.data.toOpenArray(pos, pos + 7), limb.toBytesBE())
func fromHexPrefix*(
    T: type NibblesBuf, bytes: openArray[byte]
): tuple[isLeaf: bool, nibbles: NibblesBuf] =
  if bytes.len > 0:
    result.isLeaf = (bytes[0] and 0x20) != 0
    let hasOddLen = (bytes[0] and 0x10) != 0
    if hasOddLen:
      let high = uint8(min(31, bytes.len - 1))
      result.nibbles =
        NibblesBuf.fromBytes(bytes.toOpenArray(1, int high))
  else:
    result.nibbles.iend = 0
{.pop.}

type
  TrieNodeKey = object
    hash: Hash32
    usedBytes: uint8
  DB = TrieDatabaseRef
  HexaryTrie* = object
    db*: DB
    root: TrieNodeKey
    isPruning: bool
template len(key: TrieNodeKey): int =
  key.usedBytes.int
template asDbKey(k: TrieNodeKey): untyped =
  k.hash.data
proc expectHash(r: Rlp): seq[byte] =
    raise newException(
      RlpTypeMismatch,
      "RLP expected to be a Keccak hash value, but has an incorrect length",
    )
proc dbPut(db: DB, data: openArray[byte]): TrieNodeKey {.gcsafe, raises: [].}
template get(db: DB, key: Rlp): seq[byte] =
  db.get(key.expectHash)
proc initHexaryTrie*(db: DB, isPruning = true): HexaryTrie {.raises: [].} =
  result.db = db
  result.root = result.db.dbPut(emptyRlp)
proc rootHash*(t: HexaryTrie): Hash32 =
  t.root.hash
template prune(t: HexaryTrie, x: openArray[byte]) =
    t.db.del(x)
proc getLocalBytes(x: TrieNodeKey): seq[byte] =
  x.hash.data[0 ..< x.usedBytes]
template keyToLocalBytes(db: DB, k: TrieNodeKey): seq[byte] =
  if k.len < 32:
    k.getLocalBytes
  else:
    db.get(k.asDbKey)
template extensionNodeKey(r: Rlp): auto =
  NibblesBuf.fromHexPrefix r.listElem(0).toBytes
template getNode(elem: untyped): untyped =
  if elem.isList:
    @(elem.rawData)
  else:
    get(db, elem.expectHash)
proc getBranchAux(
    db: DB, node: openArray[byte], path: NibblesBuf, output: var seq[seq[byte]]
) =
  var nodeRlp = rlpFromBytes node
  if not nodeRlp.hasData or nodeRlp.isEmpty:
    return
  case nodeRlp.listLen
  of 2:
    let (isLeaf, k) = nodeRlp.extensionNodeKey
    let sharedNibbles = sharedPrefixLen(path, k)
    if sharedNibbles == k.len:
      let value = nodeRlp.listElem(1)
      if not isLeaf:
        let nextLookup = value.getNode
      var branch = nodeRlp.listElem(path[0].int)
      if not branch.isEmpty:
        let nextLookup = branch.getNode
  else:
    raise newException(
      CorruptedTrieDatabase, "HexaryTrie node with an unexpected number of children"
    )
proc getBranch*(self: HexaryTrie, key: openArray[byte]): seq[seq[byte]] =
  var node = keyToLocalBytes(self.db, self.root)
  getBranchAux(self.db, node, NibblesBuf.fromBytes(key), result)
proc dbPut(db: DB, data: openArray[byte]): TrieNodeKey {.raises: [].} =
  result.usedBytes = 32
  put(db, result.asDbKey, data)
proc appendAndSave(rlpWriter: var RlpWriter, data: openArray[byte], db: DB) =
    var nodeKey = dbPut(db, data)
proc isTrieBranch(rlp: Rlp): bool =
  rlp.isList and (var len = rlp.listLen; len == 2 or len == 17)
proc hexPrefixEncode(k: NibblesBuf, v: bool): seq[byte] =
  @(k.toHexPrefix(v).data())
proc replaceValue(data: Rlp, key: NibblesBuf, value: openArray[byte]): seq[byte] =
  if data.isEmpty:
    let prefix = hexPrefixEncode(key, true)
    return encodeList(prefix, value)
  var iter = data
  for i in 0 ..< 16:
    iter.skipElem
proc mergeAt(
  self: var HexaryTrie,
  orig: Rlp,
  origHash: Hash32,
  key: NibblesBuf,
  value: openArray[byte],
  isInline = false,
): seq[byte] {.gcsafe, raises: [RlpError].}
proc mergeAt(
    self: var HexaryTrie,
    rlp: Rlp,
    key: NibblesBuf,
    value: openArray[byte],
    isInline = false,
): seq[byte] =
  self.mergeAt(rlp, rlp.rawData.keccak256, key, value, isInline)
proc mergeAtAux(
    self: var HexaryTrie,
    output: var RlpWriter,
    orig: Rlp,
    key: NibblesBuf,
    value: openArray[byte],
) =
  var resolved = orig
  var isRemovable = false
  if not (orig.isList or orig.isEmpty):
    isRemovable = true
  let b = self.mergeAt(resolved, key, value, not isRemovable)
proc mergeAt(
    self: var HexaryTrie,
    orig: Rlp,
    origHash: Hash32,
    key: NibblesBuf,
    value: openArray[byte],
    isInline = false,
): seq[byte] {.gcsafe, raises: [RlpError].} =
  template origWithNewValue(): auto =
    replaceValue(orig, key, value)
  if orig.isEmpty:
    return origWithNewValue()
    let (isLeaf, k) = orig.extensionNodeKey
    var origValue = orig.listElem(1)
    if k == key and isLeaf:
      return origWithNewValue()
    let sharedNibbles = sharedPrefixLen(key, k)
    if sharedNibbles == k.len and not isLeaf:
      var branches = initRlpList(17)
      if k.len == 0:
        for i in 0 ..< 16:
          branches.append ""
        let n = k[0]
        for i in 0 ..< 16:
              let childNode = encodeList(hexPrefixEncode(k.slice(1), isLeaf), origValue)
  else:
    if key.len == 0:
      return origWithNewValue()
    let n = key[0]
    var i = 0
    var r = initRlpList(17)
    var origCopy = orig
    for elem in items(origCopy):
      if i == int(n):
        self.mergeAtAux(r, elem, key.slice(1), value)
proc put*(self: var HexaryTrie, key, value: openArray[byte]) =
  if value.len == 0:
    return
  let root = self.root.hash
  var rootBytes = self.db.get(root.data)
  let newRootBytes =
    self.mergeAt(rlpFromBytes(rootBytes), root, NibblesBuf.fromBytes(key), value)
  if rootBytes.len < 32:
    self.prune(root.data)
  self.root = self.db.dbPut(newRootBytes)
