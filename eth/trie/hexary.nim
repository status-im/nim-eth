import
  tables,
  nimcrypto/[keccak, hash, utils], stew/ranges/ptr_arith, eth/rlp,
  trie_defs, nibbles, trie_utils as trieUtils, db

type
  TrieNodeKey = object
    hash: KeccakHash
    usedBytes: uint8

  DB = TrieDatabaseRef

  HexaryTrie* = object
    db*: DB
    root: TrieNodeKey
    isPruning: bool

  SecureHexaryTrie* = distinct HexaryTrie

  TrieNode = Rlp

template len(key: TrieNodeKey): int =
  key.usedBytes.int

proc keccak*(r: BytesRange): KeccakHash =
  keccak256.digest r.toOpenArray

template asDbKey(k: TrieNodeKey): untyped =
  doAssert k.usedBytes == 32
  k.hash.data

proc expectHash(r: Rlp): BytesRange =
  result = r.toBytes
  if result.len != 32:
    raise newException(RlpTypeMismatch,
      "RLP expected to be a Keccak hash value, but has an incorrect length")

proc dbPut(db: DB, data: BytesRange): TrieNodeKey {.gcsafe.}

template get(db: DB, key: Rlp): BytesRange =
  db.get(key.expectHash.toOpenArray).toRange

converter toTrieNodeKey(hash: KeccakHash): TrieNodeKey =
  result.hash = hash
  result.usedBytes = 32

proc initHexaryTrie*(db: DB, rootHash: KeccakHash, isPruning = true): HexaryTrie =
  result.db = db
  result.root = rootHash
  result.isPruning = isPruning

template initSecureHexaryTrie*(db: DB, rootHash: KeccakHash, isPruning = true): SecureHexaryTrie =
  SecureHexaryTrie initHexaryTrie(db, rootHash, isPruning)

proc initHexaryTrie*(db: DB, isPruning = true): HexaryTrie =
  result.db = db
  result.root = result.db.dbPut(emptyRlp.toRange)
  result.isPruning = isPruning

template initSecureHexaryTrie*(db: DB, isPruning = true): SecureHexaryTrie =
  SecureHexaryTrie initHexaryTrie(db, isPruning)

proc rootHash*(t: HexaryTrie): KeccakHash =
  t.root.hash

proc rootHashHex*(t: HexaryTrie): string =
  $t.root.hash

template prune(t: HexaryTrie, x: openArray[byte]) =
  if t.isPruning: t.db.del(x)

proc isPruning*(t: HexaryTrie): bool =
  t.isPruning

proc getLocalBytes(x: TrieNodeKey): BytesRange =
  ## This proc should be used on nodes using the optimization
  ## of short values within the key.
  doAssert x.usedBytes < 32

  when defined(rangesEnableUnsafeAPI):
    result = unsafeRangeConstruction(x.data, x.usedBytes)
  else:
    var dataCopy = newSeq[byte](x.usedBytes)
    copyMem(dataCopy.baseAddr, x.hash.data.baseAddr, x.usedBytes)
    return dataCopy.toRange

template keyToLocalBytes(db: DB, k: TrieNodeKey): BytesRange =
  if k.len < 32: k.getLocalBytes
  else: db.get(k.asDbKey).toRange

template extensionNodeKey(r: Rlp): auto =
  hexPrefixDecode r.listElem(0).toBytes

proc getAux(db: DB, nodeRlp: Rlp, path: NibblesRange): BytesRange {.gcsafe.}

proc getAuxByHash(db: DB, node: TrieNodeKey, path: NibblesRange): BytesRange =
  var nodeRlp = rlpFromBytes keyToLocalBytes(db, node)
  return getAux(db, nodeRlp, path)

template getLookup(elem: untyped): untyped =
  if elem.isList: elem
  else: rlpFromBytes(get(db, toOpenArray(elem.expectHash)).toRange)

proc getAux(db: DB, nodeRlp: Rlp, path: NibblesRange): BytesRange =
  if not nodeRlp.hasData or nodeRlp.isEmpty:
    return zeroBytesRange

  case nodeRlp.listLen
  of 2:
    let (isLeaf, k) = nodeRlp.extensionNodeKey
    let sharedNibbles = sharedPrefixLen(path, k)

    if sharedNibbles == k.len:
      let value = nodeRlp.listElem(1)
      if sharedNibbles == path.len and isLeaf:
        return value.toBytes
      elif not isLeaf:
        let nextLookup = value.getLookup
        return getAux(db, nextLookup, path.slice(sharedNibbles))

    return zeroBytesRange
  of 17:
    if path.len == 0:
      return nodeRlp.listElem(16).toBytes
    var branch = nodeRlp.listElem(path[0].int)
    if branch.isEmpty:
      return zeroBytesRange
    else:
      let nextLookup = branch.getLookup
      return getAux(db, nextLookup, path.slice(1))
  else:
    raise newException(CorruptedTrieDatabase,
                       "HexaryTrie node with an unexpected number of children")

proc get*(self: HexaryTrie; key: BytesRange): BytesRange =
  return getAuxByHash(self.db, self.root, initNibbleRange(key))

proc getKeysAux(db: DB, stack: var seq[tuple[nodeRlp: Rlp, path: NibblesRange]]): BytesRange =
  while stack.len > 0:
    let (nodeRlp, path) = stack.pop()
    if not nodeRlp.hasData or nodeRlp.isEmpty:
      continue

    case nodeRlp.listLen
    of 2:
      let
        (isLeaf, k) = nodeRlp.extensionNodeKey
        key = path & k

      if isLeaf:
        doAssert(key.len mod 2 == 0)
        return key.getBytes
      else:
        let
          value = nodeRlp.listElem(1)
          nextLookup = value.getLookup
        stack.add((nextLookup, key))
    of 17:
      for i in 0 ..< 16:
        var branch = nodeRlp.listElem(i)
        if not branch.isEmpty:
          let nextLookup = branch.getLookup
          var key = path.cloneAndReserveNibble()
          key.replaceLastNibble(i.byte)
          stack.add((nextLookup, key))

      var lastElem = nodeRlp.listElem(16)
      if not lastElem.isEmpty:
        doAssert(path.len mod 2 == 0)
        return path.getBytes
    else:
      raise newException(CorruptedTrieDatabase,
                        "HexaryTrie node with an unexpected number of children")

iterator keys*(self: HexaryTrie): BytesRange =
  var
    nodeRlp = rlpFromBytes keyToLocalBytes(self.db, self.root)
    path = newRange[byte](0)
    stack = @[(nodeRlp, initNibbleRange(path))]
  while stack.len > 0:
    yield getKeysAux(self.db, stack)

proc getValuesAux(db: DB, stack: var seq[Rlp]): BytesRange =
  while stack.len > 0:
    let nodeRlp = stack.pop()
    if not nodeRlp.hasData or nodeRlp.isEmpty:
      continue

    case nodeRlp.listLen
    of 2:
      let
        (isLeaf, _) = nodeRlp.extensionNodeKey
        value = nodeRlp.listElem(1)

      if isLeaf:
        return value.toBytes
      else:
        let nextLookup = value.getLookup
        stack.add(nextLookup)
    of 17:
      for i in 0 ..< 16:
        var branch = nodeRlp.listElem(i)
        if not branch.isEmpty:
          let nextLookup = branch.getLookup
          stack.add(nextLookup)

      var lastElem = nodeRlp.listElem(16)
      if not lastElem.isEmpty:
        return lastElem.toBytes
    else:
      raise newException(CorruptedTrieDatabase,
                        "HexaryTrie node with an unexpected number of children")

iterator values*(self: HexaryTrie): BytesRange =
  var
    nodeRlp = rlpFromBytes keyToLocalBytes(self.db, self.root)
    stack = @[nodeRlp]
  while stack.len > 0:
    yield getValuesAux(self.db, stack)

proc getPairsAux(db: DB, stack: var seq[tuple[nodeRlp: Rlp, path: NibblesRange]]): (BytesRange, BytesRange) =
  while stack.len > 0:
    let (nodeRlp, path) = stack.pop()
    if not nodeRlp.hasData or nodeRlp.isEmpty:
      continue

    case nodeRlp.listLen
    of 2:
      let
        (isLeaf, k) = nodeRlp.extensionNodeKey
        key = path & k
        value = nodeRlp.listElem(1)

      if isLeaf:
        doAssert(key.len mod 2 == 0)
        return (key.getBytes, value.toBytes)
      else:
        let nextLookup = value.getLookup
        stack.add((nextLookup, key))
    of 17:
      for i in 0 ..< 16:
        var branch = nodeRlp.listElem(i)
        if not branch.isEmpty:
          let nextLookup = branch.getLookup
          var key = path.cloneAndReserveNibble()
          key.replaceLastNibble(i.byte)
          stack.add((nextLookup, key))

      var lastElem = nodeRlp.listElem(16)
      if not lastElem.isEmpty:
        doAssert(path.len mod 2 == 0)
        return (path.getBytes, lastElem.toBytes)
    else:
      raise newException(CorruptedTrieDatabase,
                        "HexaryTrie node with an unexpected number of children")

iterator pairs*(self: HexaryTrie): (BytesRange, BytesRange) =
  var
    nodeRlp = rlpFromBytes keyToLocalBytes(self.db, self.root)
    path = newRange[byte](0)
    stack = @[(nodeRlp, initNibbleRange(path))]
  while stack.len > 0:
    # perhaps a Nim bug #9778
    # cannot yield the helper proc directly
    # it will cut the yield in half
    let res = getPairsAux(self.db, stack)
    yield res

iterator replicate*(self: HexaryTrie): (BytesRange, BytesRange) =
  # this iterator helps 'rebuild' the entire trie without
  # going through a trie algorithm, but it will pull the entire
  # low level KV pairs. Thus the target db will only use put operations
  # without del or contains, can speed up huge trie replication.
  var
    localBytes = keyToLocalBytes(self.db, self.root)
    nodeRlp = rlpFromBytes localBytes
    path = newRange[byte](0)
    stack = @[(nodeRlp, initNibbleRange(path))]

  template pushOrYield(elem: untyped) =
    if elem.isList:
      stack.add((elem, key))
    else:
      let rlpBytes = get(self.db, toOpenArray(elem.expectHash)).toRange
      let nextLookup = rlpFromBytes(rlpBytes)
      stack.add((nextLookup, key))
      yield (elem.toBytes, rlpBytes)

  yield (self.rootHash.toRange, localBytes)
  while stack.len > 0:
    let (nodeRlp, path) = stack.pop()
    if not nodeRlp.hasData or nodeRlp.isEmpty:
      continue

    case nodeRlp.listLen
    of 2:
      let
        (isLeaf, k) = nodeRlp.extensionNodeKey
        key = path & k
        value = nodeRlp.listElem(1)
      if not isLeaf: pushOrYield(value)
    of 17:
      for i in 0 ..< 16:
        var branch = nodeRlp.listElem(i)
        if not branch.isEmpty:
          var key = path.cloneAndReserveNibble()
          key.replaceLastNibble(i.byte)
          pushOrYield(branch)
    else:
      raise newException(CorruptedTrieDatabase,
                        "HexaryTrie node with an unexpected number of children")

proc getValues*(self: HexaryTrie): seq[BytesRange] =
  result = @[]
  for v in self.values:
    result.add v

proc getKeys*(self: HexaryTrie): seq[BytesRange] =
  result = @[]
  for k in self.keys:
    result.add k

template getNode(elem: untyped): untyped =
  if elem.isList: elem.rawData
  else: get(db, toOpenArray(elem.expectHash)).toRange

proc getBranchAux(db: DB, node: BytesRange, path: NibblesRange, output: var seq[BytesRange]) =
  var nodeRlp = rlpFromBytes node
  if not nodeRlp.hasData or nodeRlp.isEmpty: return

  case nodeRlp.listLen
  of 2:
    let (isLeaf, k) = nodeRlp.extensionNodeKey
    let sharedNibbles = sharedPrefixLen(path, k)
    if sharedNibbles == k.len:
      let value = nodeRlp.listElem(1)
      if not isLeaf:
        let nextLookup = value.getNode
        output.add nextLookup
        getBranchAux(db, nextLookup, path.slice(sharedNibbles), output)
  of 17:
    if path.len != 0:
      var branch = nodeRlp.listElem(path[0].int)
      if not branch.isEmpty:
        let nextLookup = branch.getNode
        output.add nextLookup
        getBranchAux(db, nextLookup, path.slice(1), output)
  else:
    raise newException(CorruptedTrieDatabase,
                       "HexaryTrie node with an unexpected number of children")

proc getBranch*(self: HexaryTrie; key: BytesRange): seq[BytesRange] =
  result = @[]
  var node = keyToLocalBytes(self.db, self.root)
  result.add node
  getBranchAux(self.db, node, initNibbleRange(key), result)

proc dbDel(t: var HexaryTrie, data: BytesRange) =
  if data.len >= 32: t.prune(data.keccak.data)

proc dbPut(db: DB, data: BytesRange): TrieNodeKey =
  result.hash = data.keccak
  result.usedBytes = 32
  put(db, result.asDbKey, data.toOpenArray)

proc appendAndSave(rlpWriter: var RlpWriter, data: BytesRange, db: DB) =
  if data.len >= 32:
    var nodeKey = dbPut(db, data)
    rlpWriter.append(nodeKey.hash)
  else:
    rlpWriter.appendRawBytes(data)

proc isTrieBranch(rlp: Rlp): bool =
  rlp.isList and (var len = rlp.listLen; len == 2 or len == 17)

proc replaceValue(data: Rlp, key: NibblesRange, value: BytesRange): Bytes =
  if data.isEmpty:
    let prefix = hexPrefixEncode(key, true)
    return encodeList(prefix, value)

  doAssert data.isTrieBranch
  if data.listLen == 2:
    return encodeList(data.listElem(0), value)

  var r = initRlpList(17)

  # XXX: This can be optimized to a direct bitwise copy of the source RLP
  var iter = data
  # We already know that we are working with a list
  discard iter.enterList()
  for i in 0 ..< 16:
    r.append iter
    iter.skipElem

  r.append value
  return r.finish()

proc isTwoItemNode(self: HexaryTrie; r: Rlp): bool =
  if r.isBlob:
    let resolved = self.db.get(r)
    let rlp = rlpFromBytes(resolved)
    return rlp.isList and rlp.listLen == 2
  else:
    return r.isList and r.listLen == 2

proc isLeaf(r: Rlp): bool =
  doAssert r.isList and r.listLen == 2
  let b = r.listElem(0).toBytes()
  return (b[0] and 0x20) != 0

proc findSingleChild(r: Rlp; childPos: var byte): Rlp =
  result = zeroBytesRlp
  var i: byte = 0
  var rlp = r
  for elem in rlp:
    if not elem.isEmpty:
      if not result.hasData:
        result = elem
        childPos = i
      else:
        return zeroBytesRlp
    inc i

proc deleteAt(self: var HexaryTrie; origRlp: Rlp, key: NibblesRange): BytesRange {.gcsafe.}

proc deleteAux(self: var HexaryTrie; rlpWriter: var RlpWriter;
               origRlp: Rlp; path: NibblesRange): bool =
  if origRlp.isEmpty:
    return false

  var toDelete = if origRlp.isList: origRlp
                 else: rlpFromBytes self.db.get(origRlp)

  let b = self.deleteAt(toDelete, path)

  if b.len == 0:
    return false

  rlpWriter.appendAndSave(b, self.db)
  return true

proc graft(self: var HexaryTrie; r: Rlp): Bytes =
  doAssert r.isList and r.listLen == 2
  var (origIsLeaf, origPath) = r.extensionNodeKey
  var value = r.listElem(1)

  var n: Rlp
  if not value.isList:
    let nodeKey = value.expectHash
    var resolvedData = self.db.get(nodeKey.toOpenArray).toRange
    self.prune(nodeKey.toOpenArray)
    value = rlpFromBytes resolvedData

  doAssert value.listLen == 2
  let (valueIsLeaf, valueKey) = value.extensionNodeKey

  var rlpWriter = initRlpList(2)
  rlpWriter.append hexPrefixEncode(origPath, valueKey, valueIsLeaf)
  rlpWriter.append value.listElem(1)
  return rlpWriter.finish

proc mergeAndGraft(self: var HexaryTrie;
                   soleChild: Rlp, childPos: byte): Bytes =
  var output = initRlpList(2)
  if childPos == 16:
    output.append hexPrefixEncode(zeroNibblesRange, true)
  else:
    doAssert(not soleChild.isEmpty)
    output.append int(hexPrefixEncodeByte(childPos))
  output.append(soleChild)
  result = output.finish()

  if self.isTwoItemNode(soleChild):
    result = self.graft(rlpFromBytes(result.toRange))

proc deleteAt(self: var HexaryTrie;
              origRlp: Rlp, key: NibblesRange): BytesRange =
  if origRlp.isEmpty:
    return zeroBytesRange

  doAssert origRlp.isTrieBranch
  let origBytes = origRlp.rawData
  if origRlp.listLen == 2:
    let (isLeaf, k) = origRlp.extensionNodeKey
    if k == key and isLeaf:
      self.dbDel origBytes
      return emptyRlp.toRange

    if key.startsWith(k):
      var
        rlpWriter = initRlpList(2)
        path = origRlp.listElem(0)
        value = origRlp.listElem(1)
      rlpWriter.append(path)
      if not self.deleteAux(rlpWriter, value, key.slice(k.len)):
        return zeroBytesRange
      self.dbDel origBytes
      var finalBytes = rlpWriter.finish.toRange
      var rlp = rlpFromBytes(finalBytes)
      if self.isTwoItemNode(rlp.listElem(1)):
        return self.graft(rlp).toRange
      return finalBytes
    else:
      return zeroBytesRange
  else:
    if key.len == 0 and origRlp.listElem(16).isEmpty:
      self.dbDel origBytes
      var foundChildPos: byte
      let singleChild = origRlp.findSingleChild(foundChildPos)
      if singleChild.hasData and foundChildPos != 16:
        result = self.mergeAndGraft(singleChild, foundChildPos).toRange
      else:
        var rlpRes = initRlpList(17)
        var iter = origRlp
        # We already know that we are working with a list
        discard iter.enterList
        for i in 0 ..< 16:
          rlpRes.append iter
          iter.skipElem
        rlpRes.append ""
        return rlpRes.finish.toRange
    else:
      var rlpWriter = initRlpList(17)
      let keyHead = int(key[0])
      var i = 0
      var origCopy = origRlp
      for elem in items(origCopy):
        if i == keyHead:
          if not self.deleteAux(rlpWriter, elem, key.slice(1)):
            return zeroBytesRange
        else:
          rlpWriter.append(elem)
        inc i

      self.dbDel origBytes
      result = rlpWriter.finish.toRange
      var resultRlp = rlpFromBytes(result)
      var foundChildPos: byte
      let singleChild = resultRlp.findSingleChild(foundChildPos)
      if singleChild.hasData:
        result = self.mergeAndGraft(singleChild, foundChildPos).toRange

proc del*(self: var HexaryTrie; key: BytesRange) =
  var
    rootBytes = keyToLocalBytes(self.db, self.root)
    rootRlp = rlpFromBytes rootBytes

  var newRootBytes = self.deleteAt(rootRlp, initNibbleRange(key))
  if newRootBytes.len > 0:
    if rootBytes.len < 32:
      self.prune(self.root.asDbKey)
    self.root = self.db.dbPut(newRootBytes)

proc mergeAt(self: var HexaryTrie, orig: Rlp, origHash: KeccakHash,
             key: NibblesRange, value: BytesRange,
             isInline = false): BytesRange {.gcsafe.}

proc mergeAt(self: var HexaryTrie, rlp: Rlp,
             key: NibblesRange, value: BytesRange,
             isInline = false): BytesRange =
  self.mergeAt(rlp, rlp.rawData.keccak, key, value, isInline)

proc mergeAtAux(self: var HexaryTrie, output: var RlpWriter, orig: Rlp,
                key: NibblesRange, value: BytesRange) =
  var resolved = orig
  var isRemovable = false
  if not (orig.isList or orig.isEmpty):
    resolved = rlpFromBytes self.db.get(orig)
    isRemovable = true

  let b = self.mergeAt(resolved, key, value, not isRemovable)
  output.appendAndSave(b, self.db)

proc mergeAt(self: var HexaryTrie, orig: Rlp, origHash: KeccakHash,
             key: NibblesRange, value: BytesRange,
             isInline = false): BytesRange =
  template origWithNewValue: auto =
    self.prune(origHash.data)
    replaceValue(orig, key, value).toRange

  if orig.isEmpty:
    return origWithNewValue()

  doAssert orig.isTrieBranch
  if orig.listLen == 2:
    let (isLeaf, k) = orig.extensionNodeKey
    var origValue = orig.listElem(1)

    if k == key and isLeaf:
      return origWithNewValue()

    let sharedNibbles = sharedPrefixLen(key, k)

    if sharedNibbles == k.len and not isLeaf:
      var r = initRlpList(2)
      r.append orig.listElem(0)
      self.mergeAtAux(r, origValue, key.slice(k.len), value)
      return r.finish.toRange

    if orig.rawData.len >= 32:
      self.prune(origHash.data)

    if sharedNibbles > 0:
      # Split the extension node
      var bottom = initRlpList(2)
      bottom.append hexPrefixEncode(k.slice(sharedNibbles), isLeaf)
      bottom.append origValue

      var top = initRlpList(2)
      top.append hexPrefixEncode(k.slice(0, sharedNibbles), false)
      top.appendAndSave(bottom.finish.toRange, self.db)

      return self.mergeAt(rlpFromBytes(top.finish.toRange), key, value, true)
    else:
      # Create a branch node
      var branches = initRlpList(17)
      if k.len == 0:
        # The key is now exhausted. This must be a leaf node
        doAssert isLeaf
        for i in 0 ..< 16:
          branches.append ""
        branches.append origValue
      else:
        let n = k[0]
        for i in 0 ..< 16:
          if byte(i) == n:
            if isLeaf or k.len > 1:
              let childNode = encodeList(hexPrefixEncode(k.slice(1), isLeaf),
                                         origValue).toRange
              branches.appendAndSave(childNode, self.db)
            else:
              branches.append origValue
          else:
            branches.append ""
        branches.append ""

      return self.mergeAt(rlpFromBytes(branches.finish.toRange), key, value, true)
  else:
    if key.len == 0:
      return origWithNewValue()

    if isInline:
      self.prune(origHash.data)

    let n = key[0]
    var i = 0
    var r = initRlpList(17)

    var origCopy = orig
    for elem in items(origCopy):
      if i == int(n):
        self.mergeAtAux(r, elem, key.slice(1), value)
      else:
        r.append(elem)
      inc i

    return r.finish.toRange

proc put*(self: var HexaryTrie; key, value: BytesRange) =
  let root = self.root.hash

  var rootBytes = self.db.get(root.data).toRange
  doAssert rootBytes.len > 0

  let newRootBytes = self.mergeAt(rlpFromBytes(rootBytes), root,
                                  initNibbleRange(key), value)
  if rootBytes.len < 32:
    self.prune(root.data)

  self.root = self.db.dbPut(newRootBytes)

proc put*(self: var SecureHexaryTrie; key, value: BytesRange) =
  let keyHash = @(key.keccak.data)
  put(HexaryTrie(self), keyHash.toRange, value)

proc get*(self: SecureHexaryTrie; key: BytesRange): BytesRange =
  let keyHash = @(key.keccak.data)
  return get(HexaryTrie(self), keyHash.toRange)

proc del*(self: var SecureHexaryTrie; key: BytesRange) =
  let keyHash = @(key.keccak.data)
  del(HexaryTrie(self), keyHash.toRange)

proc rootHash*(self: SecureHexaryTrie): KeccakHash {.borrow.}
proc rootHashHex*(self: SecureHexaryTrie): string {.borrow.}
proc isPruning*(self: SecureHexaryTrie): bool {.borrow.}

template contains*(self: HexaryTrie | SecureHexaryTrie;
                   key: BytesRange): bool =
  self.get(key).len > 0

