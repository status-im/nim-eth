import
  tables,
  nimcrypto/[keccak, hash], eth/rlp,
  trie_defs, nibbles, db

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

template len(key: TrieNodeKey): int =
  key.usedBytes.int

proc keccak*(r: openArray[byte]): KeccakHash =
  keccak256.digest r

template asDbKey(k: TrieNodeKey): untyped =
  doAssert k.usedBytes == 32
  k.hash.data

proc expectHash(r: Rlp): seq[byte] =
  result = r.toBytes
  if result.len != 32:
    raise newException(RlpTypeMismatch,
      "RLP expected to be a Keccak hash value, but has an incorrect length")

proc dbPut(db: DB, data: openArray[byte]): TrieNodeKey {.gcsafe.}

template get(db: DB, key: Rlp): seq[byte] =
  db.get(key.expectHash)

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
  result.root = result.db.dbPut(emptyRlp)
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

proc getLocalBytes(x: TrieNodeKey): seq[byte] =
  ## This proc should be used on nodes using the optimization
  ## of short values within the key.
  doAssert x.usedBytes < 32
  x.hash.data[0..<x.usedBytes]

template keyToLocalBytes(db: DB, k: TrieNodeKey): seq[byte] =
  if k.len < 32: k.getLocalBytes
  else: db.get(k.asDbKey)

template extensionNodeKey(r: Rlp): auto =
  hexPrefixDecode r.listElem(0).toBytes

proc getAux(db: DB, nodeRlp: Rlp, path: NibblesSeq): seq[byte] {.gcsafe.}

proc getAuxByHash(db: DB, node: TrieNodeKey, path: NibblesSeq): seq[byte] =
  var nodeRlp = rlpFromBytes keyToLocalBytes(db, node)
  return getAux(db, nodeRlp, path)

template getLookup(elem: untyped): untyped =
  if elem.isList: elem
  else: rlpFromBytes(get(db, elem.expectHash))

proc getAux(db: DB, nodeRlp: Rlp, path: NibblesSeq): seq[byte] =
  if not nodeRlp.hasData or nodeRlp.isEmpty:
    return

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

    return
  of 17:
    if path.len == 0:
      return nodeRlp.listElem(16).toBytes
    var branch = nodeRlp.listElem(path[0].int)
    if branch.isEmpty:
      return
    else:
      let nextLookup = branch.getLookup
      return getAux(db, nextLookup, path.slice(1))
  else:
    raise newException(CorruptedTrieDatabase,
                       "HexaryTrie node with an unexpected number of children")

proc get*(self: HexaryTrie; key: openArray[byte]): seq[byte] =
  return getAuxByHash(self.db, self.root, initNibbleRange(key))

proc getKeysAux(db: DB, stack: var seq[tuple[nodeRlp: Rlp, path: NibblesSeq]]): seq[byte] =
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

iterator keys*(self: HexaryTrie): seq[byte] =
  var
    nodeRlp = rlpFromBytes keyToLocalBytes(self.db, self.root)
    stack = @[(nodeRlp, initNibbleRange([]))]
  while stack.len > 0:
    yield getKeysAux(self.db, stack)

proc getValuesAux(db: DB, stack: var seq[Rlp]): seq[byte] =
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

iterator values*(self: HexaryTrie): seq[byte] =
  var
    nodeRlp = rlpFromBytes keyToLocalBytes(self.db, self.root)
    stack = @[nodeRlp]
  while stack.len > 0:
    yield getValuesAux(self.db, stack)

proc getPairsAux(db: DB, stack: var seq[tuple[nodeRlp: Rlp, path: NibblesSeq]]): (seq[byte], seq[byte]) =
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

iterator pairs*(self: HexaryTrie): (seq[byte], seq[byte]) =
  var
    nodeRlp = rlpFromBytes keyToLocalBytes(self.db, self.root)
    stack = @[(nodeRlp, initNibbleRange([]))]
  while stack.len > 0:
    # perhaps a Nim bug #9778
    # cannot yield the helper proc directly
    # it will cut the yield in half
    let res = getPairsAux(self.db, stack)
    yield res

iterator replicate*(self: HexaryTrie): (seq[byte], seq[byte]) =
  # this iterator helps 'rebuild' the entire trie without
  # going through a trie algorithm, but it will pull the entire
  # low level KV pairs. Thus the target db will only use put operations
  # without del or contains, can speed up huge trie replication.
  var
    localBytes = keyToLocalBytes(self.db, self.root)
    nodeRlp = rlpFromBytes localBytes
    stack = @[(nodeRlp, initNibbleRange([]))]

  template pushOrYield(elem: untyped) =
    if elem.isList:
      stack.add((elem, key))
    else:
      let rlpBytes = get(self.db, elem.expectHash)
      let nextLookup = rlpFromBytes(rlpBytes)
      stack.add((nextLookup, key))
      yield (elem.toBytes, rlpBytes)

  yield (@(self.rootHash.data), localBytes)
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

proc getValues*(self: HexaryTrie): seq[seq[byte]] =
  result = @[]
  for v in self.values:
    result.add v

proc getKeys*(self: HexaryTrie): seq[seq[byte]] =
  result = @[]
  for k in self.keys:
    result.add k

template getNode(elem: untyped): untyped =
  if elem.isList: @(elem.rawData)
  else: get(db, elem.expectHash)

proc getBranchAux(db: DB, node: openArray[byte], path: NibblesSeq, output: var seq[seq[byte]]) =
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

proc getBranch*(self: HexaryTrie; key: openArray[byte]): seq[seq[byte]] =
  result = @[]
  var node = keyToLocalBytes(self.db, self.root)
  result.add node
  getBranchAux(self.db, node, initNibbleRange(key), result)

proc dbDel(t: var HexaryTrie, data: openArray[byte]) =
  if data.len >= 32: t.prune(data.keccak.data)

proc dbPut(db: DB, data: openArray[byte]): TrieNodeKey =
  result.hash = data.keccak
  result.usedBytes = 32
  put(db, result.asDbKey, data)

proc appendAndSave(rlpWriter: var RlpWriter, data: openArray[byte], db: DB) =
  if data.len >= 32:
    var nodeKey = dbPut(db, data)
    rlpWriter.append(nodeKey.hash)
  else:
    rlpWriter.appendRawBytes(data)

proc isTrieBranch(rlp: Rlp): bool =
  rlp.isList and (var len = rlp.listLen; len == 2 or len == 17)

proc replaceValue(data: Rlp, key: NibblesSeq, value: openArray[byte]): seq[byte] =
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
  doAssert iter.enterList()
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

proc deleteAt(self: var HexaryTrie; origRlp: Rlp, key: NibblesSeq): seq[byte] {.gcsafe.}

proc deleteAux(self: var HexaryTrie; rlpWriter: var RlpWriter;
               origRlp: Rlp; path: NibblesSeq): bool =
  if origRlp.isEmpty:
    return false

  var toDelete = if origRlp.isList: origRlp
                 else: rlpFromBytes self.db.get(origRlp)

  let b = self.deleteAt(toDelete, path)

  if b.len == 0:
    return false

  rlpWriter.appendAndSave(b, self.db)
  return true

proc graft(self: var HexaryTrie; r: Rlp): seq[byte] =
  doAssert r.isList and r.listLen == 2
  var (_, origPath) = r.extensionNodeKey
  var value = r.listElem(1)

  if not value.isList:
    let nodeKey = value.expectHash
    var resolvedData = self.db.get(nodeKey)
    self.prune(nodeKey)
    value = rlpFromBytes resolvedData

  doAssert value.listLen == 2
  let (valueIsLeaf, valueKey) = value.extensionNodeKey

  var rlpWriter = initRlpList(2)
  rlpWriter.append hexPrefixEncode(origPath, valueKey, valueIsLeaf)
  rlpWriter.append value.listElem(1)
  return rlpWriter.finish

proc mergeAndGraft(self: var HexaryTrie;
                   soleChild: Rlp, childPos: byte): seq[byte] =
  var output = initRlpList(2)
  if childPos == 16:
    output.append hexPrefixEncode(NibblesSeq(), true)
  else:
    doAssert(not soleChild.isEmpty)
    output.append int(hexPrefixEncodeByte(childPos))
  output.append(soleChild)
  result = output.finish()

  if self.isTwoItemNode(soleChild):
    result = self.graft(rlpFromBytes(result))

proc deleteAt(self: var HexaryTrie;
              origRlp: Rlp, key: NibblesSeq): seq[byte] =
  if origRlp.isEmpty:
    return

  doAssert origRlp.isTrieBranch
  let origBytes = @(origRlp.rawData)
  if origRlp.listLen == 2:
    let (isLeaf, k) = origRlp.extensionNodeKey
    if k == key and isLeaf:
      self.dbDel origBytes
      return emptyRlp

    if key.startsWith(k):
      var
        rlpWriter = initRlpList(2)
        path = origRlp.listElem(0)
        value = origRlp.listElem(1)
      rlpWriter.append(path)
      if not self.deleteAux(rlpWriter, value, key.slice(k.len)):
        return
      self.dbDel origBytes
      var finalBytes = rlpWriter.finish
      var rlp = rlpFromBytes(finalBytes)
      if self.isTwoItemNode(rlp.listElem(1)):
        return self.graft(rlp)
      return finalBytes
    else:
      return
  else:
    if key.len == 0 and origRlp.listElem(16).isEmpty:
      self.dbDel origBytes
      var foundChildPos: byte
      let singleChild = origRlp.findSingleChild(foundChildPos)
      if singleChild.hasData and foundChildPos != 16:
        result = self.mergeAndGraft(singleChild, foundChildPos)
      else:
        var rlpRes = initRlpList(17)
        var iter = origRlp
        # We already know that we are working with a list
        doAssert iter.enterList
        for i in 0 ..< 16:
          rlpRes.append iter
          iter.skipElem
        rlpRes.append ""
        return rlpRes.finish
    else:
      var rlpWriter = initRlpList(17)
      let keyHead = int(key[0])
      var i = 0
      var origCopy = origRlp
      for elem in items(origCopy):
        if i == keyHead:
          if not self.deleteAux(rlpWriter, elem, key.slice(1)):
            return
        else:
          rlpWriter.append(elem)
        inc i

      self.dbDel origBytes
      result = rlpWriter.finish
      var resultRlp = rlpFromBytes(result)
      var foundChildPos: byte
      let singleChild = resultRlp.findSingleChild(foundChildPos)
      if singleChild.hasData:
        result = self.mergeAndGraft(singleChild, foundChildPos)

proc del*(self: var HexaryTrie; key: openArray[byte]) =
  var
    rootBytes = keyToLocalBytes(self.db, self.root)
    rootRlp = rlpFromBytes rootBytes

  var newRootBytes = self.deleteAt(rootRlp, initNibbleRange(key))
  if newRootBytes.len > 0:
    if rootBytes.len < 32:
      self.prune(self.root.asDbKey)
    self.root = self.db.dbPut(newRootBytes)

proc mergeAt(self: var HexaryTrie, orig: Rlp, origHash: KeccakHash,
             key: NibblesSeq, value: openArray[byte],
             isInline = false): seq[byte] {.gcsafe.}

proc mergeAt(self: var HexaryTrie, rlp: Rlp,
             key: NibblesSeq, value: openArray[byte],
             isInline = false): seq[byte] =
  self.mergeAt(rlp, rlp.rawData.keccak, key, value, isInline)

proc mergeAtAux(self: var HexaryTrie, output: var RlpWriter, orig: Rlp,
                key: NibblesSeq, value: openArray[byte]) =
  var resolved = orig
  var isRemovable = false
  if not (orig.isList or orig.isEmpty):
    resolved = rlpFromBytes self.db.get(orig)
    isRemovable = true

  let b = self.mergeAt(resolved, key, value, not isRemovable)
  output.appendAndSave(b, self.db)

proc mergeAt(self: var HexaryTrie, orig: Rlp, origHash: KeccakHash,
             key: NibblesSeq, value: openArray[byte],
             isInline = false): seq[byte] =
  template origWithNewValue: auto =
    self.prune(origHash.data)
    replaceValue(orig, key, value)

  if orig.isEmpty:
    return origWithNewValue()

  doAssert orig.isTrieBranch, $orig
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
      return r.finish

    if orig.rawData.len >= 32:
      self.prune(origHash.data)

    if sharedNibbles > 0:
      # Split the extension node
      var bottom = initRlpList(2)
      bottom.append hexPrefixEncode(k.slice(sharedNibbles), isLeaf)
      bottom.append origValue

      var top = initRlpList(2)
      top.append hexPrefixEncode(k.slice(0, sharedNibbles), false)
      top.appendAndSave(bottom.finish, self.db)

      return self.mergeAt(rlpFromBytes(top.finish), key, value, true)
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
                                         origValue)
              branches.appendAndSave(childNode, self.db)
            else:
              branches.append origValue
          else:
            branches.append ""
        branches.append ""

      return self.mergeAt(rlpFromBytes(branches.finish), key, value, true)
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

    return r.finish

proc put*(self: var HexaryTrie; key, value: openArray[byte]) =
  let root = self.root.hash

  var rootBytes = self.db.get(root.data)
  doAssert rootBytes.len > 0

  let newRootBytes = self.mergeAt(rlpFromBytes(rootBytes), root,
                                  initNibbleRange(key), value)
  if rootBytes.len < 32:
    self.prune(root.data)

  self.root = self.db.dbPut(newRootBytes)

proc put*(self: var SecureHexaryTrie; key, value: openArray[byte]) =
  put(HexaryTrie(self), key.keccak.data, value)

proc get*(self: SecureHexaryTrie; key: openArray[byte]): seq[byte] =
  return get(HexaryTrie(self), key.keccak.data)

proc del*(self: var SecureHexaryTrie; key: openArray[byte]) =
  del(HexaryTrie(self), key.keccak.data)

proc rootHash*(self: SecureHexaryTrie): KeccakHash {.borrow.}
proc rootHashHex*(self: SecureHexaryTrie): string {.borrow.}
proc isPruning*(self: SecureHexaryTrie): bool {.borrow.}

template contains*(self: HexaryTrie | SecureHexaryTrie;
                   key: openArray[byte]): bool =
  self.get(key).len > 0
