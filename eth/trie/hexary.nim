# nim-eth
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[options, tables],
  nimcrypto/[keccak, hash],
  ../rlp,
  "."/[trie_defs, nibbles, db]

type
  TrieNodeKey = object
    hash: KeccakHash
    usedBytes: uint8

  DB = TrieDatabaseRef

  HexaryTrie* = object
    db*: DB
    root: TrieNodeKey
    isPruning: bool
    shouldMissingNodesBeErrors: bool

  SecureHexaryTrie* = distinct HexaryTrie

template len(key: TrieNodeKey): int =
  key.usedBytes.int

template asDbKey(k: TrieNodeKey): untyped =
  doAssert k.usedBytes == 32
  k.hash.data

proc expectHash(r: Rlp): seq[byte] =
  result = r.toBytes
  if result.len != 32:
    raise newException(RlpTypeMismatch,
      "RLP expected to be a Keccak hash value, but has an incorrect length")

type MissingNodeError* = ref object of AssertionDefect
  path*: NibblesSeq
  nodeHashBytes*: seq[byte]

proc dbGet(db: DB, data: openArray[byte]): seq[byte]
  {.gcsafe, raises: [].} =
  db.get(data)

proc dbGet(db: DB, key: Rlp): seq[byte] =
  dbGet(db, key.expectHash)

proc dbPut(db: DB, data: openArray[byte]): TrieNodeKey
  {.gcsafe, raises: [].}

# For stateless mode, it's possible for nodes to be missing from the DB,
# and we need the higher-level code to be able to find out the *path* to
# the missing node. So here we need the path to be passed in, and if the
# node is missing we'll raise an exception to get that information up to
# where it's needed.
proc getPossiblyMissingNode(db: DB, data: openArray[byte], fullPath: NibblesSeq, pathIndex: int, errorIfMissing: bool): seq[byte]
  {.gcsafe, raises: [].} =
  let nodeBytes = db.get(data)  # need to call this before the call to contains, otherwise CaptureDB complains
  if nodeBytes.len > 0 or not errorIfMissing:
    nodeBytes
  else:
    raise MissingNodeError(path: fullPath.slice(0, pathIndex), nodeHashBytes: @data)

proc getPossiblyMissingNode(db: DB, key: Rlp, fullPath: NibblesSeq, pathIndex: int, errorIfMissing: bool): seq[byte] =
  getPossiblyMissingNode(db, key.expectHash, fullPath, pathIndex, errorIfMissing)

converter toTrieNodeKey(hash: KeccakHash): TrieNodeKey =
  result.hash = hash
  result.usedBytes = 32

proc initHexaryTrie*(db: DB, rootHash: KeccakHash, isPruning = true, shouldMissingNodesBeErrors = false): HexaryTrie =
  result.db = db
  result.root = rootHash
  result.isPruning = isPruning
  result.shouldMissingNodesBeErrors = shouldMissingNodesBeErrors

template initSecureHexaryTrie*(db: DB, rootHash: KeccakHash, isPruning = true, shouldMissingNodesBeErrors = false): SecureHexaryTrie =
  SecureHexaryTrie initHexaryTrie(db, rootHash, isPruning, shouldMissingNodesBeErrors)

proc initHexaryTrie*(db: DB, isPruning = true, shouldMissingNodesBeErrors = false): HexaryTrie
    {.raises: [].} =
  result.db = db
  result.root = result.db.dbPut(emptyRlp)
  result.isPruning = isPruning
  result.shouldMissingNodesBeErrors = shouldMissingNodesBeErrors

template initSecureHexaryTrie*(db: DB, isPruning = true, shouldMissingNodesBeErrors = false): SecureHexaryTrie =
  SecureHexaryTrie initHexaryTrie(db, isPruning, shouldMissingNodesBeErrors)

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
  else: dbGet(db, k.asDbKey)

template extensionNodeKey(r: Rlp): auto =
  hexPrefixDecode r.listElem(0).toBytes

proc getLookup(db: DB, elem: Rlp, fullPath: NibblesSeq, pathIndex: int, errorIfMissing: bool): Rlp =
  if elem.isList: elem
  else: rlpFromBytes(getPossiblyMissingNode(db, elem.expectHash, fullPath, pathIndex, errorIfMissing))

proc getAux(db: DB, nodeRlp: Rlp, fullPath: NibblesSeq, pathIndex: int, errorIfMissing: bool): seq[byte]
    {.gcsafe, raises: [RlpError].} =
  if not nodeRlp.hasData or nodeRlp.isEmpty:
    return

  let path = fullPath.slice(pathIndex)
  case nodeRlp.listLen
  of 2:
    let (isLeaf, k) = nodeRlp.extensionNodeKey
    let sharedNibbles = sharedPrefixLen(path, k)

    if sharedNibbles == k.len:
      let value = nodeRlp.listElem(1)
      if sharedNibbles == path.len and isLeaf:
        return value.toBytes
      elif not isLeaf:
        let nextLookup = getLookup(db, value, fullPath, pathIndex + sharedNibbles, errorIfMissing)
        return getAux(db, nextLookup, fullPath, pathIndex + sharedNibbles, errorIfMissing)

    return
  of 17:
    if path.len == 0:
      return nodeRlp.listElem(16).toBytes
    var branch = nodeRlp.listElem(path[0].int)
    if branch.isEmpty:
      return
    else:
      let nextLookup = getLookup(db, branch, fullPath, pathIndex + 1, errorIfMissing)
      return getAux(db, nextLookup, fullPath, pathIndex + 1, errorIfMissing)
  else:
    raise newException(CorruptedTrieDatabase,
                       "HexaryTrie node with an unexpected number of children")

proc get*(self: HexaryTrie; key: openArray[byte]): seq[byte] =
  var nodeRlp = rlpFromBytes keyToLocalBytes(self.db, self.root)
  return getAux(self.db, nodeRlp, initNibbleRange(key), 0, self.shouldMissingNodesBeErrors)

proc getKeysAux(db: DB, stack: var seq[tuple[nodeRlp: Rlp, path: NibblesSeq]], errorIfMissing: bool): seq[byte] =
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
          nextLookup = getLookup(db, value, key, key.len, errorIfMissing)
        stack.add((nextLookup, key))
    of 17:
      for i in 0 ..< 16:
        var branch = nodeRlp.listElem(i)
        if not branch.isEmpty:
          var key = path.cloneAndReserveNibble()
          key.replaceLastNibble(i.byte)
          let nextLookup = getLookup(db, branch, key, key.len, errorIfMissing)
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
    yield getKeysAux(self.db, stack, self.shouldMissingNodesBeErrors)

proc getValuesAux(db: DB, stack: var seq[tuple[nodeRlp: Rlp, path: NibblesSeq]], errorIfMissing: bool): seq[byte] =
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
        return value.toBytes
      else:
        let nextLookup = getLookup(db, value, key, key.len, errorIfMissing)
        stack.add((nextLookup, key))
    of 17:
      for i in 0 ..< 16:
        var branch = nodeRlp.listElem(i)
        if not branch.isEmpty:
          var key = path.cloneAndReserveNibble()
          key.replaceLastNibble(i.byte)
          let nextLookup = getLookup(db, branch, key, key.len, errorIfMissing)
          stack.add((nextLookup, key))

      var lastElem = nodeRlp.listElem(16)
      if not lastElem.isEmpty:
        return lastElem.toBytes
    else:
      raise newException(CorruptedTrieDatabase,
                        "HexaryTrie node with an unexpected number of children")

iterator values*(self: HexaryTrie): seq[byte] =
  var
    nodeRlp = rlpFromBytes keyToLocalBytes(self.db, self.root)
    stack = @[(nodeRlp, initNibbleRange([]))]
  while stack.len > 0:
    yield getValuesAux(self.db, stack, self.shouldMissingNodesBeErrors)

proc getPairsAux(db: DB, stack: var seq[tuple[nodeRlp: Rlp, path: NibblesSeq]], errorIfMissing: bool): (seq[byte], seq[byte]) =
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
        let nextLookup = getLookup(db, value, key, key.len, errorIfMissing)
        stack.add((nextLookup, key))
    of 17:
      for i in 0 ..< 16:
        var branch = nodeRlp.listElem(i)
        if not branch.isEmpty:
          var key = path.cloneAndReserveNibble()
          key.replaceLastNibble(i.byte)
          let nextLookup = getLookup(db, branch, key, key.len, errorIfMissing)
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
    let res = getPairsAux(self.db, stack, self.shouldMissingNodesBeErrors)
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

template getNode(db: DB, elem: Rlp): untyped =
  if elem.isList: @(elem.rawData)
  else: dbGet(db, elem.expectHash)

proc getBranchAux(db: DB, node: openArray[byte], fullPath: NibblesSeq, pathIndex: int, output: var seq[seq[byte]]) =
  var nodeRlp = rlpFromBytes node
  if not nodeRlp.hasData or nodeRlp.isEmpty: return

  let path = fullPath.slice(pathIndex)
  case nodeRlp.listLen
  of 2:
    let (isLeaf, k) = nodeRlp.extensionNodeKey
    let sharedNibbles = sharedPrefixLen(path, k)
    if sharedNibbles == k.len:
      let value = nodeRlp.listElem(1)
      if not isLeaf:
        let nextLookup = getNode(db, value)
        output.add nextLookup
        getBranchAux(db, nextLookup, fullPath, pathIndex + sharedNibbles, output)
  of 17:
    if path.len != 0:
      var branch = nodeRlp.listElem(path[0].int)
      if not branch.isEmpty:
        let nextLookup = getNode(db, branch)
        output.add nextLookup
        getBranchAux(db, nextLookup, fullPath, pathIndex + 1, output)
  else:
    raise newException(CorruptedTrieDatabase,
                       "HexaryTrie node with an unexpected number of children")

proc getBranch*(self: HexaryTrie; key: openArray[byte]): seq[seq[byte]] =
  result = @[]
  var node = keyToLocalBytes(self.db, self.root)
  result.add node
  getBranchAux(self.db, node, initNibbleRange(key), 0, result)

proc dbDel(t: var HexaryTrie, data: openArray[byte]) =
  if data.len >= 32: t.prune(data.keccakHash.data)

proc dbPut(db: DB, data: openArray[byte]): TrieNodeKey
    {.raises: [].} =
  result.hash = data.keccakHash
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

proc isTwoItemNode(self: HexaryTrie; r: Rlp, fullPath: NibblesSeq, pathIndex: int): bool =
  if r.isBlob:
    let resolved = getPossiblyMissingNode(self.db, r, fullPath, pathIndex, self.shouldMissingNodesBeErrors)
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

proc deleteAt(self: var HexaryTrie;
              origRlp: Rlp,
              fullPath: NibblesSeq,
              pathIndex: int): seq[byte]
  {.gcsafe, raises: [RlpError].}

proc deleteAux(self: var HexaryTrie;
               rlpWriter: var RlpWriter;
               origRlp: Rlp;
               fullPath: NibblesSeq,
               pathIndex: int): bool =
  if origRlp.isEmpty:
    return false

  var toDelete = if origRlp.isList: origRlp
                 else: rlpFromBytes getPossiblyMissingNode(self.db, origRlp, fullPath, pathIndex, self.shouldMissingNodesBeErrors)

  let b = self.deleteAt(toDelete, fullPath, pathIndex)

  if b.len == 0:
    return false

  rlpWriter.appendAndSave(b, self.db)
  return true

proc graft(self: var HexaryTrie; r: Rlp, fullPath: NibblesSeq, pathIndexToTheParent: int): seq[byte] =
  doAssert r.isList and r.listLen == 2
  var (_, origPath) = r.extensionNodeKey
  var value = r.listElem(1)

  if not value.isList:
    let nodeKey = value.expectHash
    var resolvedData = getPossiblyMissingNode(self.db, nodeKey, fullPath, pathIndexToTheParent + origPath.len, self.shouldMissingNodesBeErrors)
    self.prune(nodeKey)
    value = rlpFromBytes resolvedData

  doAssert value.listLen == 2
  let (valueIsLeaf, valueKey) = value.extensionNodeKey

  var rlpWriter = initRlpList(2)
  rlpWriter.append hexPrefixEncode(origPath, valueKey, valueIsLeaf)
  rlpWriter.append value.listElem(1)
  return rlpWriter.finish

proc mergeAndGraft(self: var HexaryTrie;
                   fullPath: NibblesSeq;
                   pathIndexToTheParent: int,
                   soleChild: Rlp, childPos: byte): seq[byte] =
  var output = initRlpList(2)
  if childPos == 16:
    output.append hexPrefixEncode(NibblesSeq(), true)
  else:
    doAssert(not soleChild.isEmpty)
    output.append int(hexPrefixEncodeByte(childPos))
  output.append(soleChild)
  result = output.finish()

  if self.isTwoItemNode(soleChild, fullPath, pathIndexToTheParent + 1):
    result = self.graft(rlpFromBytes(result), fullPath, pathIndexToTheParent)

# If the key is present, returns the RLP bytes for a node that
# omits this key. Returns an empty seq if the key is absent.
proc deleteAt(self: var HexaryTrie; origRlp: Rlp, fullPath: NibblesSeq, pathIndex: int): seq[byte]
    {.gcsafe, raises: [RlpError].} =
  if origRlp.isEmpty:
    # It's empty RLP, so the key is absent, so no change necessary.
    return

  doAssert origRlp.isTrieBranch
  let origBytes = @(origRlp.rawData)
  let path = fullPath.slice(pathIndex)
  if origRlp.listLen == 2:
    let (isLeaf, k) = origRlp.extensionNodeKey
    if k == path and isLeaf:
      # This is the leaf for the key we're looking for.
      # Omitting this key from the leaf means we're
      # left with empty RLP.
      self.dbDel origBytes
      return emptyRlp

    if path.startsWith(k):
      # This extension node gets us *partway* to the desired
      # key, but not all the way.
      let path = origRlp.listElem(0)
      let value = origRlp.listElem(1)
      # Create RLP for a new 2-item node that omits the key we're
      # trying to delete.
      var rlpWriter = initRlpList(2)
      rlpWriter.append(path)
      if not self.deleteAux(rlpWriter, value, fullPath, pathIndex + k.len):
        # Key is absent in the value, so never mind.
        return
      # We don't need the original node anymore, since we're about to
      # replace it with a modified one.
      self.dbDel origBytes
      var finalBytes = rlpWriter.finish
      var rlp = rlpFromBytes(finalBytes)
      # We already knew that *this* node is a 2-item node; now
      # we check to see if the modified *child* is also a 2-item
      # node, because if so, we can graft it.
      if self.isTwoItemNode(rlp.listElem(1), fullPath, pathIndex + k.len):
        return self.graft(rlp, fullPath, pathIndex)
      return finalBytes
    else:
      return
  else:
    if path.len == 0 and origRlp.listElem(16).isEmpty:
      self.dbDel origBytes
      var foundChildPos: byte
      let singleChild = origRlp.findSingleChild(foundChildPos)
      if singleChild.hasData and foundChildPos != 16:
        result = self.mergeAndGraft(fullPath, pathIndex + 1, singleChild, foundChildPos)
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
      let keyHead = int(path[0])
      var i = 0
      var origCopy = origRlp
      for elem in items(origCopy):
        if i == keyHead:
          if not self.deleteAux(rlpWriter, elem, fullPath, pathIndex + 1):
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
        result = self.mergeAndGraft(fullPath, pathIndex + 1, singleChild, foundChildPos)

proc del*(self: var HexaryTrie; key: openArray[byte]) =
  var
    rootBytes = keyToLocalBytes(self.db, self.root)
    rootRlp = rlpFromBytes rootBytes

  var newRootBytes = self.deleteAt(rootRlp, initNibbleRange(key), 0)
  if newRootBytes.len > 0:
    if rootBytes.len < 32:
      self.prune(self.root.asDbKey)
    self.root = self.db.dbPut(newRootBytes)

proc mergeAt(self: var HexaryTrie, orig: Rlp, origHash: KeccakHash,
  fullPath: NibblesSeq, pathIndex: int, value: openArray[byte],
  isInline = false): seq[byte]
  {.gcsafe, raises: [RlpError].}

proc mergeAt(self: var HexaryTrie, rlp: Rlp,
             fullPath: NibblesSeq, pathIndex: int, value: openArray[byte],
             isInline = false): seq[byte] =
  self.mergeAt(rlp, rlp.rawData.keccakHash, fullPath, pathIndex, value, isInline)

proc mergeAtAux(self: var HexaryTrie, output: var RlpWriter, orig: Rlp,
                fullPath: NibblesSeq, pathIndex: int, value: openArray[byte]) =
  var resolved = orig
  var isRemovable = false
  if not (orig.isList or orig.isEmpty):
    resolved = rlpFromBytes getPossiblyMissingNode(self.db, orig, fullPath, pathIndex, self.shouldMissingNodesBeErrors)
    isRemovable = true

  let b = self.mergeAt(resolved, fullPath, pathIndex, value, not isRemovable)
  output.appendAndSave(b, self.db)

proc mergeAt(self: var HexaryTrie, orig: Rlp, origHash: KeccakHash,
    fullPath: NibblesSeq, pathIndex: int, value: openArray[byte],
    isInline = false): seq[byte]
    {.gcsafe, raises: [RlpError].} =
  let path = fullPath.slice(pathIndex)
  template origWithNewValue: auto =
    self.prune(origHash.data)
    replaceValue(orig, path, value)

  if orig.isEmpty:
    return origWithNewValue()

  doAssert orig.isTrieBranch, $orig
  if orig.listLen == 2:
    let (isLeaf, k) = orig.extensionNodeKey
    var origValue = orig.listElem(1)

    if k == path and isLeaf:
      return origWithNewValue()

    let sharedNibbles = sharedPrefixLen(path, k)

    if sharedNibbles == k.len and not isLeaf:
      var r = initRlpList(2)
      r.append orig.listElem(0)
      self.mergeAtAux(r, origValue, fullPath, pathIndex + k.len, value)
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

      return self.mergeAt(rlpFromBytes(top.finish), fullPath, pathIndex, value, true)
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

      return self.mergeAt(rlpFromBytes(branches.finish), fullPath, pathIndex, value, true)
  else:
    if path.len == 0:
      return origWithNewValue()

    if isInline:
      self.prune(origHash.data)

    let n = path[0]
    var i = 0
    var r = initRlpList(17)

    var origCopy = orig
    for elem in items(origCopy):
      if i == int(n):
        self.mergeAtAux(r, elem, fullPath, pathIndex + 1, value)
      else:
        r.append(elem)
      inc i

    return r.finish

proc put*(self: var HexaryTrie; key, value: openArray[byte]) =
  let root = self.root.hash

  var rootBytes = getPossiblyMissingNode(self.db, root.data, NibblesSeq(), 0, self.shouldMissingNodesBeErrors)
  doAssert rootBytes.len > 0

  let newRootBytes = self.mergeAt(rlpFromBytes(rootBytes), root,
                                  initNibbleRange(key), 0, value)
  if rootBytes.len < 32:
    self.prune(root.data)

  self.root = self.db.dbPut(newRootBytes)

proc put*(self: var SecureHexaryTrie; key, value: openArray[byte]) =
  put(HexaryTrie(self), key.keccakHash.data, value)

proc get*(self: SecureHexaryTrie; key: openArray[byte]): seq[byte] =
  return get(HexaryTrie(self), key.keccakHash.data)

proc del*(self: var SecureHexaryTrie; key: openArray[byte]) =
  del(HexaryTrie(self), key.keccakHash.data)

proc rootHash*(self: SecureHexaryTrie): KeccakHash {.borrow.}
proc rootHashHex*(self: SecureHexaryTrie): string {.borrow.}
proc isPruning*(self: SecureHexaryTrie): bool {.borrow.}

template contains*(self: HexaryTrie | SecureHexaryTrie;
                   key: openArray[byte]): bool =
  self.get(key).len > 0

# Validates merkle proof against provided root hash
proc isValidBranch*(branch: seq[seq[byte]], rootHash: KeccakHash, key, value: seq[byte]): bool =
  # branch must not be empty
  doAssert(branch.len != 0)

  var db = newMemoryDB()
  for node in branch:
    doAssert(node.len != 0)
    let nodeHash = keccakHash(node)
    db.put(nodeHash.data, node)

  var trie = initHexaryTrie(db, rootHash)
  result = trie.get(key) == value




# The code below has a lot of duplication with the code above; I needed
# versions of get/put/del that don't just assume that all the nodes exist.
# Maybe there's some way to eliminate the duplication without screwing
# up performance? But for now I don't want to meddle with the existing
# code, for fear of breaking it. --Adam, Nov. 2022

proc db*(self: SecureHexaryTrie): TrieDatabaseRef = HexaryTrie(self).db

template maybeKeyToLocalBytes(db: DB, k: TrieNodeKey): Option[seq[byte]] =
  if k.len < 32:
    some(k.getLocalBytes)
  else:
    db.maybeGet(k.asDbKey)

proc maybeGetLookup(db: DB, elem: Rlp): Option[Rlp] =
  if elem.isList:
    some(elem)
  else:
    let h = elem.expectHash
    let maybeBytes = db.maybeGet(h)
    if maybeBytes.isNone:
      none[Rlp]()
    else:
      let bytes = maybeBytes.get
      some(rlpFromBytes(bytes))

proc maybeGetAux(db: DB, nodeRlp: Rlp, fullPath: NibblesSeq, pathIndex: int): Option[seq[byte]]
    {.gcsafe, raises: [RlpError].} =
  # FIXME-Adam: do I need to distinguish between these two cases?
  if not nodeRlp.hasData:
    let zero: seq[byte] = @[]
    return some(zero)
    # return none[seq[byte]]()
  if nodeRlp.isEmpty:
    # FIXME-Adam: I am REALLY not sure this is the right thing to do. But toGenesisHeader
    # failing is a pretty clear indication. So let's try this. I wonder whether the
    # above case needs to do this too.
    let zero: seq[byte] = @[]
    return some(zero)
    # return none[seq[byte]]()

  let path = fullPath.slice(pathIndex)
  case nodeRlp.listLen
  of 2:
    let (isLeaf, k) = nodeRlp.extensionNodeKey
    let sharedNibbles = sharedPrefixLen(path, k)

    if sharedNibbles == k.len:
      let value = nodeRlp.listElem(1)
      if sharedNibbles == path.len and isLeaf:
        return some(value.toBytes)
      elif not isLeaf:
        let maybeNextLookup = maybeGetLookup(db, value)
        if maybeNextLookup.isNone:
          return none[seq[byte]]()
        else:
          return maybeGetAux(db, maybeNextLookup.get, fullPath, pathIndex + sharedNibbles)
      else:
        raise newException(RlpError, "isLeaf is true but the shared nibbles didn't exhaust the path?")
    else:
      let zero: seq[byte] = @[]
      return some(zero)
  of 17:
    if path.len == 0:
      return some(nodeRlp.listElem(16).toBytes)
    var branch = nodeRlp.listElem(path[0].int)
    if branch.isEmpty:
      let zero: seq[byte] = @[]
      return some(zero)
    else:
      let maybeNextLookup = maybeGetLookup(db, branch)
      if maybeNextLookup.isNone:
        return none[seq[byte]]()
      else:
        return maybeGetAux(db, maybeNextLookup.get, fullPath, pathIndex + 1)
  else:
    raise newException(CorruptedTrieDatabase,
                       "HexaryTrie node with an unexpected number of children")

proc maybeGetAuxByHash(db: DB, node: TrieNodeKey, fullPath: NibblesSeq, pathIndex: int): Option[seq[byte]] =
  let maybeBytes = maybeKeyToLocalBytes(db, node)
  if maybeBytes.isNone:
    return none[seq[byte]]()
  else:
    let bytes = maybeBytes.get
    var nodeRlp = rlpFromBytes(bytes)
    return maybeGetAux(db, nodeRlp, fullPath, pathIndex)

proc maybeGet*(self: HexaryTrie; key: openArray[byte]): Option[seq[byte]] =
  return maybeGetAuxByHash(self.db, self.root, initNibbleRange(key), 0)

proc maybeGet*(self: SecureHexaryTrie; key: openArray[byte]): Option[seq[byte]] =
  return maybeGet(HexaryTrie(self), key.keccakHash.data)
