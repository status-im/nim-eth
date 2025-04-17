import ../common/hashes, ../rlp, stew/arraybuf

export hashes

type
  ShortHash = ArrayBuf[32, byte]

  OrderedTrieLeaf*[T] = object
    keyPath: ArrayBuf[10, byte]
    value: T

  OrderedTrieBranch* = ArrayBuf[16, ShortHash]

  OrderedTrieExtension* = object
    keyPath: ArrayBuf[10, byte]
    value: ShortHash

  OrderedTrieNode = OrderedTrieLeaf | OrderedTrieExtension | OrderedTrieBranch

  OrderedTrieRootBuilder* = object
    ## A special case of hexary trie root building for the case where keys are
    ## sorted integers and number of entries is known ahead of time.
    ##
    ## The builder must be initialized with the value count by calling `init`.
    ##
    ## In the ethereum MPT, leaf leaves are computed by prefixing the value with
    ## its trie path slice. When the keys are ordere, we can pre-compute the
    ## trie path slice thus avoiding unnecessary storage of leaf values.
    ##
    ## Similar implementations with various tradeoffs exist that cover the
    ## general case:
    ##
    ## * https://github.com/alloy-rs/trie
    ## * https://github.com/rust-ethereum/ethereum/blob/b160820620aa9fd30050d5fcb306be4e12d58c8c/src/util.rs#L152
    ## * https://github.com/ethereum/go-ethereum/blob/master/trie/stacktrie.go
    ##
    ## TODO We don't need to store all leaves - instead, we could for each
    ##      level of the trie store only a hashing state that collects the trie
    ##      built "so far", similar to the StackTrie implementation - this works
    ##      for items 0x80 and up where the rlp-encoded order matches insertion
    ##      order.
    leaves: seq[ShortHash]

    items: int
      ## Number of items added so far (and therefore also the key of the next item)

func init*(T: type OrderedTrieRootBuilder, expected: int): T =
  T(leaves: newSeq[ShortHash](expected))

proc append*(w: var RlpWriter, node: OrderedTrieLeaf) =
  w.startList(2)
  w.append(node.keyPath.data)
  w.wrapEncoding(1)
  w.append(node.value)

proc append*(w: var RlpWriter, node: OrderedTrieExtension) =
  w.startList(2)
  w.append(node.keyPath.data)
  w.append(node.value)

func append*(w: var RlpWriter, key: ShortHash) =
  if 1 < key.len and key.len < 32:
    w.appendRawBytes key.data
  else:
    w.append key.data

proc append*(w: var RlpWriter, branchNode: OrderedTrieBranch) = 
  w.startList(17)
  for n in 0 .. 15:
    w.append(branchNode[n])
  w.append(openArray[byte]([]))

func toShortHash(v: OrderedTrieNode): ShortHash =
  withTracker(v):
    let length = tracker.totalLength
    if length < 32:
      var writer = initTwoPassWriter(tracker)
      writer.append(v)
      let buf = writer.finish()
      return ShortHash.initCopyFrom(buf)
    else:
      var writer = initHashWriter(tracker)
      writer.append(v)
      let buf = writer.finish()
      return ShortHash.initCopyFrom(buf.data)

func keyAtIndex(b: var OrderedTrieRootBuilder, i: int): RlpIntBuf =
  # Given a leaf index, compute the rlp-encoded key
  let key =
    if i <= 0x7f:
      if i == min(0x7f, b.leaves.len - 1):
        0'u64
      else:
        uint64 i + 1
    else:
      uint64 i
  rlp.encodeInt(key)

func nibble(v: RlpIntBuf, i: int): byte =
  let data = v.data[i shr 1]
  if (i and 1) != 0:
    data and 0xf
  else:
    data shr 4

func nibbles(v: RlpIntBuf): int =
  v.len * 2

func sharedPrefixLen(a, b: RlpIntBuf): int =
  # Number of nibbles the two buffers have in common
  for i in 0 ..< min(a.len, b.len):
    if a[i] != b[i]:
      return
        if a.nibble(i * 2) == b.nibble(i * 2):
          i * 2 + 1
        else:
          i * 2
  min(a.len, b.len)

func hexPrefixEncode(
    r: RlpIntBuf, ibegin, iend: int, isLeaf = false
): ArrayBuf[10, byte] =
  let nibbleCount = iend - ibegin
  var oddnessFlag = (nibbleCount and 1) != 0
  result.setLen((nibbleCount div 2) + 1)
  result[0] = byte((int(isLeaf) * 2 + int(oddnessFlag)) shl 4)
  var writeHead = 0

  for i in ibegin ..< iend:
    let nextNibble = r.nibble(i)
    if oddnessFlag:
      result[writeHead] = result[writeHead] or nextNibble
    else:
      inc writeHead
      result[writeHead] = nextNibble shl 4
    oddnessFlag = not oddnessFlag

proc keyToIndex(b: var OrderedTrieRootBuilder, key: uint64): int =
  ## Given a key, compute its position according to the rlp-encoded integer
  ## ordering, ie the order that would result from encoding the key
  ## with RLP, "shortest big endian encoding" and sorting lexicographically -
  ## this lexicographical order determines the location of the key in the trie
  if key == 0:
    # Key 0 goes into position 0x7f or last, depending on how many there are
    min(0x7f, b.leaves.len - 1)
  elif key <= uint64 min(0x7f, b.leaves.len - 1):
    int key - 1
  else:
    int key

proc updateHash(b: var OrderedTrieRootBuilder, key: uint64, v: auto) =
  let
    pos = b.keyToIndex(key)
    cur = rlp.encodeInt(key)
  b.leaves[pos] =
    try:
      # compute the longest shared nibble prefix between a key and its sorted
      # neighbours which determines how much of the key is left in the leaf
      # itself during encoding
      let spl =
        if b.leaves.len == 1:
          -1 # If there's only one leaf, the whole key is used as leaf path
        else:
          if pos + 1 < b.leaves.len:
            let next = b.keyAtIndex(pos + 1)
            if pos > 0:
              let prev = b.keyAtIndex(pos - 1)
              max(prev.sharedPrefixLen(cur), next.sharedPrefixLen(cur))
            else:
              next.sharedPrefixLen(cur)
          else:
            let prev = b.keyAtIndex(pos - 1)
            prev.sharedPrefixLen(cur)

      let leafNode = OrderedTrieLeaf[typeof v](
        keyPath: cur.hexPrefixEncode(spl + 1, cur.nibbles, isLeaf = true),
        value: v
      )

      toShortHash(leafNode)
    except RlpError:
      raiseAssert "RLP failures not expected"

proc add*[T](b: var OrderedTrieRootBuilder, v: openArray[T]) =
  ## Add items to the trie root builder, calling `rlp.encode(item)` to compute
  ## the value of the item. The total number of items added before calling
  ## `rootHash` must equal what was given in `init`.
  ##
  ## TODO instead of RLP-encoding the items to bytes, we should be hashing them
  ##      directly:
  ##      * https://github.com/status-im/nim-eth/issues/724
  ##      * https://github.com/status-im/nim-eth/issues/698
  for item in v:
    b.updateHash(uint64 b.items, item)
    b.items += 1

proc computeKey(b: var OrderedTrieRootBuilder, rng: Slice[int], depth: int): ShortHash =
  if rng.len == 0:
    ShortHash.initCopyFrom([byte 128]) # RLP of empty list
  elif rng.len == 1: # Leaf
    b.leaves[rng.a]
  else: # Branch (or extension)
    var p = int.high
    let ka = b.keyAtIndex(rng.a)

    # Find the shortest shared prefix among the given keys - if this is not 0,
    # it means an extension node must be introduced among the nodes in the given
    # range. The top level always has a 0 shared length prefix because the
    # encodings for 0 and 1 start with different nibbles.
    if depth == 0:
      p = 0
    else:
      for i in 1 ..< rng.len:
        # TODO We can get rid of this loop by observing what the nibbles in the
        #      RLP integer encoding have in common and adjust accordingly
        p = min(p, sharedPrefixLen(ka, b.keyAtIndex(rng.a + i)))
        if p == depth:
          break

    var w = initRlpWriter()

    if p == depth: # No shared prefix - this is a branch
      var branchNode = OrderedTrieBranch()
      # Sub-divide the keys by nibble and recurse
      var pos = rng.a
      for n in 0 .. 15:
        var x: int
        # Pick out the keys that have the asked-for nibble at the given depth
        while pos + x <= rng.b and b.keyAtIndex(pos + x).nibble(depth) == uint8(n):
          x += 1

        if x > 0:
          branchNode[n] = b.computeKey(pos .. pos + x - 1, depth + 1)
        else:
          branchNode[n] = ShortHash.initCopyFrom(openArray[byte]([]))
        pos += x

      return toShortHash(branchNode) 
    else:
      let extNode = OrderedTrieExtension(
        keyPath: ka.hexPrefixEncode(depth, p, isLeaf = false),
        value: b.computeKey(rng, p)
      )

      return toShortHash(extNode) 

proc rootHash*(b: var OrderedTrieRootBuilder): Root =
  doAssert b.items == b.leaves.len, "Items added does not match initial length"
  let h = b.computeKey(0 ..< b.leaves.len, 0)
  if h.len == 32:
    Root(h.buf)
  else:
    keccak256(h.data)

proc orderedTrieRoot*[T](items: openArray[T]): Root =
  ## Compute the MPT root of a list of items using their rlp-encoded index as
  ## key.
  ##
  ## Typical examples include the transaction and withdrawal roots that appear
  ## in blocks.
  ##
  ## The given values will be rlp-encoded using `rlp.encode`.
  var b = OrderedTrieRootBuilder.init(items.len)
  b.add(items)
  b.rootHash

when isMainModule: # A small benchmark
  import std/[monotimes, times], eth/trie/[hexary, db]

  let n = 1000000
  echo "Testing ", n
  let values = block:
    var tmp: seq[uint64]
    for i in 0 .. n:
      tmp.add i.uint64
    tmp

  let x0 = getMonoTime()
  let b1 = block:
    var db = OrderedTrieRootBuilder.init(values.len)

    db.add(values)
    db.rootHash()
  echo b1
  let x1 = getMonoTime()
  let b2 = block:
    var db2 = initHexaryTrie(newMemoryDB())
    for v in values:
      db2.put(rlp.encode(v), rlp.encode(v))

    db2.rootHash()
  let x2 = getMonoTime()
  assert b1 == b2

  echo (
    (x1 - x0), (x2 - x1), (x1 - x0).inNanoseconds.float / (x2 - x1).inNanoseconds.float
  )
