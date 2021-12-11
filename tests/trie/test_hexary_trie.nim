{.used.}

import
  std/[sequtils, os, algorithm, random],
  unittest2,
  stew/byteutils, nimcrypto/utils,
  ../../eth/trie/[hexary, db, trie_defs],
  ./testutils

from strutils import split

suite "hexary trie":
  setup:
    var
      db = newMemoryDB()
      tr {.used.} = initHexaryTrie(db)

  test "ref-counted keys crash":
    proc addKey(intKey: int) =
      var key = newSeqWith(20, 0.byte)
      key[19] = byte(intKey)
      var data = newSeqWith(29, 1.byte)

      var k = key

      let v = tr.get(k)
      doAssert(v.len == 0)

      tr.put(k, data)

    addKey(166)
    addKey(193)
    addKey(7)
    addKey(101)
    addKey(159)
    addKey(187)
    addKey(206)
    addKey(242)
    addKey(94)
    addKey(171)
    addKey(14)
    addKey(143)
    addKey(237)
    addKey(148)
    addKey(181)
    addKey(147)
    addKey(45)
    addKey(81)
    addKey(77)
    addKey(123)
    addKey(35)
    addKey(24)
    addKey(188)
    addKey(136)


  const genesisAccounts = "tests/cases/mainnet-genesis-accounts.txt"
  if fileExists(genesisAccounts):
    # This test is optional because it takes a while to run and the
    # verification is already being part of Nimbus (see genesis.nim).
    #
    # On the other hand, it's useful to be able to debug just the trie
    # code if problems arise. You can download the genesis-accounts file
    # using the the following command at the root at the repo:
    #
    # wget https://gist.github.com/zah/f3a7d325a71d35df3c2606af05d30910/raw/d8bf8fed3d2760f0054cebf4de254a0564a87322/mainnet-genesis-accounts.txt -P tests/cases
    test "genesis hash":
      for line in lines(genesisAccounts):
        var parts = line.split(" ")
        var
          key = fromHex(parts[0])
          val = fromHex(parts[1])

        SecureHexaryTrie(tr).put(key, val)

      check tr.rootHashHex == "D7F8974FB5AC78D9AC099B9AD5018BEDC2CE0A72DAD1827A1709DA30580F0544"

  # lexicographic comparison
  proc lexComp(a, b: seq[byte]): bool =
    var
      x = 0
      y = 0
      xlen = a.len
      ylen = b.len

    while x != xlen:
      if y == ylen or b[y] < a[x]: return false
      elif a[x] < b[y]: return true
      inc x
      inc y

    result = y != ylen

  proc cmp(a, b: seq[byte]): int =
    if a == b: return 0
    if a.lexComp(b): return 1
    return -1

  test "get values and keys":
    randomize()
    var
      memdb = newMemoryDB()
      trie = initHexaryTrie(memdb)
      keys = [
        "key".toBytes,
        "abc".toBytes,
        "hola".toBytes,
        "bubble".toBytes
      ]

      vals = [
        "hello".toBytes,
        "world".toBytes,
        "block".toBytes,
        "chain".toBytes
      ]

    for i in 0 ..< keys.len:
      trie.put(keys[i], vals[i])

    var values = trie.getValues()
    values.sort(cmp)
    vals.sort(cmp)
    check values == vals

    var paths = trie.getKeys()
    paths.sort(cmp)
    keys.sort(cmp)
    check paths == keys

    paths.setLen(0)
    for k in trie.keys:
      paths.add(k)
    paths.sort(cmp)
    keys.sort(cmp)
    check paths == keys

    values.setLen(0)
    paths.setLen(0)
    for k, v in trie:
      paths.add k
      values.add v

    paths.sort(cmp)
    values.sort(cmp)
    check paths == keys
    check values == vals

  test "get values and keys with random data":
    var
      memdb = newMemoryDB()
      trie = initHexaryTrie(memdb)
      keys = randList(seq[byte], randGen(5, 32), randGen(10))
      vals = randList(seq[byte], randGen(5, 7), randGen(10))

      keys2 = randList(seq[byte], randGen(5, 30), randGen(15))
      vals2 = randList(seq[byte], randGen(5, 7), randGen(15))

    for i in 0 ..< keys.len:
      trie.put(keys[i], vals[i])

    for i in 0 ..< keys.len:
      check trie.get(keys[i]) == vals[i]

    var values = trie.getValues()
    values.sort(cmp)
    vals.sort(cmp)
    check values == vals

    let rootHash = trie.rootHash
    for i in 0 ..< keys2.len:
      trie.put(keys2[i], vals2[i])
    var trie2 = initHexaryTrie(memdb, rootHash)

    # because of pruning, equality become uncertain
    values = trie2.getValues()
    values.sort(cmp)
    let
      cmpResultA = values != vals
      cmpResultB = values == vals
    check cmpResultB or cmpResultA

    var values2 = trie.getValues()
    vals2.add vals
    values2.sort(cmp)
    vals2.sort(cmp)
    check values2 == vals2

    values2.setLen(0)
    for k in trie.values:
      values2.add(k)
    values2.sort(cmp)
    check values2 == vals2

    var paths = trie.getKeys()
    paths.sort(cmp)
    keys2.add keys
    keys2.sort(cmp)
    check paths == keys2

    paths.setLen(0)
    for k in trie.keys:
      paths.add(k)
    paths.sort(cmp)
    check paths == keys2

    values.setLen(0)
    paths.setLen(0)
    for k, v in trie:
      paths.add k
      values.add v

    paths.sort(cmp)
    values.sort(cmp)
    check paths == keys2
    check values == vals2

  test "non-pruning mode":
    var
      memdb = newMemoryDB()
      nonPruningTrie = initHexaryTrie(memdb, false)
      keys = randList(seq[byte], randGen(5, 77), randGen(30))
      vals = randList(seq[byte], randGen(1, 57), randGen(30))

      moreKeys = randList(seq[byte], randGen(5, 33), randGen(45))
      moreVals = randList(seq[byte], randGen(1, 47), randGen(45))

    for i in 0 ..< keys.len:
      nonPruningTrie.put(keys[i], vals[i])

    let rootHash = nonPruningTrie.rootHash
    for i in 0 ..< moreKeys.len:
      nonPruningTrie.put(moreKeys[i], moreVals[i])

    var
      readOnlyTrie = initHexaryTrie(memdb, rootHash)
      secondaryTrie = initHexaryTrie(memdb, rootHash, false)

    keys.sort(cmp)
    vals.sort(cmp)

    var
      roKeys = readOnlyTrie.getKeys()
      roValues = readOnlyTrie.getValues()
      scKeys = secondaryTrie.getKeys()
      scValues = secondaryTrie.getValues()

    roKeys.sort(cmp)
    roValues.sort(cmp)
    scKeys.sort(cmp)
    scValues.sort(cmp)

    check keys == roKeys
    check vals == roValues
    check keys == scKeys
    check vals == scValues

  test "elaborate non-pruning test":
    type
      History = object
        keys: seq[seq[byte]]
        values: seq[seq[byte]]
        rootHash: KeccakHash

    const
      listLength = 30
      numLoop = 100

    for iteration in 0 ..< numLoop:
      var
        memdb = newMemoryDB()
        nonPruningTrie = initHexaryTrie(memdb, false)
        keys = randList(seq[byte], randGen(3, 33), randGen(listLength))
        values = randList(seq[byte], randGen(5, 77), randGen(listLength))
        historyList = newSeq[History](listLength)
        ok = true

      for i, k in keys:
        historyList[i].keys = newSeq[seq[byte]](i + 1)
        historyList[i].values = newSeq[seq[byte]](i + 1)
        for x in 0 ..< i + 1:
          historyList[i].keys[x] = keys[x]
          historyList[i].values[x] = values[x]
        nonPruningTrie.put(keys[i], values[i])
        historyList[i].rootHash = nonPruningTrie.rootHash
        historyList[i].keys.sort(cmp)
        historyList[i].values.sort(cmp)

      for h in historyList:
        var
          trie = initHexaryTrie(memdb, h.rootHash)
          pKeys: seq[seq[byte]] = @[]
          pValues = trie.getValues()

        for k in trie.keys:
          pKeys.add k
        pKeys.sort(cmp)
        pValues.sort(cmp)
        check pKeys.len == h.keys.len
        check pValues.len == h.values.len
        check pKeys == h.keys
        check pValues == h.values

        ok = ok and pKeys.len == h.keys.len
        ok = ok and pValues.len == h.values.len
        ok = ok and pKeys == h.keys
        ok = ok and pValues == h.values
        if not ok: break

      if not ok:
        echo "ITERATION: ", iteration
        break

  test "get branch with pruning trie":
    var
      memdb = newMemoryDB()
      trie = initHexaryTrie(memdb)
      keys = randList(seq[byte], randGen(5, 77), randGen(30))
      vals = randList(seq[byte], randGen(1, 57), randGen(30))

    for i in 0 ..< keys.len:
      trie.put(keys[i], vals[i])

    for i in 0 ..< keys.len:
      var branch = trie.getBranch(keys[i])
      check isValidBranch(branch, trie.rootHash, keys[i], vals[i])

  test "get branch with non pruning trie":
    const
      numKeyVal = 30

    var
      memdb = newMemoryDB()
      nonPruningTrie = initHexaryTrie(memdb, false)
      keys = randList(seq[byte], randGen(5, 77), randGen(numKeyVal))
      vals = randList(seq[byte], randGen(1, 57), randGen(numKeyVal))
      roots = newSeq[KeccakHash](numKeyVal)

    for i in 0 ..< keys.len:
      nonPruningTrie.put(keys[i], vals[i])
      roots[i] = nonPruningTrie.rootHash

    for i in 0 ..< keys.len:
      var trie = initHexaryTrie(memdb, roots[i], false)
      for x in 0 ..< i+1:
        var branch = trie.getBranch(keys[x])
        check isValidBranch(branch, trie.rootHash, keys[x], vals[x])

  test "isPruning getter":
    var
      memdb = newMemoryDB()
      nonPruningTrie = initHexaryTrie(memdb, false)
      pruningTrie = initHexaryTrie(memdb, true)
      nonPruningSecureTrie = initSecureHexaryTrie(memdb, false)
      pruningSecureTrie = initSecureHexaryTrie(memdb, true)

    check nonPruningTrie.isPruning == false
    check pruningTrie.isPruning == true
    check nonPruningSecureTrie.isPruning == false
    check pruningSecureTrie.isPruning == true

  test "multi-roots pruning trie":
    const
      numKeyVal = 30

    var
      memdb = newMemoryDB()
      pruningTrie = initHexaryTrie(memdb, isPruning = true)

    let
      keys = randList(seq[byte], randGen(5, 77), randGen(numKeyVal))
      vals = randList(seq[byte], randGen(1, 57), randGen(numKeyVal))
      newVals = randList(seq[byte], randGen(1, 63), randGen(numKeyVal))

    var tx1 = memdb.beginTransaction()
    for i in 0 ..< numKeyVal:
      pruningTrie.put(keys[i], vals[i])
    tx1.commit()
    let rootHash1 = pruningTrie.rootHash

    var tx2 = memdb.beginTransaction()
    for i in 0 ..< numKeyVal:
      pruningTrie.put(keys[i], newVals[i])
    tx2.commit(applyDeletes = false)
    let rootHash2 = pruningTrie.rootHash

    check rootHash1 != rootHash2

    var trie1 = initHexaryTrie(memdb, rootHash1, isPruning = true)
    for x in 0 ..< numKeyVal:
      var branch = trie1.getBranch(keys[x])
      check isValidBranch(branch, trie1.rootHash, keys[x], vals[x])

    var trie2 = initHexaryTrie(memdb, rootHash2, isPruning = true)
    for x in 0 ..< numKeyVal:
      var branch = trie2.getBranch(keys[x])
      check isValidBranch(branch, trie2.rootHash, keys[x], newVals[x])

  test "replicate iterator":
    const
      numKeyVal = 30

    var
      memdb = newMemoryDB()
      repdb = newMemoryDB()
      pruningTrie = initHexaryTrie(memdb, isPruning = true)

    let
      keys = randList(seq[byte], randGen(5, 77), randGen(numKeyVal))
      vals = randList(seq[byte], randGen(1, 57), randGen(numKeyVal))

    for i in 0 ..< numKeyVal:
      pruningTrie.put(keys[i], vals[i])

    let rootHash = pruningTrie.rootHash
    for k, v in pruningTrie.replicate:
      repdb.put(k, v)

    var trie = initHexaryTrie(repdb, rootHash, isPruning = true)
    var numPairs = 0
    for k, v in trie.pairs:
      check k in keys
      check v in vals
      inc numPairs
    check numPairs == numKeyVal
