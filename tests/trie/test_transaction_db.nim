{.used.}

import
  unittest,
  eth/trie/[db], ./testutils

suite "transaction db":
  setup:
    const
      listLength = 30

    var
      keysA = randList(seq[byte], randGen(3, 33), randGen(listLength))
      valuesA = randList(seq[byte], randGen(5, 77), randGen(listLength))
      keysB = randList(seq[byte], randGen(3, 33), randGen(listLength))
      valuesB = randList(seq[byte], randGen(5, 77), randGen(listLength))

    proc populateA(db: TrieDatabaseRef) =
      for i in 0 ..< listLength:
        db.put(keysA[i], valuesA[i])

    proc checkContentsA(db: TrieDatabaseRef): bool =
      for i in 0 ..< listLength:
        let v = db.get(keysA[i])
        if v != valuesA[i]: return false
      result = true

    proc checkEmptyContentsA(db: TrieDatabaseRef): bool {.used.} =
      for i in 0 ..< listLength:
        let v = db.get(keysA[i])
        if v.len != 0: return false
      result = true

    proc populateB(db: TrieDatabaseRef) {.used.} =
      for i in 0 ..< listLength:
        db.put(keysB[i], valuesB[i])

    proc checkContentsB(db: TrieDatabaseRef): bool {.used.} =
      for i in 0 ..< listLength:
        let v = db.get(keysB[i])
        if v != valuesB[i]: return false
      result = true

    proc checkEmptyContentsB(db: TrieDatabaseRef): bool {.used.} =
      for i in 0 ..< listLength:
        let v = db.get(keysB[i])
        if v.len != 0: return false
      result = true

  test "commit":
    var db = newMemoryDB()
    var tx = db.beginTransaction()
    db.populateA()
    check checkContentsA(db)
    tx.commit()
    check checkContentsA(db)

  test "rollback":
    var db = newMemoryDB()
    var tx = db.beginTransaction()
    db.populateA()
    check checkContentsA(db)
    tx.rollback()
    check checkEmptyContentsA(db)

  test "dispose":
    var db = newMemoryDB()
    var tx = db.beginTransaction()
    db.populateA()
    check checkContentsA(db)
    tx.dispose()
    check checkEmptyContentsA(db)

  test "commit dispose":
    var db = newMemoryDB()
    var tx = db.beginTransaction()
    db.populateA()
    check checkContentsA(db)
    tx.commit()
    tx.dispose()
    check checkContentsA(db)

  test "rollback dispose":
    var db = newMemoryDB()
    var tx = db.beginTransaction()
    db.populateA()
    check checkContentsA(db)
    tx.rollback()
    tx.dispose()
    check checkEmptyContentsA(db)

  test "dispose dispose":
    var db = newMemoryDB()
    var tx = db.beginTransaction()
    db.populateA()
    check checkContentsA(db)
    tx.dispose()
    tx.dispose()
    check checkEmptyContentsA(db)

  test "commit commit":
    var db = newMemoryDB()
    var txA = db.beginTransaction()
    db.populateA()
    var txB = db.beginTransaction()
    db.populateB()

    check checkContentsA(db)
    check checkContentsB(db)

    txB.commit()
    txA.commit()

    check checkContentsA(db)
    check checkContentsB(db)

  test "commit rollback":
    var db = newMemoryDB()
    var txA = db.beginTransaction()
    db.populateA()
    var txB = db.beginTransaction()
    db.populateB()

    check checkContentsA(db)
    check checkContentsB(db)

    txB.rollback()
    txA.commit()

    check checkContentsA(db)
    check checkEmptyContentsB(db)

  test "rollback commit":
    var db = newMemoryDB()
    var txA = db.beginTransaction()
    db.populateA()
    var txB = db.beginTransaction()
    db.populateB()

    check checkContentsA(db)
    check checkContentsB(db)

    txB.commit()
    txA.rollback()

    check checkEmptyContentsB(db)
    check checkEmptyContentsA(db)

  test "rollback rollback":
    var db = newMemoryDB()
    var txA = db.beginTransaction()
    db.populateA()
    var txB = db.beginTransaction()
    db.populateB()

    check checkContentsA(db)
    check checkContentsB(db)

    txB.rollback()
    txA.rollback()

    check checkEmptyContentsB(db)
    check checkEmptyContentsA(db)

  test "commit rollback dispose":
    var db = newMemoryDB()
    var txA = db.beginTransaction()
    db.populateA()
    var txB = db.beginTransaction()
    db.populateB()

    check checkContentsA(db)
    check checkContentsB(db)

    txB.rollback()
    txA.commit()
    txA.dispose()

    check checkContentsA(db)
    check checkEmptyContentsB(db)
