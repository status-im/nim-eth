import
  unittest, macros, os,
  eth/trie/backends/[rocksdb_backend, sqlite_backend, lmdb_backend]

template dummyInstance(T: type SqliteChainDB): auto =
  sqlite_backend.newChainDB(getTempDir(), inMemory = true)

template dummyInstance(T: type RocksChainDB): auto =
  let tmp = getTempDir() / "nimbus-test-db"
  removeDir(tmp)
  rocksdb_backend.newChainDB(tmp)

template dummyInstance(T: type LmdbChainDB): auto =
  # remove sqlite created database
  let tmp = getTempDir() / "nimbus.db"
  removeFile(tmp)
  lmdb_backend.newChainDB(getTempDir())

template backendTests(DB) =
  suite("storage tests: " & astToStr(DB)):
    setup:
      var db = dummyInstance(DB)

    teardown:
      close(db)

    test "basic insertions and deletions":
      var keyA = [1.byte, 2, 3]
      var keyB = [1.byte, 2, 4]
      var value1 = @[1.byte, 2, 3, 4, 5]
      var value2 = @[7.byte, 8, 9, 10]

      db.put(keyA, value1)

      check:
        keyA in db
        keyB notin db

      db.put(keyB, value2)

      check:
        keyA in db
        keyB in db

      check:
        db.get(keyA) == value1
        db.get(keyB) == value2

      db.del(keyA)
      db.put(keyB, value1)

      check:
        keyA notin db
        keyB in db

      check db.get(keyA).len == 0

      check db.get(keyB) == value1
      db.del(keyA)

backendTests(RocksChainDB)
backendTests(SqliteChainDB)
backendTests(LmdbChainDB)
