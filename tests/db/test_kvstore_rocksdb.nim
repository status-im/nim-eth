{.used.}

import
  std/[os, unittest],
  chronicles,
  ../../eth/db/[kvstore, kvstore_rocksdb],
  ./test_kvstore

suite "RocksStoreRef":
  test "KvStore interface":
    let tmp = getTempDir() / "nimbus-test-db"
    removeDir(tmp)

    let db = RocksStoreRef.init(tmp, "test")[]
    defer: db.close()

    testKvStore(kvStore db, false)
