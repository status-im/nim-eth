{.used.}

import
  os,
  testutils/unittests,
  ../../eth/db/[kvstore, kvstore_sqlite3],
  ./test_kvstore

procSuite "SqStoreRef":
  test "KvStore interface":
    let db = SqStoreRef.init("", "test", inMemory = true)[]
    defer: db.close()

    testKvStore(kvStore db)

  test "Prepare and execute statements":
    let db = SqStoreRef.init("", "test", inMemory = true)[]
    defer: db.close()

    let createTableRes = db.exec """
      CREATE TABLE IF NOT EXISTS records(
         key INTEGER PRIMARY KEY,
         value BLOB
      );
    """
    check createTableRes.isOk

    let insertStmt = db.prepareStmt(
      "INSERT INTO records(value) VALUES (?);",
      openarray[byte], void).get

    let insert1Res = insertStmt.exec [byte 1, 2, 3, 4]
    let insert2Res = insertStmt.exec @[]
    let insert3Res = insertStmt.exec @[byte 5]

    check:
      insert1Res.isOk
      insert2Res.isOk
      insert3Res.isOk

    let countStmt = db.prepareStmt(
      "SELECT COUNT(*) FROM records;",
      NoParams, int64).get

    var totalRecords = 0
    echo "About to call total records"
    let countRes = countStmt.exec do (res: int64):
      totalRecords = int res

    check:
      countRes.isOk and countRes.get == true
      totalRecords == 3

    let selectRangeStmt = db.prepareStmt(
      "SELECT value FROM records WHERE key >= ? and key < ?;",
      (int64, int64), openarray[byte]).get

    block:
      var allBytes = newSeq[byte]()
      let selectRangeRes = selectRangeStmt.exec((0'i64, 5'i64)) do (bytes: openarray[byte]) {.gcsafe.}:
        allBytes.add byte(bytes.len)
        allBytes.add bytes

      if selectRangeRes.isErr:
        echo selectRangeRes.error

      check:
        selectRangeRes.isOk and selectRangeRes.get == true
        allBytes == [byte 4, 1, 2, 3, 4,
                     0,
                     1, 5]
    block:
      let selectRangeRes = selectRangeStmt.exec((10'i64, 20'i64)) do (bytes: openarray[byte]):
        echo "Got unexpected bytes: ", bytes

      check:
        selectRangeRes.isOk and selectRangeRes.get == false

    let selectAllStmt = db.prepareStmt(
      "SELECT * FROM records;",
      NoParams, (int64, seq[byte])).get

    var indices = newSeq[int64]()
    var values = newSeq[seq[byte]]()

    discard selectAllStmt.exec do (res: (int64, seq[byte])):
      indices.add res[0]
      values.add res[1]

    check:
      indices == [int64 1, 2, 3]
      values == [
        @[byte 1, 2, 3, 4],
        @[],
        @[byte 5]
      ]

