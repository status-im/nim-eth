{.used.}

import
  std/[os, options, sequtils],
  testutils/unittests,
  stew/endians2,
  ../../eth/db/[kvstore, kvstore_sqlite3],
  ./test_kvstore

procSuite "SqStoreRef":
  test "KvStore interface":
    let db = SqStoreRef.init("", "test", inMemory = true)[]
    defer: db.close()
    let kv = db.openKvStore()
    defer: kv.get()[].close()

    testKvStore(kvStore kv.get(), true)

  test "Readonly kvstore with no table":
    let db = SqStoreRef.init("", "test", inMemory = true, readOnly = true)[]
    defer: db.close()
    let kv = db.openKvStore().expect("working db")

    check:
      not kv.get([byte 0, 1, 2], nil).expect("ok to query data")
      kv.find([byte 0, 1, 2], nil).expect("ok") == 0
      kv.put([byte 0, 1, 2], []).isErr
      kv.del([byte 0, 1, 2]).isOk
    defer: kv[].close()

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
      openArray[byte], void).get

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
    let countRes = countStmt.exec do (res: int64):
      totalRecords = int res

    check:
      countRes.isOk and countRes.get == true
      totalRecords == 3

    # Without prepare..
    totalRecords = 0
    check:
      (db.exec("SELECT COUNT(*) FROM records;", ()) do (res: int64):
        totalRecords = int res).get()

    check:
      totalRecords == 3

    let selectRangeStmt = db.prepareStmt(
      "SELECT value FROM records WHERE key >= ? and key < ?;",
      (int64, int64), openArray[byte]).get

    block:
      var allBytes = newSeq[byte]()
      let selectRangeRes = selectRangeStmt.exec((0'i64, 5'i64)) do (bytes: openArray[byte]) {.gcsafe.}:
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
      let selectRangeRes = selectRangeStmt.exec((10'i64, 20'i64)) do (bytes: openArray[byte]):
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

  test "Tuple with byte arrays support":
    # openArray[byte] requires either Nim 1.4
    # or hardcoding the seq[byte] and array[N, byte] paths
    let db = SqStoreRef.init("", "test", inMemory = true)[]
    defer: db.close()

    let createTableRes = db.exec """
      CREATE TABLE IF NOT EXISTS attestations(
         validator_id INTEGER NOT NULL,
         source_epoch INTEGER NOT NULL,
         target_epoch INTEGER NOT NULL,
         attestation_root BLOB NOT NULL UNIQUE,
         UNIQUE (validator_id, target_epoch)
      );
    """
    check createTableRes.isOk

    let insertStmt = db.prepareStmt("""
      INSERT INTO attestations(
        validator_id,
        source_epoch,
        target_epoch,
        attestation_root)
      VALUES
        (?,?,?,?);
    """, (int32, int64, int64, array[32, byte]), void).get()

    var hash: array[32, byte]
    hash[1] = byte 1
    hash[2] = byte 2
    let insertRes = insertStmt.exec(
      (123'i32, 2'i64, 4'i64, hash)
    )

    check: insertRes.isOk

    let countStmt = db.prepareStmt(
      "SELECT COUNT(*) FROM attestations;",
      NoParams, int64).get

    var totalRecords = 0
    let countRes = countStmt.exec do (res: int64):
      totalRecords = int res

    check:
      countRes.isOk and countRes.get == true
      totalRecords == 1

    let selectRangeStmt = db.prepareStmt("""
      SELECT
        source_epoch,
        target_epoch,
        attestation_root
      FROM
        attestations
      WHERE
        validator_id = ?
        AND
        ? < source_epoch AND target_epoch < ?
      LIMIT 1
      """, (int32, int64, int64), (int64, int64, array[32, byte])).get()

    block:
      var digest: array[32, byte]
      var source, target: int64
      let selectRangeRes = selectRangeStmt.exec(
            (123'i32, 1'i64, 5'i64)
          ) do (res: tuple[source, target: int64, hash: array[32, byte]]) {.gcsafe.}:
        source = res.source
        target = res.target
        digest = res.hash

      if selectRangeRes.isErr:
        echo selectRangeRes.error

      check:
        selectRangeRes.isOk and selectRangeRes.get == true
        source == 2
        target == 4
        digest == hash

  test "null values":
    #
    let db = SqStoreRef.init("", "test", inMemory = true)[]
    defer: db.close()

    let createTableRes = db.exec """
      CREATE TABLE IF NOT EXISTS testnull(
         a INTEGER PRIMARY KEY,
         b INTEGER NULL,
         c INTEGER NULL
      );
    """
    check createTableRes.isOk

    type
      ABC = (int64, Option[int64], Option[int64])
    let insertStmt = db.prepareStmt("""
      INSERT INTO testnull(a, b, c) VALUES (?,?,?);
    """, ABC, void).get()

    const val = (42'i64, none(int64), some(44'i64))
    check:
      insertStmt.exec(val).isOk()

    let selectStmt = db.prepareStmt("""
      SELECT a, b, c FROM testnull
      """, NoParams, ABC).get()

    block:
      var abc: ABC
      let selectRes = selectStmt.exec do (res: ABC):
        abc = res

      if selectRes.isErr:
        echo selectRes.error

      check:
        selectRes.isOk and selectRes.get == true
        abc == val

      var found = false
      var row: selectStmt.Result
      for rowRes in selectStmt.exec(row):
        rowRes.expect("working db")
        check abc == row
        found = true
      check found

  proc customSumFun(
    a: openArray[byte],
    b: openArray[byte]): Result[seq[byte], cstring] {.noSideEffect, gcsafe, cdecl, raises: [Defect].} =
    let num1 = uint32.fromBytesBE(a)
    let num2 = uint32.fromBytesBE(b)
    let sum = num1 + num2
    let asBytes = sum.toBytesBE().toSeq()
    return ok(asBytes)

  test "Register custom scalar function":
    let db = SqStoreRef.init("", "test", inMemory = true)[]

    let registerResult = db.registerCustomScalarFunction("sum32", customSumFun)

    check:
      registerResult.isOk()

    defer: db.close()

    let kv = db.openKvStore().get()
    defer: kv.close()

    var sums: seq[seq[byte]] = @[]

    # Use custom function, which interprets blobs as uint32 numbers and sums
    # them together
    let sumKeyVal = db.prepareStmt(
      "SELECT sum32(key, value) FROM kvstore;",
      NoParams, seq[byte]).get

    let testUint = uint32(38)

    let putRes = kv.put(testUint.toBytesBE(), testUint.toBytesBE())

    check:
      putRes.isOk()

    discard sumKeyVal.exec do (res: seq[byte]):
      sums.add(res)

    check:
      len(sums) == 1

    let sum = uint32.fromBytesBE(sums[0])

    check:
      sum == testUint + testUint
