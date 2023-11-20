{.used.}

import
  std/sequtils,
  testutils/unittests,
  stew/endians2,
  stew/ptrops,
  sqlite3_abi,
  ../../eth/db/kvstore_sqlite3

procSuite "SqStoreRef custom function":

  proc customSum(
      ctx: SqliteContext, n: cint, v: SqliteValue)
      {.cdecl, gcsafe, raises: [].} =
    doAssert(n == 2)

    let
      ptrs = makeUncheckedArray(v)
      blob1Len = sqlite3_value_bytes(ptrs[][0])
      blob2Len = sqlite3_value_bytes(ptrs[][1])

      num1 = uint32.fromBytesBE(makeOpenArray(
        sqlite3_value_blob(ptrs[][0]), byte, blob1Len))
      num2 = uint32.fromBytesBE(makeOpenArray(
        sqlite3_value_blob(ptrs[][1]), byte, blob2Len))
      sum = num1 + num2

      bytes = sum.toBytesBE().toSeq()

    sqlite3_result_blob(ctx, baseAddr bytes, cint bytes.len, SQLITE_TRANSIENT)

  test "Create custom function":
    let db = SqStoreRef.init("", "test", inMemory = true)[]
    defer: db.close()

    db.createCustomFunction("sum32", 2, customSum).expect(
      "Custom function creation OK")

    let kv = db.openKvStore().expect("Working database")
    defer: kv.close()

    # Use the custom function, which interprets blobs as uint32 numbers and
    # sums them together
    let sumStmt = db.prepareStmt(
      "SELECT sum32(key, value) FROM kvstore;",
      NoParams, seq[byte]).get()

    let
      key = uint32(39)
      val = uint32(38)

    kv.put(key.toBytesBE(), val.toBytesBE()).expect("Working database")

    var sums: seq[seq[byte]] = @[]
    discard sumStmt.exec do (res: seq[byte]):
      sums.add(res)

    check:
      len(sums) == 1

    let sum = uint32.fromBytesBE(sums[0])

    check:
      sum == key + val
