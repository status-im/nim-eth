## Implementation of KvStore based on sqlite3

{.push raises: [Defect].}

import
  os, strformat,
  sqlite3_abi,
  ./kvstore

export kvstore

type
  Sqlite3Ptr* = ptr sqlite3

  KeySpaceStatements = object
    getStmt, putStmt, delStmt, containsStmt: ptr sqlite3_stmt

  SqStoreRef* = ref object of RootObj
    env: Sqlite3Ptr
    keyspaces: seq[KeySpaceStatements]

template checkErr(op, cleanup: untyped) =
  if (let v = (op); v != SQLITE_OK):
    cleanup
    return err($sqlite3_errstr(v))

template checkErr(op) =
  checkErr(op): discard

proc bindBlob(s: ptr sqlite3_stmt, n: int, blob: openarray[byte]): cint =
  sqlite3_bind_blob(s, n.cint, unsafeAddr blob[0], blob.len.cint, nil)

proc getImpl(db: SqStoreRef,
             keyspace: int,
             key: openarray[byte],
             onData: DataProc): KvResult[bool] =
  let getStmt = db.keyspaces[keyspace].getStmt
  checkErr bindBlob(getStmt, 1, key)

  let
    v = sqlite3_step(getStmt)
    res = case v
      of SQLITE_ROW:
        let
          p = cast[ptr UncheckedArray[byte]](sqlite3_column_blob(getStmt, 0))
          l = sqlite3_column_bytes(getStmt, 0)
        onData(toOpenArray(p, 0, l-1))
        ok(true)
      of SQLITE_DONE:
        ok(false)
      else:
        err($sqlite3_errstr(v))

  # release implicit transaction
  discard sqlite3_reset(getStmt) # same return information as step
  discard sqlite3_clear_bindings(getStmt) # no errors possible

  res

proc get*(db: SqStoreRef, key: openarray[byte], onData: DataProc): KvResult[bool] =
  getImpl(db, 0, key, onData)

template get*(db: SqStoreRef, keyspace: int, key: openarray[byte], onData: DataProc): KvResult[bool] =
  getImpl(db, keyspace, key, onData)

proc putImpl(db: SqStoreRef, keyspace: int, key, value: openarray[byte]): KvResult[void] =
  let putStmt = db.keyspaces[keyspace].putStmt

  checkErr bindBlob(putStmt, 1, key)
  checkErr bindBlob(putStmt, 2, value)

  let res =
    if (let v = sqlite3_step(putStmt); v != SQLITE_DONE):
      err($sqlite3_errstr(v))
    else:
      ok()

  # release implict transaction
  discard sqlite3_reset(putStmt) # same return information as step
  discard sqlite3_clear_bindings(putStmt) # no errors possible

  res

proc put*(db: SqStoreRef, key, value: openarray[byte]): KvResult[void] =
  putImpl(db, 0, key, value)

template put*(db: SqStoreRef, keyspace: int, key, value: openarray[byte]): KvResult[void] =
  putImpl(db, keyspace, key, value)

proc containsImpl(db: SqStoreRef, keyspace: int, key: openarray[byte]): KvResult[bool] =
  let containsStmt = db.keyspaces[keyspace].containsStmt
  checkErr bindBlob(containsStmt, 1, key)

  let
    v = sqlite3_step(containsStmt)
    res = case v
      of SQLITE_ROW: ok(true)
      of SQLITE_DONE: ok(false)
      else: err($sqlite3_errstr(v))

  # release implicit transaction
  discard sqlite3_reset(containsStmt) # same return information as step
  discard sqlite3_clear_bindings(containsStmt) # no errors possible

  res

proc contains*(db: SqStoreRef, key: openarray[byte]): KvResult[bool] =
  containsImpl(db, 0, key)

template contains*(db: SqStoreRef, keyspace: int, key: openarray[byte]): KvResult[bool] =
  containsImpl(db, keyspace, key)

proc delImpl(db: SqStoreRef, keyspace: int, key: openarray[byte]): KvResult[void] =
  let delStmt = db.keyspaces[keyspace].delStmt
  checkErr bindBlob(delStmt, 1, key)

  let res =
    if (let v = sqlite3_step(delStmt); v != SQLITE_DONE):
      err($sqlite3_errstr(v))
    else:
      ok()

  # release implict transaction
  discard sqlite3_reset(delStmt) # same return information as step
  discard sqlite3_clear_bindings(delStmt) # no errors possible

  res

proc del*(db: SqStoreRef, key: openarray[byte]): KvResult[void] =
  delImpl(db, 0, key)

template del*(db: SqStoreRef, keyspace: int, key: openarray[byte]): KvResult[void] =
  delImpl(db, keyspace, key)

proc close*(db: SqStoreRef) =
  for keyspace in db.keyspaces:
    discard sqlite3_finalize(keyspace.putStmt)
    discard sqlite3_finalize(keyspace.getStmt)
    discard sqlite3_finalize(keyspace.delStmt)
    discard sqlite3_finalize(keyspace.containsStmt)

  discard sqlite3_close(db.env)

  db[] = SqStoreRef()[]

proc init*(
    T: type SqStoreRef,
    basePath: string,
    name: string,
    readOnly = false,
    inMemory = false,
    keyspaces: openarray[string] = ["kvstore"]): KvResult[T] =
  var
    env: ptr sqlite3

  let
    name =
      if inMemory: ":memory:"
      else: basepath / name & ".sqlite3"
    flags =
      if readOnly: SQLITE_OPEN_READONLY
      else: SQLITE_OPEN_READWRITE or SQLITE_OPEN_CREATE

  if not inMemory:
    try:
      createDir(basePath)
    except OSError, IOError:
      return err("`sqlite: cannot create database directory")

  checkErr sqlite3_open_v2(name, addr env, flags.cint, nil)

  template prepare(q: string, cleanup: untyped): ptr sqlite3_stmt =
    var s: ptr sqlite3_stmt
    checkErr sqlite3_prepare_v2(env, q, q.len.cint, addr s, nil):
      cleanup
      discard sqlite3_close(env)
    s

  template checkExec(s: ptr sqlite3_stmt) =
    if (let x = sqlite3_step(s); x != SQLITE_DONE):
      discard sqlite3_finalize(s)
      discard sqlite3_close(env)
      return err($sqlite3_errstr(x))

    if (let x = sqlite3_finalize(s); x != SQLITE_OK):
      discard sqlite3_close(env)
      return err($sqlite3_errstr(x))

  template checkExec(q: string) =
    let s = prepare(q): discard
    checkExec(s)

  template checkWalPragmaResult(journalModePragma: ptr sqlite3_stmt) =
    if (let x = sqlite3_step(journalModePragma); x != SQLITE_ROW):
      discard sqlite3_finalize(journalModePragma)
      discard sqlite3_close(env)
      return err($sqlite3_errstr(x))

    if (let x = sqlite3_column_type(journalModePragma, 0); x != SQLITE3_TEXT):
      discard sqlite3_finalize(journalModePragma)
      discard sqlite3_close(env)
      return err($sqlite3_errstr(x))

    if (let x = sqlite3_column_text(journalModePragma, 0);
        x != "memory" and x != "wal"):
      discard sqlite3_finalize(journalModePragma)
      discard sqlite3_close(env)
      return err("Invalid pragma result: " & $x)

  # TODO: check current version and implement schema versioning
  checkExec "PRAGMA user_version = 1;"

  let journalModePragma = prepare("PRAGMA journal_mode = WAL;"): discard
  checkWalPragmaResult(journalModePragma)
  checkExec(journalModePragma)

  var keyspaceStatements = newSeq[KeySpaceStatements]()
  for keyspace in keyspaces:
    checkExec """
      CREATE TABLE IF NOT EXISTS """ & keyspace & """ (
         key BLOB PRIMARY KEY,
         value BLOB
      ) WITHOUT ROWID;
    """

    let
      getStmt = prepare("SELECT value FROM " & keyspace & " WHERE key = ?;"):
        discard
      putStmt = prepare("INSERT OR REPLACE INTO " & keyspace & "(key, value) VALUES (?, ?);"):
        discard sqlite3_finalize(getStmt)
      delStmt = prepare("DELETE FROM " & keyspace & " WHERE key = ?;"):
        discard sqlite3_finalize(getStmt)
        discard sqlite3_finalize(putStmt)
      containsStmt = prepare("SELECT 1 FROM " & keyspace & " WHERE key = ?;"):
        discard sqlite3_finalize(getStmt)
        discard sqlite3_finalize(putStmt)
        discard sqlite3_finalize(delStmt)

    keyspaceStatements.add KeySpaceStatements(
      getStmt: getStmt,
      putStmt: putStmt,
      delStmt: delStmt,
      containsStmt: containsStmt)

  ok(SqStoreRef(
    env: env,
    keyspaces: keyspaceStatements
  ))

proc init*(
    T: type SqStoreRef,
    basePath: string,
    name: string,
    Keyspaces: type[enum],
    readOnly = false,
    inMemory = false): KvResult[T] =

  var keyspaceNames = newSeq[string]()
  for keyspace in Keyspaces:
    keyspaceNames.add $keyspace

  SqStoreRef.init(basePath, name, readOnly, inMemory, keyspaceNames)

when defined(metrics):
  import tables, times,
        chronicles, metrics

  type Sqlite3Info = ref object of Gauge

  proc newSqlite3Info*(name: string, help: string, registry = defaultRegistry): Sqlite3Info {.raises: [Exception].} =
    validateName(name)
    result = Sqlite3Info(name: name,
                        help: help,
                        typ: "gauge",
                        creationThreadId: getThreadId())
    result.register(registry)

  var sqlite3Info* {.global.} = newSqlite3Info("sqlite3_info", "SQLite3 info")

  method collect*(collector: Sqlite3Info): Metrics =
    result = initOrderedTable[Labels, seq[Metric]]()
    result[@[]] = @[]
    let timestamp = getTime().toMilliseconds()
    var currentMem, highwaterMem: int64

    if (let res = sqlite3_status64(SQLITE_STATUS_MEMORY_USED, currentMem.addr, highwaterMem.addr, 0); res != SQLITE_OK):
      error "SQLite3 error", msg = sqlite3_errstr(res)
    else:
      result[@[]] = @[
        Metric(
          name: "sqlite3_memory_used_bytes",
          value: currentMem.float64,
          timestamp: timestamp,
        ),
      ]

