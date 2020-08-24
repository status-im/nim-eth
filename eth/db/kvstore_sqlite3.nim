## Implementation of KvStore based on sqlite3

{.push raises: [Defect].}

import
  os,
  sqlite3_abi,
  ./kvstore

export kvstore

type
  SqStoreRef* = ref object of RootObj
    env: ptr sqlite3
    getStmt, putStmt, delStmt, containsStmt: ptr sqlite3_stmt

template checkErr(op, cleanup: untyped) =
  if (let v = (op); v != SQLITE_OK):
    cleanup
    return err($sqlite3_errstr(v))

template checkErr(op) =
  checkErr(op): discard

proc bindBlob(s: ptr sqlite3_stmt, n: int, blob: openarray[byte]): cint =
  sqlite3_bind_blob(s, n.cint, unsafeAddr blob[0], blob.len.cint, nil)

proc get*(db: SqStoreRef, key: openarray[byte], onData: DataProc): KvResult[bool] =
  checkErr sqlite3_reset(db.getStmt)
  checkErr sqlite3_clear_bindings(db.getStmt)
  checkErr bindBlob(db.getStmt, 1, key)

  let v = sqlite3_step(db.getStmt)
  case v
  of SQLITE_ROW:
    let
      p = cast[ptr UncheckedArray[byte]](sqlite3_column_blob(db.getStmt, 0))
      l = sqlite3_column_bytes(db.getStmt, 0)
    onData(toOpenArray(p, 0, l-1))
    ok(true)
  of SQLITE_DONE:
    ok(false)
  else:
    err($sqlite3_errstr(v))

proc put*(db: SqStoreRef, key, value: openarray[byte]): KvResult[void] =
  checkErr sqlite3_reset(db.putStmt)
  checkErr sqlite3_clear_bindings(db.putStmt)

  checkErr bindBlob(db.putStmt, 1, key)
  checkErr bindBlob(db.putStmt, 2, value)

  if (let v = sqlite3_step(db.putStmt); v != SQLITE_DONE):
    err($sqlite3_errstr(v))
  else:
    ok()

proc contains*(db: SqStoreRef, key: openarray[byte]): KvResult[bool] =
  checkErr sqlite3_reset(db.containsStmt)
  checkErr sqlite3_clear_bindings(db.containsStmt)

  checkErr bindBlob(db.containsStmt, 1, key)

  let v = sqlite3_step(db.containsStmt)
  case v
  of SQLITE_ROW: ok(true)
  of SQLITE_DONE: ok(false)
  else: err($sqlite3_errstr(v))

proc del*(db: SqStoreRef, key: openarray[byte]): KvResult[void] =
  checkErr sqlite3_reset(db.delStmt)
  checkErr sqlite3_clear_bindings(db.delStmt)

  checkErr bindBlob(db.delStmt, 1, key)

  if (let v = sqlite3_step(db.delStmt); v != SQLITE_DONE):
    err($sqlite3_errstr(v))
  else:
    ok()

proc close*(db: SqStoreRef) =
  discard sqlite3_finalize(db.putStmt)
  discard sqlite3_finalize(db.getStmt)
  discard sqlite3_finalize(db.delStmt)
  discard sqlite3_finalize(db.containsStmt)

  discard sqlite3_close(db.env)

  db[] = SqStoreRef()[]

proc init*(
    T: type SqStoreRef,
    basePath: string,
    name: string,
    readOnly = false,
    inMemory = false): KvResult[T] =
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

    if (let x = sqlite3_column_text(journalModePragma, 0); x != "wal"):
      discard sqlite3_finalize(journalModePragma)
      discard sqlite3_close(env)
      return err("Invalid result from pramga")

  # TODO: check current version and implement schema versioning
  checkExec "PRAGMA user_version = 1;"

  let journalModePragma = prepare("PRAGMA journal_mode = WAL;"): discard
  checkWalPragmaResult(journalModePragma)
  checkExec(journalModePragma)

  checkExec """
    CREATE TABLE IF NOT EXISTS kvstore(
       key BLOB PRIMARY KEY,
       value BLOB
    ) WITHOUT ROWID;
  """

  let
    getStmt = prepare "SELECT value FROM kvstore WHERE key = ?;":
      discard
    putStmt = prepare "INSERT OR REPLACE INTO kvstore(key, value) VALUES (?, ?);":
      discard sqlite3_finalize(getStmt)
    delStmt = prepare "DELETE FROM kvstore WHERE key = ?;":
      discard sqlite3_finalize(getStmt)
      discard sqlite3_finalize(putStmt)
    containsStmt = prepare "SELECT 1 FROM kvstore WHERE key = ?;":
      discard sqlite3_finalize(getStmt)
      discard sqlite3_finalize(putStmt)
      discard sqlite3_finalize(delStmt)

  ok(SqStoreRef(
    env: env,
    getStmt: getStmt,
    putStmt: putStmt,
    delStmt: delStmt,
    containsStmt: containsStmt
  ))

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

