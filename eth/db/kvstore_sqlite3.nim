## Implementation of KvStore based on sqlite3

{.push raises: [Defect].}

import
  std/[os, strformat],
  sqlite3_abi,
  ./kvstore

export kvstore

type
  RawStmtPtr = ptr sqlite3_stmt

  AutoDisposed[T: ptr|ref] = object
    val: T

  # TODO: These should become AutoDisposed
  #       This is currently considered risky due to the destructor
  #       problem found in FastStreams (triggered when objects in
  #       the GC heap have destructors)
  Sqlite* = ptr sqlite3
  SqliteStmt*[Params; Result] = distinct RawStmtPtr
  NoParams* = tuple # this is the empty tuple
  ResultHandler*[T] = proc(val: T) {.gcsafe, raises: [Defect].}

  KeySpaceStatements = object
    getStmt, putStmt, delStmt, containsStmt: RawStmtPtr

  SqStoreRef* = ref object of RootObj
    env: Sqlite
    keyspaces: seq[KeySpaceStatements]
    managedStmts: seq[RawStmtPtr]

  SqStoreCheckpointKind* {.pure.} = enum
    passive, full, restart, truncate

template dispose(db: Sqlite) =
  discard sqlite3_close(db)

template dispose(db: RawStmtPtr) =
  discard sqlite3_finalize(db)

template dispose*(db: SqliteStmt) =
  discard sqlite3_finalize(RawStmtPtr db)

proc release[T](x: var AutoDisposed[T]): T =
  result = x.val
  x.val = nil

proc disposeIfUnreleased[T](x: var AutoDisposed[T]) =
  mixin dispose
  if x.val != nil:
    dispose(x.release)

template checkErr(op, cleanup: untyped) =
  if (let v = (op); v != SQLITE_OK):
    cleanup
    return err($sqlite3_errstr(v))

template checkErr(op) =
  checkErr(op): discard

proc prepareStmt*(db: SqStoreRef,
                  stmt: string,
                  Params: type,
                  Res: type,
                  managed = true): KvResult[SqliteStmt[Params, Res]] =
  var s: RawStmtPtr
  checkErr sqlite3_prepare_v2(db.env, stmt, stmt.len.cint, addr s, nil)
  if managed: db.managedStmts.add s
  ok SqliteStmt[Params, Res](s)

proc bindParam(s: RawStmtPtr, n: int, val: auto): cint =
  when val is openarray[byte]|seq[byte]:
    if val.len > 0:
      sqlite3_bind_blob(s, n.cint, unsafeAddr val[0], val.len.cint, nil)
    else:
      sqlite3_bind_blob(s, n.cint, nil, 0.cint, nil)
  elif val is array:
    when val.items.typeof is byte:
      # Prior to Nim 1.4 and view types array[N, byte] in tuples
      # don't match with openarray[byte]
      if val.len > 0:
        sqlite3_bind_blob(s, n.cint, unsafeAddr val[0], val.len.cint, nil)
      else:
        sqlite3_bind_blob(s, n.cint, nil, 0.cint, nil)
    else:
      {.fatal: "Please add support for the '" & $typeof(val) & "' type".}
  elif val is int32:
    sqlite3_bind_int(s, n.cint, val)
  elif val is int64:
    sqlite3_bind_int64(s, n.cint, val)
  else:
    {.fatal: "Please add support for the '" & $typeof(val) & "' type".}

template bindParams(s: RawStmtPtr, params: auto) =
  when params is tuple:
    var i = 1
    for param in fields(params):
      checkErr bindParam(s, i, param)
      inc i
  else:
    checkErr bindParam(s, 1, params)

proc exec*[P](s: SqliteStmt[P, void], params: P): KvResult[void] =
  let s = RawStmtPtr s
  bindParams(s, params)

  let res =
    if (let v = sqlite3_step(s); v != SQLITE_DONE):
      err($sqlite3_errstr(v))
    else:
      ok()

  # release implict transaction
  discard sqlite3_reset(s) # same return information as step
  discard sqlite3_clear_bindings(s) # no errors possible

  res

template readResult(s: RawStmtPtr, column: cint, T: type): auto =
  when T is int32:
    sqlite3_column_int(s, column)
  elif T is int64:
    sqlite3_column_int64(s, column)
  elif T is int:
    {.fatal: "Please use specify either int32 or int64 precisely".}
  elif T is openarray[byte]:
    let
      p = cast[ptr UncheckedArray[byte]](sqlite3_column_blob(s, column))
      l = sqlite3_column_bytes(s, column)
    toOpenArray(p, 0, l-1)
  elif T is seq[byte]:
    var res: seq[byte]
    let len = sqlite3_column_bytes(s, column)
    if len > 0:
      res.setLen(len)
      copyMem(addr res[0], sqlite3_column_blob(s, column), len)
    res
  elif T is array:
    # array[N, byte]. "genericParams(T)[1]" requires 1.4 to handle nnkTypeOfExpr
    when typeof(default(T)[0]) is byte:
      var res: T
      let colLen = sqlite3_column_bytes(s, column)

      # truncate if the type is too small
      # TODO: warning/error? We assume that users always properly dimension buffers
      let copyLen = min(colLen, res.len)
      if copyLen > 0:
        copyMem(addr res[0], sqlite3_column_blob(s, column), copyLen)
      res
    else:
      {.fatal: "Please add support for the '" & $(T) & "' type".}
  else:
    {.fatal: "Please add support for the '" & $(T) & "' type".}

template readResult(s: RawStmtPtr, T: type): auto =
  when T is tuple:
    var res: T
    var i = cint 0
    for field in fields(res):
      field = readResult(s, i, typeof(field))
      inc i
    res
  else:
    readResult(s, 0.cint, T)

proc exec*[Params, Res](s: SqliteStmt[Params, Res],
                        params: Params,
                        onData: ResultHandler[Res]): KvResult[bool] =
  let s = RawStmtPtr s
  bindParams(s, params)

  try:
    var gotResults = false
    while true:
      let v = sqlite3_step(s)
      case v
      of SQLITE_ROW:
        onData(readResult(s, Res))
        gotResults = true
      of SQLITE_DONE:
        break
      else:
        return err($sqlite3_errstr(v))
    return ok gotResults
  finally:
    # release implicit transaction
    discard sqlite3_reset(s) # same return information as step
    discard sqlite3_clear_bindings(s) # no errors possible

template exec*(s: SqliteStmt[NoParams, void]): KvResult[void] =
  exec(s, ())

template exec*[Res](s: SqliteStmt[NoParams, Res],
                    onData: ResultHandler[Res]): KvResult[bool] =
  exec(s, (), onData)

proc exec*[Params: tuple](db: SqStoreRef,
                          stmt: string,
                          params: Params): KvResult[void] =
  let stmt = ? db.prepareStmt(stmt, Params, void, managed = false)
  result = exec(stmt, params)
  let finalizeStatus = sqlite3_finalize(RawStmtPtr stmt)
  if finalizeStatus != SQLITE_OK and result.isOk:
    return err($sqlite3_errstr(finalizeStatus))

template exec*(db: SqStoreRef, stmt: string): KvResult[void] =
  exec(db, stmt, ())

proc getImpl(db: SqStoreRef,
             keyspace: int,
             key: openarray[byte],
             onData: DataProc): KvResult[bool] =
  let getStmt = db.keyspaces[keyspace].getStmt
  checkErr bindParam(getStmt, 1, key)

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

  checkErr bindParam(putStmt, 1, key)
  checkErr bindParam(putStmt, 2, value)

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
  checkErr bindParam(containsStmt, 1, key)

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
  checkErr bindParam(delStmt, 1, key)

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

  for stmt in db.managedStmts:
    discard sqlite3_finalize(stmt)

  discard sqlite3_close(db.env)

  db[] = SqStoreRef()[]

proc checkpoint*(db: SqStoreRef, kind = SqStoreCheckpointKind.passive) =
  let mode: cint = case kind
  of SqStoreCheckpointKind.passive: SQLITE_CHECKPOINT_PASSIVE
  of SqStoreCheckpointKind.full: SQLITE_CHECKPOINT_FULL
  of SqStoreCheckpointKind.restart: SQLITE_CHECKPOINT_RESTART
  of SqStoreCheckpointKind.truncate: SQLITE_CHECKPOINT_TRUNCATE
  discard sqlite3_wal_checkpoint_v2(db.env, nil, mode, nil, nil)

proc isClosed*(db: SqStoreRef): bool =
  db.env != nil

proc init*(
    T: type SqStoreRef,
    basePath: string,
    name: string,
    readOnly = false,
    inMemory = false,
    manualCheckpoint = false,
    keyspaces: openarray[string] = ["kvstore"]): KvResult[T] =
  var env: AutoDisposed[ptr sqlite3]
  defer: disposeIfUnreleased(env)

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

  checkErr sqlite3_open_v2(name, addr env.val, flags.cint, nil)

  template prepare(q: string, cleanup: untyped): ptr sqlite3_stmt =
    var s: ptr sqlite3_stmt
    checkErr sqlite3_prepare_v2(env.val, q, q.len.cint, addr s, nil):
      cleanup
    s

  template checkExec(s: ptr sqlite3_stmt) =
    if (let x = sqlite3_step(s); x != SQLITE_DONE):
      discard sqlite3_finalize(s)
      return err($sqlite3_errstr(x))

    if (let x = sqlite3_finalize(s); x != SQLITE_OK):
      return err($sqlite3_errstr(x))

  template checkExec(q: string) =
    let s = prepare(q): discard
    checkExec(s)

  template checkWalPragmaResult(journalModePragma: ptr sqlite3_stmt) =
    if (let x = sqlite3_step(journalModePragma); x != SQLITE_ROW):
      discard sqlite3_finalize(journalModePragma)
      return err($sqlite3_errstr(x))

    if (let x = sqlite3_column_type(journalModePragma, 0); x != SQLITE3_TEXT):
      discard sqlite3_finalize(journalModePragma)
      return err($sqlite3_errstr(x))

    if (let x = sqlite3_column_text(journalModePragma, 0);
        x != "memory" and x != "wal"):
      discard sqlite3_finalize(journalModePragma)
      return err("Invalid pragma result: " & $x)

  # TODO: check current version and implement schema versioning
  checkExec "PRAGMA user_version = 1;"

  let journalModePragma = prepare("PRAGMA journal_mode = WAL;"): discard
  checkWalPragmaResult(journalModePragma)
  checkExec(journalModePragma)


  if manualCheckpoint:
    checkErr sqlite3_wal_autocheckpoint(env.val, 0)
    # In manual checkpointing mode, we relax synchronization to NORMAL -
    # this is safe in WAL mode leaving us with a consistent database at all
    # times, though potentially losing any data written between checkpoints.
    # http://www3.sqlite.org/wal.html#performance_considerations
    checkExec("PRAGMA synchronous = NORMAL;")

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
    env: env.release,
    keyspaces: keyspaceStatements
  ))

proc init*(
    T: type SqStoreRef,
    basePath: string,
    name: string,
    Keyspaces: type[enum],
    readOnly = false,
    inMemory = false,
    manualCheckpoint = false): KvResult[T] =

  var keyspaceNames = newSeq[string]()
  for keyspace in Keyspaces:
    keyspaceNames.add $keyspace

  SqStoreRef.init(basePath, name, readOnly, inMemory, manualCheckpoint, keyspaceNames)

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
