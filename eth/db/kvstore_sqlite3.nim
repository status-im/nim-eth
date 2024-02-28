# nim-eth
# Copyright (c) 2019-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Implementation of KvStore based on sqlite3

{.push raises: [].}
{.pragma: callback, gcsafe, raises: [].}

import
  std/[os, options, strformat, typetraits],
  sqlite3_abi,
  ./kvstore

export kvstore, typetraits

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
  ResultHandler*[T] = proc(val: T) {.callback.}

  SqStoreRef* = ref object
    # Handle for a single database - from here, keyspaces and statements
    # can be created
    env: Sqlite
    managedStmts: seq[RawStmtPtr]
    readOnly*: bool

  SqStoreCheckpointKind* {.pure.} = enum
    passive, full, restart, truncate

  SqKeyspace* = object of RootObj
    # A Keyspace is a single key-value table - it is generally efficient to
    # create separate keyspaces for each type of data stored
    open: bool
    env: Sqlite
    getStmt, putStmt, delStmt, clearStmt, containsStmt,
      findStmt0, findStmt1, findStmt2: RawStmtPtr

  SqKeyspaceRef* = ref SqKeyspace

template dispose(db: Sqlite) =
  discard sqlite3_close(db)

template dispose(db: RawStmtPtr) =
  discard sqlite3_finalize(db)

template dispose*(s: SqliteStmt) =
  if RawStmtPtr(s) != nil:
    discard sqlite3_finalize(RawStmtPtr s)

template env(s: RawStmtPtr): Sqlite = sqlite3_db_handle(s)

func isInsideTransaction*(db: SqStoreRef): bool =
  sqlite3_get_autocommit(db.env) == 0

proc release[T](x: var AutoDisposed[T]): T =
  result = x.val
  x.val = nil

proc disposeIfUnreleased[T](x: var AutoDisposed[T]) =
  mixin dispose
  if x.val != nil:
    dispose(x.release)

func toErrorString(env: ptr sqlite3, v: cint): string =
  var err = $sqlite3_errstr(v)
  if v in [SQLITE_CANTOPEN, SQLITE_IOERR] and not isNil(env):
    let errno = sqlite3_system_errno(env)
    if errno != 0:
      err &= ": " & osErrorMsg(OSErrorCode(errno))
  err

template checkErr(env: ptr sqlite3, op, cleanup: untyped) =
  if (let v = (op); v != SQLITE_OK):
    cleanup
    return err(toErrorString(env, v))

template checkErr(env: ptr sqlite3, op: untyped) =
  checkErr(env, op): discard

proc prepareStmt*(db: SqStoreRef,
                  stmt: string,
                  Params: type,
                  Res: type,
                  managed = true): KvResult[SqliteStmt[Params, Res]] =
  mixin env
  var s: RawStmtPtr
  checkErr db.env, sqlite3_prepare_v2(db.env, stmt, stmt.len.cint, addr s, nil)
  if managed: db.managedStmts.add s
  ok SqliteStmt[Params, Res](s)

proc bindParam(s: RawStmtPtr, n: int, val: auto): cint =
  when val is openArray[byte]|seq[byte]:
    if val.len > 0:
      sqlite3_bind_blob(s, n.cint, unsafeAddr val[0], val.len.cint, nil)
    else:
      sqlite3_bind_blob(s, n.cint, nil, 0.cint, nil)
  elif val is array:
    when val.items.typeof is byte:
      # Prior to Nim 1.4 and view types array[N, byte] in tuples
      # don't match with openArray[byte]
      if val.len > 0:
        sqlite3_bind_blob(s, n.cint, unsafeAddr val[0], val.len.cint, nil)
      else:
        sqlite3_bind_blob(s, n.cint, nil, 0.cint, nil)
    else:
      {.fatal: "Please add support for the '" & $typeof(val) & "' type".}
  elif val is SomeInteger:
    sqlite3_bind_int64(s, n.cint, val.clong)
  elif val is Option:
    if val.isNone():
      sqlite3_bind_null(s, n.cint)
    else:
      bindParam(s, n, val.get())
  else:
    {.fatal: "Please add support for the '" & $typeof(val) & "' type".}

template bindParams(s: RawStmtPtr, params: auto) =
  mixin env
  when params is tuple:
    when params.type.arity > 0:
      var i = 1
      for param in fields(params):
        checkErr s.env, bindParam(s, i, param)
        inc i
  else:
    checkErr s.env, bindParam(s, 1, params)

proc exec*[P](s: SqliteStmt[P, void], params: P): KvResult[void] =
  mixin env
  let s = RawStmtPtr s
  bindParams(s, params)

  let res =
    if (let v = sqlite3_step(s); v != SQLITE_DONE):
      err(toErrorString(s.env, v))
    else:
      ok()

  # release implicit transaction
  discard sqlite3_reset(s) # same return information as step
  discard sqlite3_clear_bindings(s) # no errors possible

  res

template readSimpleResult(s: RawStmtPtr, column: cint, T: type): auto =
  when T is int64:
    sqlite3_column_int64(s, column)
  elif T is SomeInteger:
    # sqlite integers are "up to" 8 bytes in size, so rather than silently
    # truncate them, we support only 64-bit integers when reading and let the
    # calling code deal with it - careful though, anything that is not an
    # integer (ie TEXT) is returned as 0
    {.fatal: "Use int64 for reading integers".}
  elif T is openArray[byte]:
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

template readResult(s: RawStmtPtr, column: cint, T: type): auto =
  when T is Option:
    if sqlite3_column_type(s, column) == SQLITE_NULL:
      none(typeof(default(T).get()))
    else:
      some(readSimpleResult(s, column, typeof(default(T).get())))
  else:
    readSimpleResult(s, column, T)

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
        if onData != nil:
          onData(readResult(s, Res))
        gotResults = true
      of SQLITE_DONE:
        break
      else:
        return err(toErrorString(s.env, v))
    return ok gotResults
  finally:
    # release implicit transaction
    discard sqlite3_reset(s) # same return information as step
    discard sqlite3_clear_bindings(s) # no errors possible

iterator exec*[Params, Res](s: SqliteStmt[Params, Res],
                            params: Params, item: var Res): KvResult[void] =
  let s = RawStmtPtr s

  # we use a mutable `res` variable here to avoid the code bloat that multiple
  # `yield` statements cause when inlining the loop body
  var res = KvResult[void].ok()
  when params is tuple:
    var i {.used.} = 1
    for param in fields(params):
      if (let v = bindParam(s, i, param); v != SQLITE_OK):
        res = KvResult[void].err(toErrorString(s.env, v))
        break

      inc i
  else:
    if (let v = bindParam(s, 1, params); v != SQLITE_OK):
      res = KvResult[void].err(toErrorString(s.env, v))

  defer:
    # release implicit transaction
    discard sqlite3_reset(s) # same return information as step
    discard sqlite3_clear_bindings(s) # no errors possible

  while res.isOk():
    let v = sqlite3_step(s)
    case v
    of SQLITE_ROW:
      item = readResult(s, Res)
      yield KvResult[void].ok()
    of SQLITE_DONE:
      break
    else:
      res = KvResult[void].err(toErrorString(s.env, v))

  if not res.isOk():
    yield res

iterator exec*[Res](s: SqliteStmt[NoParams, Res], item: var Res): KvResult[void] =
  for r in exec(s, (), item):
    yield r

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
    return err(toErrorString(db.env, finalizeStatus))

proc exec*[Params: tuple, Res](db: SqStoreRef,
                              stmt: string,
                              params: Params,
                              onData: ResultHandler[Res]): KvResult[bool] =
  let stmt = ? db.prepareStmt(stmt, Params, Res, managed = false)
  result = exec(stmt, params, onData)
  let finalizeStatus = sqlite3_finalize(RawStmtPtr stmt)
  if finalizeStatus != SQLITE_OK and result.isOk:
    return err(toErrorString(db.env, finalizeStatus))

template exec*(db: SqStoreRef, stmt: string): KvResult[void] =
  exec(db, stmt, ())

proc get*(db: SqKeyspaceRef,
          key: openArray[byte],
          onData: DataProc): KvResult[bool] =
  if not db.open: return err("sqlite: database closed")
  let getStmt = db.getStmt
  if getStmt == nil: return ok(false) # no such table
  checkErr db.env, bindParam(getStmt, 1, key)

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
        err(toErrorString(db.env, v))

  # release implicit transaction
  discard sqlite3_reset(getStmt) # same return information as step
  discard sqlite3_clear_bindings(getStmt) # no errors possible

  res

func nextPrefix(prefix: openArray[byte], next: var seq[byte]): bool =
  # Return a seq that is greater than all strings starting with `prefix` when
  # doing a lexicographical compare - we're looking for the string that
  # increments the last byte by 1, removing any bytes from the back that
  # cannot be incremented (0xff)

  for i in 0..<prefix.len():
    if prefix[^(i+1)] == high(byte):
      if i == 0:
        return false
      else:
        next = prefix[0..<i]
        next[^1] += 1'u8
        return true

  false # Empty

proc find*(
    db: SqKeyspaceRef,
    prefix: openArray[byte],
    onFind: KeyValueProc): KvResult[int] =
  if not db.open: return err("sqlite: database closed")
  var next: seq[byte] # extended lifetime of bound param
  let findStmt =
    if prefix.len == 0:
      if db.findStmt0 == nil: return ok(0) # no such table
      db.findStmt0 # all rows
    else:
      if not nextPrefix(prefix, next):
        # For example when looking for the prefix [byte 255], there are no
        # prefixes that lexicographically are greater, thus we use the
        # query that only does the >= comparison
        if db.findStmt1 == nil: return ok(0) # no such table
        checkErr db.env, bindParam(db.findStmt1, 1, prefix)
        db.findStmt1
      else:
        if db.findStmt2 == nil: return ok(0) # no such table
        checkErr db.env, bindParam(db.findStmt2, 1, prefix)
        checkErr db.env, bindParam(db.findStmt2, 2, next)
        db.findStmt2


  var
    total = 0
  while true:
    let
      v = sqlite3_step(findStmt)
    case v
    of SQLITE_ROW:
      let
        kp = cast[ptr UncheckedArray[byte]](sqlite3_column_blob(findStmt, 0))
        kl = sqlite3_column_bytes(findStmt, 0)
        vp = cast[ptr UncheckedArray[byte]](sqlite3_column_blob(findStmt, 1))
        vl = sqlite3_column_bytes(findStmt, 1)
      if onFind != nil:
        onFind(kp.toOpenArray(0, kl - 1), vp.toOpenArray(0, vl - 1))
      total += 1
    of SQLITE_DONE:
      break
    else:
      # release implicit transaction (could use a defer, but it's slow)
      discard sqlite3_reset(findStmt) # same return information as step
      discard sqlite3_clear_bindings(findStmt) # no errors possible

      return err(toErrorString(db.env, v))

  # release implicit transaction
  discard sqlite3_reset(findStmt) # same return information as step
  discard sqlite3_clear_bindings(findStmt) # no errors possible

  ok(total)

proc put*(db: SqKeyspaceRef, key, value: openArray[byte]): KvResult[void] =
  if not db.open: return err("sqlite: database closed")
  let putStmt = db.putStmt
  if putStmt == nil: return err("sqlite: cannot write to read-only database")
  checkErr db.env, bindParam(putStmt, 1, key)
  checkErr db.env, bindParam(putStmt, 2, value)

  let res =
    if (let v = sqlite3_step(putStmt); v != SQLITE_DONE):
      err(toErrorString(db.env, v))
    else:
      ok()

  # release implict transaction
  discard sqlite3_reset(putStmt) # same return information as step
  discard sqlite3_clear_bindings(putStmt) # no errors possible

  res

proc contains*(db: SqKeyspaceRef, key: openArray[byte]): KvResult[bool] =
  if not db.open: return err("sqlite: database closed")
  let containsStmt = db.containsStmt
  if containsStmt == nil: return ok(false) # no such table

  checkErr db.env, bindParam(containsStmt, 1, key)

  let
    v = sqlite3_step(containsStmt)
    res = case v
      of SQLITE_ROW: ok(true)
      of SQLITE_DONE: ok(false)
      else: err(toErrorString(db.env, v))

  # release implicit transaction
  discard sqlite3_reset(containsStmt) # same return information as step
  discard sqlite3_clear_bindings(containsStmt) # no errors possible

  res

proc del*(db: SqKeyspaceRef, key: openArray[byte]): KvResult[bool] =
  if not db.open: return err("sqlite: database closed")
  let delStmt = db.delStmt
  if delStmt == nil: return ok(false) # no such table
  checkErr db.env, bindParam(delStmt, 1, key)

  let res =
    if (let v = sqlite3_step(delStmt); v != SQLITE_DONE):
      err(toErrorString(db.env, v))
    else:
      ok(sqlite3_changes(db.env) > 0)

  # release implict transaction
  discard sqlite3_reset(delStmt) # same return information as step
  discard sqlite3_clear_bindings(delStmt) # no errors possible

  res

proc clear*(db: SqKeyspaceRef): KvResult[bool] =
  if not db.open: return err("sqlite: database closed")
  let clearStmt = db.clearStmt
  if clearStmt == nil: return ok(false) # no such table

  let res =
    if (let v = sqlite3_step(clearStmt); v != SQLITE_DONE):
      err(toErrorString(db.env, v))
    else:
      ok(sqlite3_changes(db.env) > 0)

  # release implicit transaction
  discard sqlite3_reset(clearStmt) # same return information as step

  res

proc close*(db: var SqKeyspace) =
  # Calling with null stmt is harmless
  discard sqlite3_finalize(db.putStmt)
  discard sqlite3_finalize(db.getStmt)
  discard sqlite3_finalize(db.delStmt)
  discard sqlite3_finalize(db.clearStmt)
  discard sqlite3_finalize(db.containsStmt)
  discard sqlite3_finalize(db.findStmt0)
  discard sqlite3_finalize(db.findStmt1)
  discard sqlite3_finalize(db.findStmt2)
  db = SqKeyspace()

proc close*(db: SqKeyspaceRef) =
  close(db[])

proc close*(db: SqStoreRef) =
  for stmt in db.managedStmts:
    discard sqlite3_finalize(stmt)

  # Lazy-v2-close allows closing the keyspaces in any order
  discard sqlite3_close_v2(db.env)

  db[] = SqStoreRef()[]

proc checkpoint*(db: SqStoreRef, kind = SqStoreCheckpointKind.passive) =
  let mode: cint = case kind
  of SqStoreCheckpointKind.passive: SQLITE_CHECKPOINT_PASSIVE
  of SqStoreCheckpointKind.full: SQLITE_CHECKPOINT_FULL
  of SqStoreCheckpointKind.restart: SQLITE_CHECKPOINT_RESTART
  of SqStoreCheckpointKind.truncate: SQLITE_CHECKPOINT_TRUNCATE
  discard sqlite3_wal_checkpoint_v2(db.env, nil, mode, nil, nil)

template prepare(env: ptr sqlite3, q: string): ptr sqlite3_stmt =
  block:
    var s: ptr sqlite3_stmt
    checkErr env, sqlite3_prepare_v2(env, cstring(q), q.len.cint, addr s, nil):
      discard
    s

template prepare(env: ptr sqlite3, q: string, cleanup: untyped): ptr sqlite3_stmt =
  block:
    var s: ptr sqlite3_stmt
    checkErr env, sqlite3_prepare_v2(env, cstring(q), q.len.cint, addr s, nil)
    s

template checkExec(env: ptr sqlite3, s: ptr sqlite3_stmt) =
  if (let x = sqlite3_step(s); x != SQLITE_DONE):
    discard sqlite3_finalize(s)
    return err(toErrorString(env, x))

  if (let x = sqlite3_finalize(s); x != SQLITE_OK):
    return err(toErrorString(env, x))

template checkExec(env: ptr sqlite3, q: string) =
  block:
    let s = prepare(env, q): discard
    checkExec(env, s)

proc isClosed*(db: SqStoreRef): bool =
  db.env != nil

proc init*(
    T: type SqStoreRef,
    basePath: string,
    name: string,
    readOnly = false,
    inMemory = false,
    manualCheckpoint = false): KvResult[T] =
  var env: AutoDisposed[ptr sqlite3]
  defer: disposeIfUnreleased(env)

  let
    name =
      if inMemory: ":memory:"
      else: basePath / name & ".sqlite3"
    flags =
      # For some reason, opening multiple in-memory databases doesn't work if
      # one of them is read-only - for now, disable read-only mode for them
      if readOnly and not inMemory: SQLITE_OPEN_READONLY
      else: SQLITE_OPEN_READWRITE or SQLITE_OPEN_CREATE

  if not inMemory:
    try:
      createDir(basePath)
    except OSError, IOError:
      return err("sqlite: cannot create database directory")

  checkErr env.val, sqlite3_open_v2(cstring name, addr env.val, flags.cint, nil)

  template checkWalPragmaResult(
      env: ptr sqlite3, journalModePragma: ptr sqlite3_stmt) =
    if (let x = sqlite3_step(journalModePragma); x != SQLITE_ROW):
      discard sqlite3_finalize(journalModePragma)
      return err(toErrorString(env, x))

    if (let x = sqlite3_column_type(journalModePragma, 0); x != SQLITE3_TEXT):
      discard sqlite3_finalize(journalModePragma)
      return err(toErrorString(env, x))

    if (let x = sqlite3_column_text(journalModePragma, 0);
        x != "memory" and x != "wal"):
      discard sqlite3_finalize(journalModePragma)
      return err("Invalid pragma result: " & $x)

  if not readOnly:
    # user_version = 1: single kvstore table without rowid
    # user_version = 2: single kvstore table with rowid
    # user_version = 3: multiple named kvstore tables via openKvStore
    checkExec env.val, "PRAGMA user_version = 3;"

    let journalModePragma = prepare(env.val, "PRAGMA journal_mode = WAL;")
    checkWalPragmaResult(env.val, journalModePragma)
    checkExec env.val, journalModePragma

  if manualCheckpoint:
    checkErr env.val, sqlite3_wal_autocheckpoint(env.val, 0)
    # In manual checkpointing mode, we relax synchronization to NORMAL -
    # this is safe in WAL mode leaving us with a consistent database at all
    # times, though potentially losing any data written between checkpoints.
    # http://www3.sqlite.org/wal.html#performance_considerations
    checkExec env.val, "PRAGMA synchronous = NORMAL;"

  ok(SqStoreRef(
    env: env.release,
    readOnly: readOnly
  ))

proc hasTable*(db: SqStoreRef, name: string): KvResult[bool] =
  let
    sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='" &
      name & "';"
  db.exec(sql, (), proc(_: openArray[byte]) {.callback.} = discard)

proc openKvStore*(
    db: SqStoreRef, name = "kvstore", withoutRowid = false,
    readOnly = false): KvResult[SqKeyspaceRef] =
  ## Open a new Key-Value store in the SQLite database
  ##
  ## withoutRowid: Create the table without rowid - this is more efficient when
  ##               rows are small (<200 bytes) but very inefficient with larger
  ##               rows (the row being the sum of key and value) - see
  ##               https://www.sqlite.org/withoutrowid.html
  ##
  let hasTable = if db.readOnly or readOnly:
    ? db.hasTable(name)
  else:
    let createSql = """
      CREATE TABLE IF NOT EXISTS '""" & name & """' (
         key BLOB PRIMARY KEY,
         value BLOB
      )"""
    checkExec db.env,
      if withoutRowid: createSql & " WITHOUT ROWID;" else: createSql & ";"
    true
  var
    tmp = SqKeyspace(env: db.env)
  defer:
    # We'll "move" ownership to the return value, effectively disabling "close"
    close(tmp)
  tmp.open = true
  if hasTable:
    tmp.getStmt =
      prepare(db.env, "SELECT value FROM '" & name & "' WHERE key = ?;")
    tmp.putStmt =
      prepare(db.env, "INSERT OR REPLACE INTO '" & name & "'(key, value) VALUES (?, ?);")
    tmp.delStmt = prepare(db.env, "DELETE FROM '" & name & "' WHERE key = ?;")
    tmp.clearStmt = prepare(db.env, "DELETE FROM '" & name & "';")
    tmp.containsStmt = prepare(db.env, "SELECT 1 FROM '" & name & "' WHERE key = ?;")
    tmp.findStmt0 = prepare(db.env, "SELECT key, value FROM '" & name & "';")
    tmp.findStmt1 = prepare(db.env, "SELECT key, value FROM '" & name & "' WHERE key >= ?;")
    tmp.findStmt2 = prepare(db.env, "SELECT key, value FROM '" & name & "' WHERE key >= ? and key < ?;")

  var res = SqKeyspaceRef()
  res[] = tmp
  tmp = SqKeyspace() # make close harmless
  ok res

type
  SqliteContext* = ptr sqlite3_context
  SqliteValue* = ptr ptr sqlite3_value
  SqliteCustomFunction* =
    proc (a1: SqliteContext; a2: cint; a3: SqliteValue) {.cdecl, callback.}

proc createCustomFunction*(
    db: SqStoreRef, name: string, argc: int,
    customFunction: SqliteCustomFunction):
    KvResult[void] =
  ## Create custom function inside sqlite engine. Function can be used in
  ## queries by the provided name. Function should be side-effect free and
  ## depend only on provided arguments.
  ## Name of the function must be a valid utf8 string.

  # Using SQLITE_DETERMINISTIC flag to inform sqlite that provided function
  # will be deterministic, this may enable additional optimisations.
  let deterministicUtf8Func = cint(SQLITE_UTF8 or SQLITE_DETERMINISTIC)

  checkErr db.env, sqlite3_create_function(
    db.env,
    name,
    cint(argc),
    deterministicUtf8Func,
    nil,
    customFunction,
    nil,
    nil
  )

  ok()

when defined(metrics):
  import chronicles, metrics

  type Sqlite3Info = ref object of Collector

  proc newSqlite3Info*(name: string, help: string, registry = defaultRegistry): Sqlite3Info {.raises: [CatchableError].} =
    Sqlite3Info.newCollector(name, help, registry = registry)

  let sqlite3Info* = newSqlite3Info("sqlite3_info", "SQLite3 info")

  when declared(MetricHandler): # nim-metrics 0.1.0+
    method collect*(collector: Sqlite3Info, output: MetricHandler) =
      let timestamp = collector.now()

      var currentMem, highwaterMem: int64

      if (let res = sqlite3_status64(SQLITE_STATUS_MEMORY_USED, currentMem.addr, highwaterMem.addr, 0); res != SQLITE_OK):
        error "SQLite3 error", msg = sqlite3_errstr(res)
      else:
        output(
          name = "sqlite3_memory_used_bytes",
          value = currentMem.float64,
          timestamp = timestamp,
        )
  else: # nim-metrics 0.0.1
    import std/times

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
