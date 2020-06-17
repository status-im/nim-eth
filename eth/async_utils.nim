import
  chronos, chronicles

proc catchOrQuit*(error: Exception) =
  if error of CatchableError:
    trace "Async operation ended with a recoverable error", err = error.msg
  else:
    fatal "Fatal exception reached", err = error.msg, stackTrace = getStackTrace()
    quit 1

proc traceAsyncErrors*(fut: FutureBase) =
  fut.addCallback do (arg: pointer):
    if not fut.error.isNil:
      catchOrQuit fut.error[]

template traceAwaitErrors*(fut: FutureBase) =
  let f = fut
  yield f
  if not f.error.isNil:
    catchOrQuit f.error[]

template awaitWithTimeout*[T](operation: Future[T],
                              deadline: Future[void],
                              onTimeout: untyped): T =
  let f = operation
  await f or deadline
  if not f.finished:
    cancel f
    onTimeout
  else:
    f.read

template awaitWithTimeout*[T](operation: Future[T],
                              timeout: Duration,
                              onTimeout: untyped): T =
  awaitWithTimeout(operation, sleepAsync(timeout), onTimeout)

