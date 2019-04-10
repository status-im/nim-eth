import
  chronos/[asyncfutures2, asyncloop], chronicles

proc catchOrQuit(error: Exception) =
  if error of CatchableError:
    trace "Async operation ended with a recoverable error", err = error.msg
  else:
    fatal "Fatal exception reached", err = error.msg
    quit 1

proc traceAsyncErrors*(fut: FutureBase) =
  proc continuation(arg: pointer) {.gcsafe.} =
    if not fut.error.isNil:
      catchOrQuit fut.error[]
  fut.addCallback continuation

template traceAwaitErrors*(fut: FutureBase) =
  let f = fut
  yield f
  if not f.error.isNil:
    catchOrQuit f.error[]
