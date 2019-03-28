import
  chronos/asyncfutures2, chronicles

proc traceAsyncErrors*(fut: FutureBase) =
  fut.addCallback do (arg: pointer):
    if not fut.error.isNil:
      if fut.error[] of CatchableError:
        trace "Async operation ended with a recoverable error", err = fut.error.msg
      else:
        fatal "Fatal exception reached", err = fut.error.msg
        quit 1

