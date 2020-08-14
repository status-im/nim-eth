import
  chronos, chronicles, chronicles/chronos_tools

export
  chronos_tools

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

