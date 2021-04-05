# TODO: Make this part of the test suite.
# We need to be able to test that a program fails in certain way.
# The testing framework from Chronicles can be extracted in a separate package.

import
  chronos,
  ../eth/async_utils

type
  SomeRecoverableError = object of CatchableError
  SomeDefect = object of Defect

proc failingAsyncProc(err: ref Exception = nil) {.async.} =
  await sleepAsync(0)
  if err != nil:
    raise err

proc main {.async.} =
  type Error =
    # Exception
    SomeDefect
    # SomeRecoverableError
  traceAsyncErrors failingAsyncProc(newException(Error, "some exception"))

waitFor main()
waitFor sleepAsync(2000)

