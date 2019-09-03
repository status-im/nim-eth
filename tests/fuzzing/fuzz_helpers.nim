import streams, posix, sequtils, strutils, chronicles

template fuzz*(body) =
  # For code we want to fuzz, SIGSEGV is needed on unwanted exceptions.
  # However, this is only needed when fuzzing with afl.
  when defined(afl):
    try:
      body
    except Exception as e:
      error "Fuzzer input created exception", exception=e.name, trace=e.repr, msg=e.msg
      discard kill(getpid(), SIGSEGV)
  else:
    body

proc readStdin*(): seq[byte] =
  # Read input from stdin (fastest for AFL)
  let s = newFileStream(stdin)
  if s.isNil:
    error "Error opening stdin"
    discard kill(getpid(), SIGSEGV)
  # We use binary files as with hex we can get lots of "not hex" failures
  var input = s.readAll()
  s.close()
  # Remove newline if it is there
  input.removeSuffix
  # TODO: is there a better/faster way?
  result = input.mapIt(it.byte)