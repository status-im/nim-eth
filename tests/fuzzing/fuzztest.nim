import streams, posix, strutils, chronicles, macros, stew/ranges/ptr_arith

template fuzz(body) =
  # For code we want to fuzz, SIGSEGV is needed on unwanted exceptions.
  # However, this is only needed when fuzzing with afl.
  when defined(standalone):
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
  result = cast[seq[byte]](input)

proc NimMain() {.importc: "NimMain".}

template test*(body: untyped): untyped =
  when defined(standalone):
    var payload {.inject.} = readStdin()

    fuzz: `body`
  else:
    proc fuzzerCall(data: ptr byte, len: csize):
        cint {.exportc: "LLVMFuzzerTestOneInput".} =
      template payload(): auto =
        makeOpenArray(data, len)

      `body`

template init*(body: untyped): untyped =
  when defined(standalone):
    fuzz: `body`
  else:
    proc fuzzerInit(): cint {.exportc: "LLVMFuzzerInitialize".} =
      NimMain()

      `body`

      return 0