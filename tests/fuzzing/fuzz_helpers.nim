import streams, posix, strutils, chronicles, macros

template fuzz(body) =
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
  result = cast[seq[byte]](input)

proc NimMain() {.importc: "NimMain".}

template `+`*[T](p: ptr T, off: int): ptr T =
  cast[ptr type(p[])](cast[ByteAddress](p) +% off * sizeof(p[]))

macro test*(body: untyped): untyped =
  when defined(afl):
    result = quote do:
      var payload {.inject.} = readStdin()

      fuzz: `body`
  else:
    result = quote do:
      proc fuzzerCall(data: ptr byte, len: csize):
          cint {.exportc: "LLVMFuzzerTestOneInput".} =
        var payload {.inject.} : seq[byte]
        if len > 0:
          # TODO: something better to get this data in the seq?
          newSeq(payload, len)
          for i in 0..<len:
            payload[i] = (data + i)[]

        `body`

macro init*(body: untyped): untyped =
  when defined(afl):
    result = quote do:
      fuzz: `body`
  else:
    result = quote do:
      proc fuzzerInit(): cint {.exportc: "LLVMFuzzerInitialize".} =
        NimMain()

        `body`

        return 0
