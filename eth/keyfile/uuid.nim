#
#                  Ethereum KeyFile
#                 (c) Copyright 2018
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

## This module implements interface to cross-platform UUID
## generator.
##
## - ``Windows`` - using rpcrt4.dll's `UuidCreate()`.
## - ``Linux`` and ``Android`` - using `/proc/sys/kernel/random/uuid`.
## - ``MacOS`` and ``iOS`` - using `uuid_generate_random()`.
## - ``FreeBSD``, ``OpenBSD``, ``NetBSD``,
##   ``DragonflyBSD`` - using `uuid_create()`.

{.deadCodeElim:on.}

import nimcrypto/utils, endians

type
  UUIDException = object of Exception

  UUID* = object
    ## Represents UUID object
    data*: array[16, byte]

proc raiseInvalidUuid() =
  raise newException(UUIDException, "Invalid UUID!")

proc uuidFromString*(s: string): UUID =
  ## Convert string representation of UUID into UUID object.
  if len(s) != 36:
    raiseInvalidUuid()
  for i in 0..<len(s):
    if s[i] notin {'A'..'F', '0'..'9', 'a'..'f', '-'}:
      raiseInvalidUuid()
  var d = fromHex(stripSpaces(s))
  bigEndian32(addr result.data[0], addr d[0])
  bigEndian16(addr result.data[4], addr d[4])
  bigEndian16(addr result.data[6], addr d[6])
  copyMem(addr result.data[8], addr d[8], 8)

proc uuidToString*(u: UUID, lowercase: bool = false): string =
  ## Convert UUID object into string representation.
  ## You can use ``lowercase`` flag to specify letter case
  ## of output string.
  result = newStringOfCap(38)
  var d: array[8, byte]
  bigEndian32(addr d[0], unsafeAddr u.data[0])
  bigEndian16(addr d[4], unsafeAddr u.data[4])
  bigEndian16(addr d[6], unsafeAddr u.data[6])
  result.add(toHex(toOpenArray(d, 0, 3), lowercase))
  result.add("-")
  result.add(toHex(toOpenArray(d, 4, 5), lowercase))
  result.add("-")
  result.add(toHex(toOpenArray(d, 6, 7), lowercase))
  result.add("-")
  result.add(toHex(toOpenArray(u.data, 8, 9), lowercase))
  result.add("-")
  result.add(toHex(toOpenArray(u.data, 10, 15), lowercase))

proc `$`*(u: UUID): string {.inline.} =
  ## Convert UUID object to lowercase string representation.
  uuidToString(u, true)

when defined(nimdoc):
  proc uuidGenerate*(output: var UUID): int
    ## Generates new unique UUID and store it to `output`.
    ##
    ## Return 1 on success, and 0 on failure

when defined(posix):
  when defined(macosx):
    proc uuidGenerateRandom(a: pointer)
         {.importc: "uuid_generate_random", header: "uuid/uuid.h".}

    proc uuidGenerate*(output: var UUID): int =
      uuidGenerateRandom(cast[pointer](addr output))
      result = 1

  elif defined(freebsd) or defined(netbsd) or defined(openbsd) or
       defined(dragonflybsd):

    proc uuidCreate(a: pointer, s: ptr uint32)
         {.importc: "uuid_create", header: "uuid.h".}

    proc uuidGenerate*(output: var UUID): int =
      var status: uint32 = 0
      uuidCreate(cast[pointer](addr output), addr status)
      if status == 0:
        result = 1
      else:
        result = 0

  elif defined(linux) or defined(android):
    import posix, os, nimcrypto/sysrand

    proc uuidRead(bytes: var string, length: int): int =
      result = -1
      let fd = posix.open("/proc/sys/kernel/random/uuid", posix.O_RDONLY)
      if fd != -1:
        result = 0
        while result < length:
          var p = cast[pointer](cast[uint](addr bytes[0]) + uint(result))
          var res = posix.read(fd, p, length - result)
          if res > 0:
            result += res
          elif res == 0:
            break
          else:
            if osLastError().int32 != EINTR:
              result = -1
              break
        discard posix.close(fd)

    proc uuidGenerate*(output: var UUID): int =
      result = 0
      var buffer = newString(37)
      if uuidRead(buffer, 36) == 36:
        buffer.setLen(36)
        output = uuidFromString(buffer)
        result = 1
      else:
        if randomBytes(output.data) == sizeof(output.data):
          result = 1
  else:
    import nimcrypto/sysrand

    proc uuidGenerate*(output: var UUID): int =
      if randomBytes(output.data) == sizeof(output.data):
        result = 1
      else:
        result = 0

elif defined(windows):
  proc UuidCreate(p: pointer): int32
       {.stdcall, dynlib: "rpcrt4", importc: "UuidCreate".}

  proc uuidGenerate*(output: var UUID): int =
    if UuidCreate(cast[pointer](addr output)) == 0:
      return 1
    else:
      return 0
elif not defined(nimdoc):
  import nimcrypto/sysrand

  proc uuidGenerate*(output: var UUID): int =
    if randomBytes(output.data) == sizeof(output.data):
      result = 1
    else:
      result = 0
