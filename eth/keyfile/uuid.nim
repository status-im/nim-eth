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

{.push raises: [Defect].}

import stew/[byteutils, endians2, results]

from nimcrypto import stripSpaces

export results

type
  UUID* = object
    ## Represents UUID object
    data*: array[16, byte]

  UuidResult*[T] = Result[T, cstring]

proc uuidFromString*(s: string): UuidResult[UUID] =
  ## Convert string representation of UUID into UUID object.
  if len(s) != 36:
    return err("uuid: length must be 36 bytes")
  for i in 0..<len(s):
    if s[i] notin {'A'..'F', '0'..'9', 'a'..'f', '-'}:
      return err("uuid: invalid characters")
  try:
    var d = hexToSeqByte(stripSpaces(s))
    var
      a = uint32.fromBytesBE(d.toOpenArray(0, 3))
      b = uint16.fromBytesBE(d.toOpenArray(4, 5))
      c = uint16.fromBytesBE(d.toOpenArray(6, 7))

    var ret: UUID
    copyMem(addr ret.data[0], addr a, 4)
    copyMem(addr ret.data[4], addr b, 2)
    copyMem(addr ret.data[6], addr c, 2)
    copyMem(addr ret.data[8], addr d[8], 8)
    ok(ret)
  except CatchableError:
    err("uuid: cannot parse hex string")

proc uuidToString*(u: UUID): string =
  ## Convert UUID object into string representation.
  ## UUID are lowercase, per RFC4122
  result = newStringOfCap(38)
  var d: array[8, byte]
  var
    a = uint32.fromBytesBE(u.data.toOpenArray(0, 3))
    b = uint16.fromBytesBE(u.data.toOpenArray(4, 5))
    c = uint16.fromBytesBE(u.data.toOpenArray(6, 7))
  copyMem(addr d[0], addr a, 4)
  copyMem(addr d[4], addr b, 2)
  copyMem(addr d[6], addr c, 2)

  result.add(toHex(toOpenArray(d, 0, 3)))
  result.add("-")
  result.add(toHex(toOpenArray(d, 4, 5)))
  result.add("-")
  result.add(toHex(toOpenArray(d, 6, 7)))
  result.add("-")
  result.add(toHex(toOpenArray(u.data, 8, 9)))
  result.add("-")
  result.add(toHex(toOpenArray(u.data, 10, 15)))

proc `$`*(u: UUID): string =
  ## Convert UUID object to lowercase string representation.
  uuidToString(u)

when defined(nimdoc):
  proc uuidGenerate*(): UuidResult[UUID]
    ## Generates new unique UUID and store it to `output`.
    ##
    ## Return 1 on success, and 0 on failure

when defined(posix):
  when defined(macosx):
    proc uuidGenerateRandom(a: pointer)
         {.importc: "uuid_generate_random", header: "uuid/uuid.h".}

    proc uuidGenerate*(): UuidResult[UUID] =
      var output: UUID
      uuidGenerateRandom(cast[pointer](addr output))
      ok(output)

  elif defined(freebsd) or defined(netbsd) or defined(openbsd) or
       defined(dragonflybsd):

    proc uuidCreate(a: pointer, s: ptr uint32)
         {.importc: "uuid_create", header: "uuid.h".}

    proc uuidGenerate*(): UuidResult[UUID] =
      var status: uint32 = 0
      var output: UUID
      uuidCreate(cast[pointer](addr output), addr status)
      if status == 0:
        ok(output)
      else:
        err("uuid: uuid_create failed")

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

    proc uuidGenerate*(): UuidResult[UUID] =
      var buffer = newString(37)
      if uuidRead(buffer, 36) == 36:
        buffer.setLen(36)
        uuidFromString(buffer)
      else:
        var output: UUID
        if randomBytes(output.data) == sizeof(output.data):
          ok(output)
        else:
          err("uuid: cannot get random bytes")

  else:
    import nimcrypto/sysrand

    proc uuidGenerate*(): UuidResult[UUID] =
      var output: UUID
      if randomBytes(output.data) == sizeof(output.data):
        ok(output)
      else:
        err("uuid: cannot get random bytes")

elif defined(windows):
  proc UuidCreate(p: pointer): int32
       {.stdcall, dynlib: "rpcrt4", importc: "UuidCreate".}

  proc uuidGenerate*(): UuidResult[UUID] =
    var output: UUID
    if UuidCreate(cast[pointer](addr output)) == 0:
      ok(output)
    else:
      err("uuid: UuidCreate failed")
elif not defined(nimdoc):
  import nimcrypto/sysrand

  proc uuidGenerate*(): UuidResult[UUID] =
    var output: UUID
    if randomBytes(output.data) == sizeof(output.data):
      ok(output)
    else:
      err("uuid: cannot get random bytes")
