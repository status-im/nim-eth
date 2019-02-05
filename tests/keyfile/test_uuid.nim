#
#                  Ethereum KeyFile
#                 (c) Copyright 2018
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

import eth_keyfile/uuid, strutils, unittest

suite "Cross-platform UUID test suite":
  test "Platform UUID check":
    var u: UUID
    check uuidGenerate(u) == 1
  test "Conversion test":
    var u: UUID
    check:
      uuidGenerate(u) == 1
      len($u) == 36
      $uuidFromString($u) == $u
      uuidToString(u, true) == $u
      uuidToString(u, false) == toUpperAscii($u)
