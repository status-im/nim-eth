#
#                  Ethereum KeyFile
#                 (c) Copyright 2018
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

{.used.}

import eth/keyfile/uuid, unittest

suite "Cross-platform UUID test suite":
  test "Platform UUID check":
    check uuidGenerate().isOk

  test "Conversion test":
    let u = uuidGenerate()[]
    check:
      len($u) == 36
      $uuidFromString($u)[] == $u
      uuidToString(u) == $u
